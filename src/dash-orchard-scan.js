// Dash Evolution (Platform) Orchard receive-scanning.
//
// Dash's shielded pool went live on the Platform chain on 17 Jul 2026
// using Zcash's Orchard protocol with a 36-byte memo. Unlike Zcash,
// scanning does NOT need a lightwalletd walk from a birthday height:
// Platform exposes the encrypted notes as one flat indexed stream, so a
// receive-scan is "page the stream from a cursor, trial-decrypt each
// 216-byte note with our FVK". Settlement is instant — Platform has
// 1-second finality, so a note in the stream IS final (no confirmation
// counting; configure `confirmations.dash = 1` and every payment
// settles the tick it is seen).
//
// The trial decryption runs in a small vendored WASM module
// (src/dash-orchard/, built from WINBIT32's packages/dash-orchard-wasm
// on dashpay's orchard fork — ~290KB, viewing-grade only, no prover).
//
// Same no-custody posture as the other chains: this module handles the
// FULL VIEWING KEY only. It can see incoming notes and compute their
// nullifiers; it can never spend.
//
// Everything network-shaped is dependency-injected (`sdk`, `wasm`) so
// the unit tests run with zero network and zero WASM.

import { readFile } from 'node:fs/promises';

/** Duffs per DASH (8 decimals, same as zatoshi). */
export const DUFFS_PER_DASH = 100_000_000;

/**
 * MMR chunk size of the Platform note stream. `start_index` MUST be a
 * multiple of this: drive-abci rejects anything else outright with
 * "start_index N is not chunk-aligned" (it is `1 << chunk_power`, and
 * chunk_power is 11 today). The cursor can therefore only ever move in
 * whole chunks — a 200-note stride made every query past the first fail.
 */
export const DASH_NOTES_CHUNK_SIZE = 2048;

/**
 * Page size for the encrypted-note stream: exactly one MMR chunk. A
 * query may legally span several adjacent chunks, but how many is a
 * consensus parameter (`max_query_chunks`) the node silently clamps to,
 * so asking for more buys nothing we can rely on.
 */
export const DASH_NOTES_PAGE_SIZE = DASH_NOTES_CHUNK_SIZE;

/** Hard cap per scan pass so a huge stream cannot wedge a tick. */
export const DASH_MAX_NOTES_PER_SCAN = 50_000;

let wasmPromise = null;

/** Load + initialise the vendored trial-decryption WASM (lazy, cached). */
export async function loadDashOrchardWasm() {
	if (!wasmPromise) {
		wasmPromise = (async () => {
			const mod = await import('./dash-orchard/dash_orchard_watch.js');
			const wasmUrl = new URL('./dash-orchard/dash_orchard_watch_bg.wasm', import.meta.url);
			await mod.default({ module_or_path: await readFile(wasmUrl) });
			return mod;
		})();
		wasmPromise.catch(() => { wasmPromise = null; });
	}
	return wasmPromise;
}

let sdkPromise = null;

/**
 * Connect an @dashevo/evo-sdk instance (lazy, cached; the dependency is
 * only imported when a dash chain is actually configured).
 */
export async function createDashPlatformSdk({ network = 'mainnet' } = {}) {
	if (!sdkPromise) {
		sdkPromise = (async () => {
			const { EvoSDK } = await import('@dashevo/evo-sdk');
			const sdk = new EvoSDK({ network, trusted: true });
			await sdk.connect();
			return sdk;
		})();
		sdkPromise.catch(() => { sdkPromise = null; });
	}
	return sdkPromise;
}

const toHex = (bytes) =>
	Array.from(bytes ?? [], (b) => b.toString(16).padStart(2, '0')).join('');

/**
 * Platform shielded notes are denominated in CREDITS, not duffs:
 * 1 duff = 1000 credits (dpp `CREDITS_PER_DUFF`). Quote amounts are in
 * duffs (COIN_DECIMALS.dash = 8), so scan output converts credits →
 * duffs, rounding DOWN so an underpayment can never round up to full.
 */
export const CREDITS_PER_DUFF = 1000n;

export const creditsToDuffs = (credits) => {
	const c = typeof credits === 'bigint' ? credits : BigInt(credits);
	return c / CREDITS_PER_DUFF;
};

/**
 * Derive watch-only keys for the receiving wallet from BIP-39 seed
 * bytes (hex string or Uint8Array). Ops helper for initial setup —
 * returns `{ fvk, defaultAddress }` (both hex); only viewing material.
 */
export async function deriveDashWatchKeys(seed, { network = 'mainnet', account = 0 } = {}) {
	const wasm = await loadDashOrchardWasm();
	const bytes = typeof seed === 'string'
		? Uint8Array.from(seed.match(/.{2}/gu) ?? [], (p) => parseInt(p, 16))
		: Uint8Array.from(seed);
	const keys = wasm.derive_watch_keys(bytes, network === 'mainnet', account);
	return { fvk: keys.fvk, defaultAddress: keys.default_address };
}

/**
 * Scan the Platform note stream for payments to our receiving FVK.
 *
 * Returns the `{ chainHeight, incoming }` shape `runCryptoRecvTick`
 * expects, plus `nextIndex` so the caller can persist the cursor and
 * resume instead of re-walking the stream:
 *
 *   incoming: [{ amountAtomic, memo, txHash, blockHeight, noteIndex, scope }]
 *
 * - `amountAtomic` is duffs (string → BigInt-safe).
 * - `memo` is the decoded kind-1 UTF-8 text (Dash memos are 36 bytes:
 *   4-byte kind + 32-byte payload — a `PG-…` quote token fits).
 * - `txHash` is the note's nullifier hex — unique per note, stable
 *   across scans, which is all the settle bookkeeping needs.
 * - `blockHeight`/`chainHeight` are both 1: Platform notes are final on
 *   arrival, so every payment reports exactly 1 confirmation.
 *
 * @param {{
 *   fvk: string, network?: string, startIndex?: number,
 *   pageSize?: number, maxNotes?: number,
 *   sdk?: object, wasm?: object,   // injected in tests
 * }} opts
 */
export async function scanDashReceiving({
	fvk,
	network = 'mainnet',
	startIndex = 0,
	pageSize = DASH_NOTES_PAGE_SIZE,
	maxNotes = DASH_MAX_NOTES_PER_SCAN,
	sdk,
	wasm
} = {}) {
	if (typeof fvk !== 'string' || !/^[0-9a-fA-F]{192}$/u.test(fvk.trim())) {
		throw new TypeError('scanDashReceiving: fvk must be a 96-byte hex full viewing key');
	}
	const wasmMod = wasm ?? await loadDashOrchardWasm();
	const client = sdk ?? await createDashPlatformSdk({ network });

	const incoming = [];
	// Queries must begin on a chunk boundary, so a cursor that isn't one
	// (an older build persisted a raw note count) is aligned DOWN and the
	// notes below it dropped after paging. Rounding up would skip
	// payments; re-reading up to a chunk is free — trial decryption is
	// pure and settlement is idempotent per (quote, tx).
	const from = Number(startIndex) > 0 ? Number(startIndex) : 0;
	const span = Math.max(
		DASH_NOTES_CHUNK_SIZE,
		Math.floor(Number(pageSize) / DASH_NOTES_CHUNK_SIZE) * DASH_NOTES_CHUNK_SIZE
	);
	let cursor = Math.floor(from / DASH_NOTES_CHUNK_SIZE) * DASH_NOTES_CHUNK_SIZE;
	let scanned = 0;

	while (scanned < maxNotes) {
		const page = await client.shielded.encryptedNotes(BigInt(cursor), span);
		if (!Array.isArray(page) || page.length === 0) break;

		const wireNotes = page.map((note, i) => ({
			index: cursor + i,
			// Platform stores the creating action's nullifier as the note's rho.
			rho: toHex(note.nullifier),
			cmx: toHex(note.cmx),
			note: toHex(note.encryptedNote)
		})).filter((note) => note.index >= from);
		for (const note of page) {
			if (typeof note.free === 'function') note.free();
		}

		const hits = wireNotes.length
			? wasmMod.trial_decrypt(fvk.trim().toLowerCase(), wireNotes)
			: [];
		for (const hit of hits) {
			incoming.push({
				// Platform denominates notes in credits; quote matching
				// wants duffs.
				amountAtomic: String(creditsToDuffs(hit.credits)),
				amountCredits: String(hit.credits),
				memo: hit.memo_text ?? '',
				txHash: hit.nullifier,
				blockHeight: 1,
				noteIndex: Number(hit.index),
				scope: hit.scope
			});
		}

		cursor += page.length;
		scanned += page.length;
		// A page that doesn't land back on a chunk boundary is the tail of
		// the stream: there is nothing after it, and asking anyway would be
		// rejected as unaligned. (Testing the boundary rather than a short
		// page also keeps us right if the node clamps `span` to its own
		// per-query cap, which is always a whole number of chunks.)
		if (cursor % DASH_NOTES_CHUNK_SIZE !== 0) break;
	}

	return { chainHeight: 1, incoming, nextIndex: cursor, scanned };
}
