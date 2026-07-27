// Pins the dash receive-scan contract: page the note stream from a
// cursor, hand the WASM the hex wire fields it expects, map hits to the
// `{ chainHeight, incoming }` shape runCryptoRecvTick consumes, and
// report instant finality (blockHeight = chainHeight = 1).

import { jest } from '@jest/globals';
import {
	scanDashReceiving,
	creditsToDuffs,
	CREDITS_PER_DUFF,
	DASH_NOTES_PAGE_SIZE,
	DASH_NOTES_CHUNK_SIZE
} from '../src/dash-orchard-scan.js';

const FVK = 'ab'.repeat(96);

const bytes = (n, fill) => new Uint8Array(n).fill(fill);

/** One full MMR chunk of opaque notes. */
const chunk = () => Array.from({ length: DASH_NOTES_CHUNK_SIZE }, () => ({
	nullifier: bytes(32, 1), cmx: bytes(32, 2), encryptedNote: bytes(216, 3)
}));

function makeSdk(pages) {
	const encryptedNotes = jest.fn();
	for (const page of pages) encryptedNotes.mockResolvedValueOnce(page);
	encryptedNotes.mockResolvedValue([]);
	return { shielded: { encryptedNotes } };
}

describe('scanDashReceiving', () => {
	test('rejects a malformed fvk before touching the network', async () => {
		await expect(scanDashReceiving({ fvk: 'nope', sdk: {}, wasm: {} }))
			.rejects.toThrow(/full viewing key/u);
		await expect(scanDashReceiving({ sdk: {}, wasm: {} }))
			.rejects.toThrow(/full viewing key/u);
	});

	test('pages from the cursor and maps hits to incoming payments', async () => {
		const fullPage = Array.from({ length: DASH_NOTES_PAGE_SIZE }, () => ({
			nullifier: bytes(32, 1), cmx: bytes(32, 2), encryptedNote: bytes(216, 3)
		}));
		const shortPage = [
			{ nullifier: bytes(32, 4), cmx: bytes(32, 5), encryptedNote: bytes(216, 6) }
		];
		const sdk = makeSdk([fullPage, shortPage]);
		const start = DASH_NOTES_CHUNK_SIZE * 2;

		const wasm = {
			trial_decrypt: jest.fn()
				.mockReturnValueOnce([{
					index: 7, credits: '123456789', scope: 'external',
					nullifier: 'c1'.repeat(32), memo_text: 'PG-3f4807e5', memo_hex: '00'.repeat(36),
					address: 'aa'.repeat(43)
				}])
				.mockReturnValueOnce([])
		};

		const result = await scanDashReceiving({ fvk: FVK, startIndex: start, sdk, wasm });

		expect(sdk.shielded.encryptedNotes).toHaveBeenNthCalledWith(1, BigInt(start), DASH_NOTES_PAGE_SIZE);
		expect(sdk.shielded.encryptedNotes)
			.toHaveBeenNthCalledWith(2, BigInt(start + DASH_NOTES_CHUNK_SIZE), DASH_NOTES_PAGE_SIZE);
		expect(result.nextIndex).toBe(start + DASH_NOTES_CHUNK_SIZE + 1);
		expect(result.scanned).toBe(DASH_NOTES_CHUNK_SIZE + 1);
		expect(result.chainHeight).toBe(1);

		// The WASM got the hex wire fields, indexed from the cursor.
		const [fvkArg, wireNotes] = wasm.trial_decrypt.mock.calls[0];
		expect(fvkArg).toBe(FVK);
		expect(wireNotes[0]).toEqual({
			index: start,
			rho: '01'.repeat(32),
			cmx: '02'.repeat(32),
			note: '03'.repeat(216)
		});

		expect(result.incoming).toEqual([{
			// The wasm reported 123456789 CREDITS; matching wants duffs
			// (1 duff = 1000 credits, floor division).
			amountAtomic: '123456',
			amountCredits: '123456789',
			memo: 'PG-3f4807e5',
			txHash: 'c1'.repeat(32),
			blockHeight: 1,
			noteIndex: 7,
			scope: 'external'
		}]);
	});

	test('frees SDK wasm note handles after reading them', async () => {
		const free = jest.fn();
		const sdk = makeSdk([[
			{ nullifier: bytes(32, 1), cmx: bytes(32, 2), encryptedNote: bytes(216, 3), free }
		]]);
		const wasm = { trial_decrypt: jest.fn().mockReturnValue([]) };
		await scanDashReceiving({ fvk: FVK, sdk, wasm });
		expect(free).toHaveBeenCalledTimes(1);
	});

	test('an empty memo becomes an empty string (never undefined)', async () => {
		const sdk = makeSdk([[
			{ nullifier: bytes(32, 1), cmx: bytes(32, 2), encryptedNote: bytes(216, 3) }
		]]);
		const wasm = {
			trial_decrypt: jest.fn().mockReturnValue([{
				index: 0, credits: '1', scope: 'internal',
				nullifier: 'c2'.repeat(32), memo_text: null, memo_hex: '00'.repeat(36),
				address: 'aa'.repeat(43)
			}])
		};
		const result = await scanDashReceiving({ fvk: FVK, sdk, wasm });
		expect(result.incoming[0].memo).toBe('');
	});

	test('maxNotes caps the walk mid-stream', async () => {
		const page = chunk();
		const sdk = makeSdk([page, page, page]);
		const wasm = { trial_decrypt: jest.fn().mockReturnValue([]) };
		const result = await scanDashReceiving({
			fvk: FVK, sdk, wasm, maxNotes: DASH_NOTES_CHUNK_SIZE + 1
		});
		expect(result.scanned).toBe(DASH_NOTES_CHUNK_SIZE * 2); // stops after the page that crosses the cap
		expect(sdk.shielded.encryptedNotes).toHaveBeenCalledTimes(2);
	});

	// drive-abci rejects any start_index that isn't a multiple of the MMR
	// chunk size, so the pager may only ever move a whole chunk at a time.
	// A 200-note stride made the second query — and with it every dash
	// scan — fail with "start_index 200 is not chunk-aligned".
	describe('chunk alignment', () => {
		test('every query starts on a chunk boundary', async () => {
			const sdk = makeSdk([chunk(), chunk(), chunk().slice(0, 5)]);
			const wasm = { trial_decrypt: jest.fn().mockReturnValue([]) };
			await scanDashReceiving({ fvk: FVK, sdk, wasm });

			const starts = sdk.shielded.encryptedNotes.mock.calls.map(([at]) => at);
			expect(starts).toEqual([0n, BigInt(DASH_NOTES_CHUNK_SIZE), BigInt(DASH_NOTES_CHUNK_SIZE * 2)]);
			for (const at of starts) expect(at % BigInt(DASH_NOTES_CHUNK_SIZE)).toBe(0n);
		});

		test('a partial chunk ends the walk — the next index would be unaligned', async () => {
			const sdk = makeSdk([chunk().slice(0, 200)]);
			const wasm = { trial_decrypt: jest.fn().mockReturnValue([]) };
			const result = await scanDashReceiving({ fvk: FVK, sdk, wasm });
			expect(sdk.shielded.encryptedNotes).toHaveBeenCalledTimes(1);
			expect(result.nextIndex).toBe(200);
		});

		test('an unaligned cursor is aligned DOWN and the notes below it dropped', async () => {
			const sdk = makeSdk([chunk().slice(0, 300)]);
			const wasm = { trial_decrypt: jest.fn().mockReturnValue([]) };
			await scanDashReceiving({ fvk: FVK, startIndex: 200, sdk, wasm });

			// Aligned down to 0 (rounding up to 2048 would skip payments).
			expect(sdk.shielded.encryptedNotes).toHaveBeenCalledWith(0n, DASH_NOTES_PAGE_SIZE);
			const [, wireNotes] = wasm.trial_decrypt.mock.calls[0];
			expect(wireNotes).toHaveLength(100);
			expect(wireNotes[0].index).toBe(200);
		});

		test('a page size below one chunk is raised to a whole chunk', async () => {
			const sdk = makeSdk([chunk().slice(0, 1)]);
			const wasm = { trial_decrypt: jest.fn().mockReturnValue([]) };
			await scanDashReceiving({ fvk: FVK, sdk, wasm, pageSize: 200 });
			expect(sdk.shielded.encryptedNotes).toHaveBeenCalledWith(0n, DASH_NOTES_CHUNK_SIZE);
		});

		test('a node that clamps the page to its own cap keeps the walk going', async () => {
			// Ask for 4 chunks; the node only allows 1 and silently returns
			// that. A short-page test would call this the end of the stream.
			const sdk = makeSdk([chunk(), chunk().slice(0, 7)]);
			const wasm = { trial_decrypt: jest.fn().mockReturnValue([]) };
			const result = await scanDashReceiving({
				fvk: FVK, sdk, wasm, pageSize: DASH_NOTES_CHUNK_SIZE * 4
			});
			expect(sdk.shielded.encryptedNotes).toHaveBeenCalledTimes(2);
			expect(result.scanned).toBe(DASH_NOTES_CHUNK_SIZE + 7);
		});
	});
});

describe('creditsToDuffs', () => {
	test('1 duff = 1000 credits, floor division (never rounds an underpayment up)', () => {
		expect(CREDITS_PER_DUFF).toBe(1000n);
		expect(creditsToDuffs('1000')).toBe(1n);
		expect(creditsToDuffs('999')).toBe(0n);
		expect(creditsToDuffs(250695832400n)).toBe(250695832n);
	});
});
