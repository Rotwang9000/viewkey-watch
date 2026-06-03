// Minimal end-to-end example: a tiny HTTP server that lets a caller
// register a view-key "watch", then a timer polls a wallet-scanner
// backend and POSTs a signed webhook whenever the balance changes.
//
// Prerequisites:
//   * A running wallet-scanner backend (the NFPT API, or anything
//     implementing the same HTTP contract — see README "Backend").
//   * Node >= 20 (uses the global fetch + node:http).
//
// Run:
//   NFPT_BASE_URL=http://127.0.0.1:3555 \
//   NFPT_API_KEY=your-key \
//   PRIVATE_WATCH_ENCRYPTION_KEY=$(openssl rand -hex 32) \
//   node examples/basic-server.mjs
//
// Create a watch (Zcash UFVK shown; Monero needs {address, viewKey}):
//   curl -sX POST localhost:8900/watch -H 'content-type: application/json' -d '{
//     "chain":"zcash","address":"u1...","viewKey":"uview1...",
//     "webhookUrl":"https://example.com/hook"
//   }'

import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';

import {
	createNfptClient,
	openWatchDb,
	createWatch,
	parseMasterKey,
	encryptViewKey,
	generateWebhookSecret,
	runPollerTick,
	WATCH_CONSTANTS
} from '../src/index.js';

const PORT = Number(process.env.PORT || 8900);
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS || 60_000);

// 32-byte AES-GCM master key. View keys are encrypted at rest with it.
// In production set PRIVATE_WATCH_ENCRYPTION_KEY and keep it stable —
// rotating it makes existing ciphertexts undecryptable.
const masterKey = process.env.PRIVATE_WATCH_ENCRYPTION_KEY
	? parseMasterKey(process.env.PRIVATE_WATCH_ENCRYPTION_KEY)
	: (() => {
		const k = randomBytes(32);
		console.warn('[demo] no PRIVATE_WATCH_ENCRYPTION_KEY set — using an EPHEMERAL key (watches die on restart)');
		return k;
	})();

const db = openWatchDb(process.env.WATCH_DB || ':memory:');
const nfptClient = createNfptClient({
	baseUrl: process.env.NFPT_BASE_URL || 'http://127.0.0.1:3555',
	apiKey: process.env.NFPT_API_KEY || 'development-key-for-testing'
});

function readJson(req) {
	return new Promise((resolve, reject) => {
		let raw = '';
		req.on('data', (c) => { raw += c; if (raw.length > 1 << 16) req.destroy(); });
		req.on('end', () => { try { resolve(JSON.parse(raw || '{}')); } catch (e) { reject(e); } });
		req.on('error', reject);
	});
}

const server = createServer(async (req, res) => {
	if (req.method !== 'POST' || req.url !== '/watch') {
		res.writeHead(404).end('POST /watch');
		return;
	}
	try {
		const body = await readJson(req);
		// NOTE: production code should additionally run the SSRF-safe
		// validators in `watch` (validateWatchRequest +
		// assertWebhookUrlSafe / resolveAndValidateWatchRequest).
		const secret = generateWebhookSecret();
		// Monero watches encrypt the private view key; Zcash watches
		// encrypt the UFVK. Both are read-only and cannot spend.
		const created = createWatchRow(body, secret);
		res.writeHead(200, { 'content-type': 'application/json' });
		res.end(JSON.stringify({
			id: created.id,
			watchToken: created.token,       // shown ONCE — store it to top up / cancel
			webhookSecret: secret,           // verify x-viewkey-signature with this
			expiresAt: created.expiresAt
		}));
	}
	catch (err) {
		res.writeHead(400, { 'content-type': 'application/json' });
		res.end(JSON.stringify({ error: String(err?.message ?? err) }));
	}
});

function createWatchRow(body, secret) {
	const viewKey = body.viewKey ?? body.ufvk;
	if (!body.chain || !body.address || !viewKey || !body.webhookUrl) {
		throw new Error('chain, address, viewKey/ufvk and webhookUrl are required');
	}
	return createWatch(db, {
		chain: body.chain,
		address: body.address,
		viewKeyCiphertext: encryptViewKey(viewKey, masterKey),
		webhookUrl: body.webhookUrl,
		webhookSecret: secret,
		birthdayHeight: body.birthdayHeight ?? null,
		creditAtomic: WATCH_CONSTANTS.STARTER_CREDIT_ATOMIC,
		dayRateAtomic: WATCH_CONSTANTS.DAY_RATE_ATOMIC,
		callRateAtomic: WATCH_CONSTANTS.CALL_RATE_ATOMIC,
		lowCreditThresholdAtomic: WATCH_CONSTANTS.LOW_CREDIT_THRESHOLD_ATOMIC
	});
}

server.listen(PORT, () => console.log(`[demo] listening on :${PORT} — POST /watch to register`));

// Drive the poll loop. Each tick bills the credit meter, scans every
// active watch via the backend, and delivers signed webhooks on change.
setInterval(async () => {
	try {
		const summary = await runPollerTick({ db, masterKey, nfptClient });
		if (summary.webhooks_attempted || summary.errors.length) {
			console.log('[poll]', JSON.stringify({
				seen: summary.watches_seen,
				delivered: summary.webhooks_delivered,
				failed: summary.webhooks_failed,
				errors: summary.errors.length
			}));
		}
	}
	catch (err) {
		console.error('[poll] tick failed:', err?.message ?? err);
	}
}, POLL_INTERVAL_MS);
