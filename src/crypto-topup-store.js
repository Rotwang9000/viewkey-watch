// Persistence for privacy-coin (XMR/ZEC) credit-top-up quotes.
//
// A "quote" is a short-lived promise: "send exactly this much XMR (or
// this much ZEC carrying this memo) to this address within N minutes
// and we'll add $X of credit to your watch at this locked rate." The
// receive-poller (a separate process) watches our own receiving wallet
// through NFPT, matches an incoming payment to an open quote, waits for
// confirmations, then credits the watch via `topupWatch`.
//
// This table lives in the SAME SQLite file as `private_watches` so the
// poller can settle a quote and bump the watch's credit in one place.
// Every function takes the `db` handle first so tests use a `:memory:`
// DB with zero ceremony.

import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';

const QUOTE_DDL = `
CREATE TABLE IF NOT EXISTS crypto_topup_quotes (
	id TEXT PRIMARY KEY,
	watch_id TEXT NOT NULL,
	watch_token_hash TEXT NOT NULL,
	chain TEXT NOT NULL CHECK(chain IN ('monero','zcash')),
	recv_address TEXT NOT NULL,
	memo TEXT,                       -- zcash attribution token; NULL for monero
	quoted_usd_cents INTEGER NOT NULL,
	expected_atomic TEXT NOT NULL,   -- coin atomic units (bigint as string)
	usd_price_milli INTEGER NOT NULL,-- locked USD/coin * 1000 (audit trail)
	spread_bps INTEGER NOT NULL,
	status TEXT NOT NULL CHECK(status IN ('pending','confirming','settled','expired','cancelled')),
	seen_tx_hash TEXT,
	seen_atomic TEXT,
	seen_block_height INTEGER,
	confirmations INTEGER DEFAULT 0,
	credited_usd_cents INTEGER,
	created_at_ms INTEGER NOT NULL,
	expires_at_ms INTEGER NOT NULL,
	settled_at_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_quote_open ON crypto_topup_quotes(chain, status);
CREATE INDEX IF NOT EXISTS idx_quote_expiry ON crypto_topup_quotes(status, expires_at_ms);
CREATE INDEX IF NOT EXISTS idx_quote_watch ON crypto_topup_quotes(watch_id);
`;

const OPEN_STATES = Object.freeze(['pending', 'confirming']);

/** Create the quotes table + indexes. Idempotent; safe to call on every open. */
export function ensureCryptoTopupSchema(db) {
	db.exec(QUOTE_DDL);
}

function hashToken(token) {
	return createHash('sha256').update(String(token)).digest('hex');
}

function tokenMatches(hashHex, token) {
	const a = Buffer.from(hashHex, 'hex');
	const b = Buffer.from(hashToken(token), 'hex');
	if (a.length !== b.length) return false;
	return timingSafeEqual(a, b);
}

/**
 * Insert a new quote. `expectedAtomic` is a BigInt (coin atomic units).
 * `watchToken` is the caller's raw token — we store only its hash.
 * Returns the persisted row.
 */
export function createQuote(db, {
	id = randomUUID(),
	watchId,
	watchToken,
	chain,
	recvAddress,
	memo = null,
	quotedUsdCents,
	expectedAtomic,
	usdPriceMilli,
	spreadBps,
	createdAtMs,
	expiresAtMs
}) {
	if (chain !== 'monero' && chain !== 'zcash') {
		throw new TypeError(`createQuote: chain must be 'monero' or 'zcash', got ${chain}`);
	}
	if (typeof watchId !== 'string' || !watchId) throw new TypeError('createQuote: watchId required');
	if (typeof watchToken !== 'string' || !watchToken) throw new TypeError('createQuote: watchToken required');
	if (typeof recvAddress !== 'string' || !recvAddress) throw new TypeError('createQuote: recvAddress required');
	if (!Number.isInteger(quotedUsdCents) || quotedUsdCents <= 0) throw new TypeError('createQuote: quotedUsdCents must be a positive integer');
	if (typeof expectedAtomic !== 'bigint' || expectedAtomic <= 0n) throw new TypeError('createQuote: expectedAtomic must be a positive BigInt');
	db.prepare(`
		INSERT INTO crypto_topup_quotes
			(id, watch_id, watch_token_hash, chain, recv_address, memo,
			 quoted_usd_cents, expected_atomic, usd_price_milli, spread_bps,
			 status, created_at_ms, expires_at_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
	`).run(
		id, watchId, hashToken(watchToken), chain, recvAddress, memo,
		quotedUsdCents, expectedAtomic.toString(), usdPriceMilli, spreadBps,
		createdAtMs, expiresAtMs
	);
	return getQuote(db, id);
}

/** Fetch a quote by id (no auth). Returns the row or null. */
export function getQuote(db, id) {
	return db.prepare('SELECT * FROM crypto_topup_quotes WHERE id = ?').get(id) ?? null;
}

/**
 * Fetch a quote for a status read, gated by the watch token (the same
 * token that owns the watch). Returns:
 *   row                       on success
 *   { error: 'not_found' }    if the quote id is unknown
 *   { error: 'forbidden' }    if the token doesn't match
 */
export function getQuoteAuthorised(db, id, watchToken) {
	const row = getQuote(db, id);
	if (!row) return { error: 'not_found' };
	if (!watchToken || !tokenMatches(row.watch_token_hash, watchToken)) {
		return { error: 'forbidden' };
	}
	return row;
}

/**
 * Quotes the poller should still try to match for a chain:
 *   - 'pending' that haven't expired (still awaiting a first sighting),
 *   - 'confirming' (payment already seen — keep counting confs regardless
 *     of the original pay-by deadline), and
 *   - with `graceMs` > 0, 'expired' quotes whose deadline passed within
 *     the grace window. A payer who sent the exact memo/amount but whose
 *     payment was only *noticed* after expiry (slow confs, scanner
 *     outage) still deserves the credit — the memo/amount match makes a
 *     false attribution impossible, so late settling is always honest.
 */
export function listMatchable(db, chain, nowMs, { graceMs = 0 } = {}) {
	return db.prepare(`
		SELECT * FROM crypto_topup_quotes
		WHERE chain = ?
		  AND ( (status = 'pending' AND expires_at_ms > ?)
		     OR  status = 'confirming'
		     OR (status = 'expired' AND expires_at_ms > ?) )
		ORDER BY created_at_ms ASC
	`).all(chain, nowMs, nowMs - Math.max(0, graceMs));
}

/** True if an open quote on this chain already claims `expectedAtomic` (collision guard for XMR amount matching). */
export function hasOpenQuoteWithAmount(db, chain, expectedAtomic) {
	const row = db.prepare(`
		SELECT 1 FROM crypto_topup_quotes
		WHERE chain = ? AND expected_atomic = ? AND status IN ('pending','confirming')
		LIMIT 1
	`).get(chain, expectedAtomic.toString());
	return Boolean(row);
}

/**
 * Record that a matching payment was seen but isn't yet fully confirmed.
 * Accepts 'expired' too: a quote the sweep expired before its payment was
 * noticed flips straight to 'confirming' (see listMatchable grace window).
 */
export function markSeen(db, id, { txHash, seenAtomic, blockHeight, confirmations }) {
	db.prepare(`
		UPDATE crypto_topup_quotes
		SET status = 'confirming',
		    seen_tx_hash = ?,
		    seen_atomic = ?,
		    seen_block_height = ?,
		    confirmations = ?
		WHERE id = ? AND status IN ('pending','confirming','expired')
	`).run(txHash, String(seenAtomic), blockHeight ?? null, confirmations ?? 0, id);
	return getQuote(db, id);
}

/** Mark a quote fully settled (credit applied to the watch). */
export function markSettled(db, id, { creditedUsdCents, txHash, seenAtomic, confirmations, settledAtMs }) {
	db.prepare(`
		UPDATE crypto_topup_quotes
		SET status = 'settled',
		    credited_usd_cents = ?,
		    seen_tx_hash = COALESCE(?, seen_tx_hash),
		    seen_atomic = COALESCE(?, seen_atomic),
		    confirmations = ?,
		    settled_at_ms = ?
		WHERE id = ? AND status IN ('pending','confirming','expired')
	`).run(creditedUsdCents, txHash ?? null, seenAtomic == null ? null : String(seenAtomic), confirmations ?? 0, settledAtMs, id);
	return getQuote(db, id);
}

/** Expire 'pending' quotes whose pay-by deadline has passed. Returns the count expired. */
export function expireStalePending(db, nowMs) {
	const info = db.prepare(`
		UPDATE crypto_topup_quotes
		SET status = 'expired'
		WHERE status = 'pending' AND expires_at_ms <= ?
	`).run(nowMs);
	return info.changes;
}

/** Cancel a still-pending quote (owner-initiated). Returns true if a row changed. */
export function cancelQuote(db, id, watchToken) {
	const row = getQuote(db, id);
	if (!row) return false;
	if (!tokenMatches(row.watch_token_hash, watchToken)) return false;
	const info = db.prepare(`UPDATE crypto_topup_quotes SET status = 'cancelled' WHERE id = ? AND status = 'pending'`).run(id);
	return info.changes > 0;
}

/** Aggregate counters for the stats/health surface. */
export function quoteStatsSnapshot(db) {
	const rows = db.prepare(`SELECT status, COUNT(*) AS n FROM crypto_topup_quotes GROUP BY status`).all();
	const out = { pending: 0, confirming: 0, settled: 0, expired: 0, cancelled: 0 };
	for (const r of rows) out[r.status] = r.n;
	const credited = db.prepare(`SELECT COALESCE(SUM(credited_usd_cents),0) AS c FROM crypto_topup_quotes WHERE status='settled'`).get();
	out.settled_usd_cents = Number(credited?.c ?? 0);
	return out;
}

export { OPEN_STATES };
