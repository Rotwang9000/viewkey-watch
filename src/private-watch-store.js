// SQLite persistence for the private-watch service.
//
// Unlike `db.js` (which is a read-only handle to the bot's mev-logs
// DB) this is the only writer in the project. The schema is small —
// one table — and we own both the writer (rest-server + poller) and
// the reader so there's no migration etiquette to worry about; the
// DDL self-creates on first open.
//
// Rows store:
//   - the encrypted view key (NEVER plaintext on disk)
//   - the per-watch webhook signing secret (plaintext: the receiver
//     already has it; protecting it from a host-compromised attacker
//     buys nothing)
//   - the watch token hash (constant-time check on poll/delete)
//   - balance state snapshots (last reported vs last observed)
//   - bookkeeping for the poller (next attempt, attempt count, dead-letter flag)
//
// The store is intentionally framework-agnostic — `rest-server.js`
// and `scripts/private-watch-poller.mjs` both consume the same
// exports. That keeps the surface easy to test with a `:memory:` DB.

import Database from 'better-sqlite3';
import { createHash, randomUUID, randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const WATCH_DDL = `
CREATE TABLE IF NOT EXISTS private_watches (
	id TEXT PRIMARY KEY,
	token_hash TEXT NOT NULL,
	chain TEXT NOT NULL CHECK(chain IN ('monero','zcash')),
	address TEXT NOT NULL,
	view_key_ct TEXT NOT NULL,
	webhook_url TEXT NOT NULL,
	webhook_secret TEXT NOT NULL,
	birthday_height INTEGER,
	expires_at_ms INTEGER NOT NULL,
	created_at_ms INTEGER NOT NULL,

	-- prepaid credit meter (all values atomic USDC; 1_000_000 = $1.00)
	credit_atomic INTEGER DEFAULT 0,
	credit_topups_atomic INTEGER DEFAULT 0,
	credit_billed_atomic INTEGER DEFAULT 0,
	credit_last_billed_ms INTEGER,
	low_credit_warned INTEGER DEFAULT 0,

	-- upstream NFPT job linkage (re-established lazily on poll if NULL/stale)
	nfpt_job_id TEXT,
	nfpt_job_token TEXT,
	nfpt_job_started_at_ms INTEGER,

	-- balance state (JSON)
	last_known_balance TEXT,    -- most recent snapshot from NFPT
	last_delivered_balance TEXT, -- snapshot at last successful webhook
	last_polled_at_ms INTEGER,
	last_delivered_at_ms INTEGER,

	-- delivery bookkeeping
	delivery_attempts INTEGER DEFAULT 0,
	delivery_count INTEGER DEFAULT 0,
	last_delivery_error TEXT,
	last_delivered_event TEXT,
	dead INTEGER DEFAULT 0,
	cancelled INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_watch_active
	ON private_watches(cancelled, dead, expires_at_ms);
CREATE INDEX IF NOT EXISTS idx_watch_poll
	ON private_watches(last_polled_at_ms);
`;
// NOTE: the idx_watch_credit index is created AFTER migrations below
// because on a pre-credit-meter DB the column doesn't yet exist when
// WATCH_DDL runs, and even `CREATE INDEX IF NOT EXISTS` will throw if
// the referenced column is missing.

/**
 * Open (or create) the watch DB. Pass a `:memory:` path in tests.
 * The parent directory is created if absent so deployments don't
 * have to pre-mkdir the state dir.
 *
 * Idempotent schema migration: new columns are added in successive
 * revisions. We ALTER TABLE … ADD COLUMN if the table already
 * exists without them, ignoring "duplicate column" errors so re-opens
 * are a no-op.
 */
export function openWatchDb(path) {
	if (typeof path !== 'string' || path.length === 0) {
		throw new TypeError('openWatchDb: path must be a non-empty string');
	}
	if (path !== ':memory:') {
		try { mkdirSync(dirname(path), { recursive: true }); }
		catch { /* ignore: better-sqlite3 will surface a clearer error */ }
	}
	const db = new Database(path);
	db.pragma('journal_mode = WAL');
	db.pragma('synchronous = NORMAL');
	db.pragma('foreign_keys = ON');
	db.exec(WATCH_DDL);
	// Migrations layered on top — order doesn't matter as each ADD is
	// idempotent. Group them so the next maintainer can append.
	addColumnIfMissing(db, 'private_watches', 'last_delivered_event', 'TEXT');
	addColumnIfMissing(db, 'private_watches', 'credit_atomic', 'INTEGER DEFAULT 0');
	addColumnIfMissing(db, 'private_watches', 'credit_topups_atomic', 'INTEGER DEFAULT 0');
	addColumnIfMissing(db, 'private_watches', 'credit_billed_atomic', 'INTEGER DEFAULT 0');
	addColumnIfMissing(db, 'private_watches', 'credit_last_billed_ms', 'INTEGER');
	addColumnIfMissing(db, 'private_watches', 'low_credit_warned', 'INTEGER DEFAULT 0');
	// Surge pricing: the rate a watch was created at is stored on
	// the row so existing watches keep their cheap rate even when
	// the global surge moves up. NULL on legacy rows; callers fall
	// back to WATCH_CONSTANTS.* (see effectiveDayRate in
	// private-watch-pricing.js).
	addColumnIfMissing(db, 'private_watches', 'day_rate_atomic', 'INTEGER');
	addColumnIfMissing(db, 'private_watches', 'call_rate_atomic', 'INTEGER');
	addColumnIfMissing(db, 'private_watches', 'low_credit_threshold_atomic', 'INTEGER');
	// Now that the credit columns exist (whether freshly created or
	// freshly added by ALTER TABLE) we can safely add the lookup index.
	try { db.exec('CREATE INDEX IF NOT EXISTS idx_watch_credit ON private_watches(credit_atomic)'); }
	catch { /* defensive: ancient SQLite without IF NOT EXISTS for indices */ }
	return db;
}

function addColumnIfMissing(db, table, col, type) {
	try { db.prepare(`ALTER TABLE ${table} ADD COLUMN ${col} ${type}`).run(); }
	catch (err) {
		if (!/duplicate column/i.test(err?.message ?? '')) throw err;
	}
}

function sha256(bytes) {
	return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Generate a watch ID + watch token pair. The token is returned to
 * the caller (only) and a sha256 of it is stored. Polls/cancellations
 * present the token and we constant-time compare hashes.
 */
function newIdAndToken() {
	return {
		id: randomUUID(),
		token: randomBytes(32).toString('base64url')
	};
}

function constantEqHex(a, b) {
	if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
	const bufA = Buffer.from(a, 'hex');
	const bufB = Buffer.from(b, 'hex');
	if (bufA.length !== bufB.length) return false;
	return timingSafeEqual(bufA, bufB);
}

/**
 * Create a new watch row. Pure-input contract — the caller has
 * already done validation (chain, address shape, encrypted view key,
 * webhook URL safety, etc.) and just hands us the resolved values.
 *
 * `creditAtomic` is the starter credit (atomic USDC units). The
 * caller passes the value that matches the paywall tier they just
 * settled. We seed `credit_last_billed_ms = nowMs` so per-day
 * billing starts ticking immediately.
 *
 * `expiresAt` is derived from credit + day-rate so the existing
 * downstream readers (purgeExpired, listActiveWatches) keep working.
 */
export function createWatch(db, params) {
	const {
		chain,
		address,
		viewKeyCiphertext,
		webhookUrl,
		webhookSecret,
		birthdayHeight = null,
		creditAtomic,
		dayRateAtomic,
		// New optional fields. Both default to NULL (legacy
		// behaviour) so existing callers that haven't migrated to
		// surge pricing keep working — the meter math will read the
		// fallback from WATCH_CONSTANTS via effectiveDayRate().
		callRateAtomic = null,
		lowCreditThresholdAtomic = null,
		maxLifetimeMs = Number.MAX_SAFE_INTEGER,
		nowMs = Date.now()
	} = params;
	if (!['monero', 'zcash'].includes(chain)) {
		throw new TypeError(`createWatch: chain=${chain} must be 'monero' or 'zcash'`);
	}
	if (typeof address !== 'string' || address.length === 0) {
		throw new TypeError('createWatch: address required');
	}
	if (typeof viewKeyCiphertext !== 'string' || viewKeyCiphertext.length === 0) {
		throw new TypeError('createWatch: viewKeyCiphertext required');
	}
	if (typeof webhookUrl !== 'string' || webhookUrl.length === 0) {
		throw new TypeError('createWatch: webhookUrl required');
	}
	if (typeof webhookSecret !== 'string' || webhookSecret.length === 0) {
		throw new TypeError('createWatch: webhookSecret required');
	}
	if (!Number.isInteger(creditAtomic) || creditAtomic <= 0) {
		throw new TypeError('createWatch: creditAtomic must be a positive integer');
	}
	if (!Number.isInteger(dayRateAtomic) || dayRateAtomic <= 0) {
		throw new TypeError('createWatch: dayRateAtomic must be a positive integer');
	}
	if (callRateAtomic != null && (!Number.isInteger(callRateAtomic) || callRateAtomic <= 0)) {
		throw new TypeError('createWatch: callRateAtomic must be a positive integer (or omitted)');
	}
	if (lowCreditThresholdAtomic != null && (!Number.isInteger(lowCreditThresholdAtomic) || lowCreditThresholdAtomic < 0)) {
		throw new TypeError('createWatch: lowCreditThresholdAtomic must be a non-negative integer (or omitted)');
	}
	const { id, token } = newIdAndToken();
	const tokenHash = sha256(Buffer.from(token, 'utf8'));
	const naiveExpires = nowMs + Math.floor((creditAtomic * 86_400_000) / dayRateAtomic);
	const expiresAt = Math.min(naiveExpires, nowMs + maxLifetimeMs);
	db.prepare(`
		INSERT INTO private_watches (
			id, token_hash, chain, address, view_key_ct,
			webhook_url, webhook_secret, birthday_height,
			expires_at_ms, created_at_ms,
			credit_atomic, credit_topups_atomic, credit_last_billed_ms,
			day_rate_atomic, call_rate_atomic, low_credit_threshold_atomic
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`).run(
		id,
		tokenHash,
		chain,
		address,
		viewKeyCiphertext,
		webhookUrl,
		webhookSecret,
		birthdayHeight,
		expiresAt,
		nowMs,
		creditAtomic,
		creditAtomic,
		nowMs,
		dayRateAtomic,
		callRateAtomic,
		lowCreditThresholdAtomic
	);
	return { id, token, expiresAt, createdAt: nowMs, creditAtomic, dayRateAtomic, callRateAtomic, lowCreditThresholdAtomic };
}

/**
 * Fetch a row by ID *and* verify the caller has the matching token.
 * Returns:
 *   - `null` if no row exists
 *   - `{ error: 'forbidden' }` if the token doesn't match
 *   - the row object otherwise
 *
 * Token comparison is constant-time via timingSafeEqual over the
 * sha256 buffers.
 */
export function getWatch(db, id, token) {
	const row = db.prepare('SELECT * FROM private_watches WHERE id = ?').get(id);
	if (!row) return null;
	const presented = sha256(Buffer.from(String(token ?? ''), 'utf8'));
	if (!constantEqHex(presented, row.token_hash)) return { error: 'forbidden' };
	return row;
}

/**
 * Fetch a row by ID with no token check — for trusted server-side
 * callers (the receive-poller reads the row to honour its locked-in
 * surge rate before crediting). Returns the row or null.
 */
export function getWatchById(db, id) {
	return db.prepare('SELECT * FROM private_watches WHERE id = ?').get(id) ?? null;
}

/**
 * Cancel a watch (mark cancelled = 1). Returns true on success,
 * false if not found / wrong token. The row remains for record
 * retention but the poller filters it out via the cancelled
 * predicate.
 */
export function cancelWatch(db, id, token) {
	const got = getWatch(db, id, token);
	if (!got || got.error) return false;
	db.prepare('UPDATE private_watches SET cancelled = 1 WHERE id = ?').run(id);
	return true;
}

/**
 * Return all watches that are not cancelled, not dead, have a
 * positive credit balance, and are not past their lifetime cap. The
 * poller drives off this list, so once `credit_atomic` hits zero
 * the watch goes silent until topped up.
 */
export function listActiveWatches(db, { nowMs = Date.now() } = {}) {
	return db.prepare(`
		SELECT *
		FROM private_watches
		WHERE cancelled = 0
		  AND dead = 0
		  AND credit_atomic > 0
		  AND expires_at_ms > ?
		ORDER BY COALESCE(last_polled_at_ms, 0) ASC
	`).all(nowMs);
}

/**
 * Patch a watch's poller state. Only the keys present in `patch` are
 * touched; unknown keys are silently rejected so a typo can't widen
 * the field list by mistake. Uses a hardcoded ALLOWED list as the
 * schema check.
 */
export function updateWatchState(db, id, patch) {
	const ALLOWED = new Set([
		'nfpt_job_id',
		'nfpt_job_token',
		'nfpt_job_started_at_ms',
		'last_known_balance',
		'last_delivered_balance',
		'last_polled_at_ms',
		'last_delivered_at_ms',
		'last_delivered_event',
		'delivery_attempts',
		'delivery_count',
		'last_delivery_error',
		'dead',
		'credit_atomic',
		'credit_topups_atomic',
		'credit_billed_atomic',
		'credit_last_billed_ms',
		'low_credit_warned',
		'expires_at_ms'
	]);
	const cols = [];
	const vals = [];
	for (const [k, v] of Object.entries(patch || {})) {
		if (!ALLOWED.has(k)) continue;
		cols.push(`${k} = ?`);
		vals.push(v);
	}
	if (cols.length === 0) return 0;
	vals.push(id);
	const sql = `UPDATE private_watches SET ${cols.join(', ')} WHERE id = ?`;
	const info = db.prepare(sql).run(...vals);
	return info.changes;
}

/**
 * Apply a top-up to a watch in an atomic UPDATE. Returns
 *   { ok: true, row }       on success (row is the post-update row)
 *   { ok: false, reason }   if the watch is missing, the token doesn't
 *                           match, or the watch is cancelled.
 *
 * Token validation is constant-time. We bump `low_credit_warned` to 0
 * if the top-up clears the threshold so the warning can fire again
 * next time the meter dips.
 */
export function topupWatch(db, id, token, opts) {
	const { creditAtomic, dayRateAtomic } = opts;
	if (!Number.isInteger(creditAtomic) || creditAtomic <= 0) {
		throw new TypeError('topupWatch: creditAtomic must be a positive integer');
	}
	if (!Number.isInteger(dayRateAtomic) || dayRateAtomic <= 0) {
		throw new TypeError('topupWatch: dayRateAtomic must be a positive integer');
	}
	const got = getWatch(db, id, token);
	if (!got) return { ok: false, reason: 'not_found' };
	if (got.error === 'forbidden') return { ok: false, reason: 'forbidden' };
	if (got.cancelled === 1) return { ok: false, reason: 'cancelled' };
	return creditWatchRow(db, got, opts);
}

/**
 * Token-less credit application for trusted server-side callers — the
 * crypto receive-poller, which detects an on-chain payment and credits
 * the matching watch. The watch token never leaves the user so an
 * on-chain event can't present it; the poller is already a privileged
 * local process sharing this DB. Behaviour otherwise mirrors
 * `topupWatch` (same expiry recompute + low-credit latch reset).
 */
export function topupWatchById(db, id, opts) {
	const { creditAtomic, dayRateAtomic } = opts;
	if (!Number.isInteger(creditAtomic) || creditAtomic <= 0) {
		throw new TypeError('topupWatchById: creditAtomic must be a positive integer');
	}
	if (!Number.isInteger(dayRateAtomic) || dayRateAtomic <= 0) {
		throw new TypeError('topupWatchById: dayRateAtomic must be a positive integer');
	}
	const got = db.prepare('SELECT * FROM private_watches WHERE id = ?').get(id);
	if (!got) return { ok: false, reason: 'not_found' };
	if (got.cancelled === 1) return { ok: false, reason: 'cancelled' };
	return creditWatchRow(db, got, opts);
}

/**
 * Shared core for `topupWatch` / `topupWatchById`: given an
 * already-fetched (and authorised) row, add `creditAtomic`, recompute
 * the credit-derived expiry (capped at the lifetime ceiling), and
 * re-arm the low-credit warning if the balance climbs back above the
 * threshold. Returns `{ ok: true, row }` with the post-update row.
 */
function creditWatchRow(db, got, {
	creditAtomic,
	dayRateAtomic,
	lowThresholdAtomic,
	maxLifetimeMs,
	nowMs = Date.now()
}) {
	const newCredit = Number(got.credit_atomic ?? 0) + creditAtomic;
	const newTopups = Number(got.credit_topups_atomic ?? 0) + creditAtomic;
	const naiveExpires = nowMs + Math.floor((newCredit * 86_400_000) / dayRateAtomic);
	const cappedExpires = maxLifetimeMs && Number.isFinite(maxLifetimeMs)
		? Math.min(naiveExpires, nowMs + maxLifetimeMs)
		: naiveExpires;
	const resetWarn = (typeof lowThresholdAtomic === 'number' && newCredit > lowThresholdAtomic) ? 0 : (got.low_credit_warned ?? 0);
	db.prepare(`
		UPDATE private_watches
		SET credit_atomic = ?,
		    credit_topups_atomic = ?,
		    expires_at_ms = ?,
		    low_credit_warned = ?,
		    dead = CASE WHEN dead = 1 AND ? > 0 THEN 0 ELSE dead END
		WHERE id = ?
	`).run(newCredit, newTopups, cappedExpires, resetWarn, newCredit, got.id);
	const updated = db.prepare('SELECT * FROM private_watches WHERE id = ?').get(got.id);
	return { ok: true, row: updated };
}

/**
 * Reset the NFPT job linkage. Used when the upstream job has aged out
 * and the poller needs to start a fresh one on the next tick.
 */
export function clearNfptJob(db, id) {
	db.prepare(`
		UPDATE private_watches
		SET nfpt_job_id = NULL,
		    nfpt_job_token = NULL,
		    nfpt_job_started_at_ms = NULL
		WHERE id = ?
	`).run(id);
}

/**
 * Hard-delete any watch row whose expires_at_ms is in the past.
 * Returns the number of rows pruned. Run from the poller at end of
 * each cycle to keep the table tiny.
 */
export function purgeExpired(db, { nowMs = Date.now() } = {}) {
	const info = db.prepare('DELETE FROM private_watches WHERE expires_at_ms <= ?').run(nowMs);
	return info.changes;
}

/**
 * Quick stats for the public health endpoint. We deliberately do NOT
 * include any of the user-supplied data here — just counters — so the
 * health check is safe to expose without auth.
 */
export function statsSnapshot(db, { nowMs = Date.now() } = {}) {
	const counters = db.prepare(`
		SELECT
			COUNT(*) AS total,
			SUM(CASE WHEN cancelled = 0 AND dead = 0 AND credit_atomic > 0 AND expires_at_ms > ? THEN 1 ELSE 0 END) AS active,
			SUM(CASE WHEN dead = 1 THEN 1 ELSE 0 END) AS dead,
			SUM(CASE WHEN cancelled = 0 AND dead = 0 AND credit_atomic <= 0 THEN 1 ELSE 0 END) AS out_of_credit,
			SUM(CASE WHEN expires_at_ms <= ? THEN 1 ELSE 0 END) AS expired,
			SUM(CASE WHEN chain = 'monero' THEN 1 ELSE 0 END) AS monero,
			SUM(CASE WHEN chain = 'zcash' THEN 1 ELSE 0 END) AS zcash,
			SUM(delivery_count) AS total_deliveries,
			COALESCE(SUM(credit_atomic), 0) AS total_credit_atomic,
			COALESCE(SUM(credit_topups_atomic), 0) AS total_topups_atomic,
			COALESCE(SUM(credit_billed_atomic), 0) AS total_billed_atomic
		FROM private_watches
	`).get(nowMs, nowMs);
	return {
		total: counters.total ?? 0,
		active: counters.active ?? 0,
		dead: counters.dead ?? 0,
		out_of_credit: counters.out_of_credit ?? 0,
		expired: counters.expired ?? 0,
		by_chain: {
			monero: counters.monero ?? 0,
			zcash: counters.zcash ?? 0
		},
		total_deliveries: counters.total_deliveries ?? 0,
		credit: {
			balance_atomic: String(counters.total_credit_atomic ?? 0),
			topups_atomic: String(counters.total_topups_atomic ?? 0),
			billed_atomic: String(counters.total_billed_atomic ?? 0)
		}
	};
}

export const WATCH_SCHEMA = Object.freeze({ WATCH_DDL });
