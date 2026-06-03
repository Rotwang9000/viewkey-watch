// Tests for the watch persistence layer. We hammer the schema with
// an in-memory SQLite DB so the tests are deterministic and don't
// touch /var/lib. Token-comparison is exercised both for success and
// failure paths so we catch any constant-time regression.

import { describe, test, expect, beforeEach } from '@jest/globals';
import Database from 'better-sqlite3';
import { randomUUID } from 'node:crypto';
import { unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';

import {
	openWatchDb,
	createWatch,
	getWatch,
	cancelWatch,
	listActiveWatches,
	updateWatchState,
	clearNfptJob,
	purgeExpired,
	statsSnapshot,
	topupWatch
} from '../src/private-watch-store.js';
import { WATCH_CONSTANTS } from '../src/private-watch.js';

let db;
const NOW = 1_700_000_000_000;
const DAY_MS = 86_400_000;
// Default credit + day-rate used across these tests. 7 days of idle
// credit at the constants' day rate so existing assertions about
// `expires_at_ms === NOW + 7d` continue to hold without rewrites.
const SEVEN_DAY_CREDIT_ATOMIC = 7 * WATCH_CONSTANTS.DAY_RATE_ATOMIC;

function makeWatch(extra = {}) {
	return createWatch(db, {
		chain: 'monero',
		address: '4'.repeat(95),
		viewKeyCiphertext: 'b64ciphertext',
		webhookUrl: 'https://example.com/hook',
		webhookSecret: 'a'.repeat(64),
		birthdayHeight: null,
		creditAtomic: SEVEN_DAY_CREDIT_ATOMIC,
		dayRateAtomic: WATCH_CONSTANTS.DAY_RATE_ATOMIC,
		maxLifetimeMs: WATCH_CONSTANTS.MAX_WATCH_LIFETIME_MS,
		nowMs: NOW,
		...extra
	});
}

beforeEach(() => {
	db = openWatchDb(':memory:');
});

describe('schema bootstrap', () => {
	test('opens and creates the private_watches table on first use', () => {
		const rows = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
		const names = rows.map((r) => r.name);
		expect(names).toContain('private_watches');
	});

	test('migrates an existing pre-credit-meter DB without throwing', () => {
		// Reproduce the production failure mode: a DB file whose
		// `private_watches` table predates the credit-meter columns
		// MUST still open cleanly. The bug was that the credit index
		// inside WATCH_DDL referenced credit_atomic before the
		// migration step ALTER TABLEd the column in.
		const tmp = `${tmpdir()}/viewkey-watch-legacy-${randomUUID()}.db`;
		// Seed an on-disk DB with the OLD schema (no credit columns,
		// no last_delivered_event, no credit index).
		const legacy = new Database(tmp);
		legacy.exec(`
			CREATE TABLE private_watches (
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
				nfpt_job_id TEXT,
				nfpt_job_token TEXT,
				nfpt_job_started_at_ms INTEGER,
				last_known_balance TEXT,
				last_delivered_balance TEXT,
				last_polled_at_ms INTEGER,
				last_delivered_at_ms INTEGER,
				delivery_attempts INTEGER DEFAULT 0,
				delivery_count INTEGER DEFAULT 0,
				last_delivery_error TEXT,
				dead INTEGER DEFAULT 0,
				cancelled INTEGER DEFAULT 0
			);
		`);
		legacy.close();
		// Now re-open with openWatchDb — this is what production does
		// on systemctl restart. Before the fix this threw "no such
		// column: credit_atomic". After the fix it must add the
		// columns and the index in the right order.
		let migrated;
		expect(() => { migrated = openWatchDb(tmp); }).not.toThrow();
		const cols = migrated.prepare("PRAGMA table_info(private_watches)").all().map((c) => c.name);
		expect(cols).toContain('credit_atomic');
		expect(cols).toContain('credit_topups_atomic');
		expect(cols).toContain('credit_billed_atomic');
		expect(cols).toContain('credit_last_billed_ms');
		expect(cols).toContain('low_credit_warned');
		expect(cols).toContain('last_delivered_event');
		const idx = migrated.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_watch_credit'").get();
		expect(idx).toBeTruthy();
		migrated.close();
		unlinkSync(tmp);
	});
});

describe('createWatch', () => {
	test('returns id + token + expiresAt', () => {
		const created = makeWatch();
		expect(created.id).toMatch(/^[0-9a-f-]{36}$/u);
		expect(created.token.length).toBeGreaterThan(20);
		expect(created.expiresAt).toBe(NOW + 7 * DAY_MS);
		expect(created.createdAt).toBe(NOW);
	});

	test('stores token only as sha256 hash', () => {
		const created = makeWatch();
		const row = db.prepare('SELECT token_hash FROM private_watches WHERE id = ?').get(created.id);
		expect(row.token_hash).toMatch(/^[0-9a-f]{64}$/u);
		expect(row.token_hash).not.toContain(created.token);
	});

	test('rejects unsupported chains', () => {
		expect(() => makeWatch({ chain: 'btc' })).toThrow(/must be 'monero' or 'zcash'/);
	});

	test('rejects missing fields', () => {
		expect(() => createWatch(db, { chain: 'monero' })).toThrow(/address required/);
	});

	test('rejects non-positive credit', () => {
		expect(() => makeWatch({ creditAtomic: 0 })).toThrow(/positive integer/);
	});

	test('rejects non-positive dayRateAtomic', () => {
		expect(() => makeWatch({ dayRateAtomic: 0 })).toThrow(/positive integer/);
	});

	test('seeds credit + topups + last-billed timestamp', () => {
		const c = makeWatch();
		const row = db.prepare('SELECT credit_atomic, credit_topups_atomic, credit_last_billed_ms FROM private_watches WHERE id = ?').get(c.id);
		expect(row.credit_atomic).toBe(SEVEN_DAY_CREDIT_ATOMIC);
		expect(row.credit_topups_atomic).toBe(SEVEN_DAY_CREDIT_ATOMIC);
		expect(row.credit_last_billed_ms).toBe(NOW);
	});
});

describe('getWatch + token check', () => {
	test('returns row on correct token', () => {
		const c = makeWatch();
		const row = getWatch(db, c.id, c.token);
		expect(row).toBeTruthy();
		expect(row.id).toBe(c.id);
		expect(row.chain).toBe('monero');
	});

	test('returns null for unknown id', () => {
		expect(getWatch(db, 'no-such-id', 'whatever')).toBeNull();
	});

	test('returns forbidden on mismatched token', () => {
		const c = makeWatch();
		const res = getWatch(db, c.id, 'wrong-token');
		expect(res).toEqual({ error: 'forbidden' });
	});

	test('forbidden for missing token', () => {
		const c = makeWatch();
		const res = getWatch(db, c.id, undefined);
		expect(res).toEqual({ error: 'forbidden' });
	});
});

describe('cancelWatch', () => {
	test('marks the row cancelled', () => {
		const c = makeWatch();
		expect(cancelWatch(db, c.id, c.token)).toBe(true);
		const row = getWatch(db, c.id, c.token);
		expect(row.cancelled).toBe(1);
	});

	test('returns false on wrong token', () => {
		const c = makeWatch();
		expect(cancelWatch(db, c.id, 'bad')).toBe(false);
	});

	test('returns false on unknown id', () => {
		expect(cancelWatch(db, 'nope', 'x')).toBe(false);
	});
});

describe('listActiveWatches', () => {
	test('excludes cancelled and dead watches', () => {
		const a = makeWatch();
		const b = makeWatch();
		cancelWatch(db, a.id, a.token);
		updateWatchState(db, b.id, { dead: 1 });
		const c = makeWatch();
		const active = listActiveWatches(db, { nowMs: NOW + 1000 });
		const ids = active.map((r) => r.id);
		expect(ids).toEqual([c.id]);
	});

	test('excludes expired watches', () => {
		// Tiny credit → expires after sub-second.
		const c = makeWatch({ creditAtomic: 1 });
		const active = listActiveWatches(db, { nowMs: NOW + 10_000 });
		expect(active.map((r) => r.id)).not.toContain(c.id);
	});

	test('excludes watches whose credit dropped to zero', () => {
		const c = makeWatch();
		updateWatchState(db, c.id, { credit_atomic: 0 });
		const active = listActiveWatches(db, { nowMs: NOW + 1000 });
		expect(active.map((r) => r.id)).not.toContain(c.id);
	});

	test('orders by last_polled_at ascending (oldest first)', () => {
		const a = makeWatch();
		const b = makeWatch();
		const c = makeWatch();
		updateWatchState(db, a.id, { last_polled_at_ms: NOW + 5000 });
		updateWatchState(db, b.id, { last_polled_at_ms: NOW + 1000 });
		// c has null last_polled_at_ms -> sorts first via COALESCE(0)
		const order = listActiveWatches(db, { nowMs: NOW + 10 }).map((r) => r.id);
		expect(order).toEqual([c.id, b.id, a.id]);
	});
});

describe('updateWatchState', () => {
	test('updates whitelisted columns', () => {
		const c = makeWatch();
		const changes = updateWatchState(db, c.id, {
			last_polled_at_ms: NOW + 100,
			delivery_count: 3
		});
		expect(changes).toBe(1);
		const row = getWatch(db, c.id, c.token);
		expect(row.last_polled_at_ms).toBe(NOW + 100);
		expect(row.delivery_count).toBe(3);
	});

	test('silently drops unknown columns', () => {
		const c = makeWatch();
		const changes = updateWatchState(db, c.id, {
			evil_drop_table: 'foo',
			last_polled_at_ms: NOW + 200
		});
		expect(changes).toBe(1);
		const row = getWatch(db, c.id, c.token);
		expect(row.last_polled_at_ms).toBe(NOW + 200);
	});

	test('returns 0 when no columns match', () => {
		const c = makeWatch();
		const changes = updateWatchState(db, c.id, { definitely_not_a_col: 1 });
		expect(changes).toBe(0);
	});
});

describe('clearNfptJob', () => {
	test('nulls out job id + token', () => {
		const c = makeWatch();
		updateWatchState(db, c.id, {
			nfpt_job_id: 'jid',
			nfpt_job_token: 'tok',
			nfpt_job_started_at_ms: NOW
		});
		clearNfptJob(db, c.id);
		const row = getWatch(db, c.id, c.token);
		expect(row.nfpt_job_id).toBeNull();
		expect(row.nfpt_job_token).toBeNull();
		expect(row.nfpt_job_started_at_ms).toBeNull();
	});
});

describe('purgeExpired', () => {
	test('removes rows whose expires_at_ms is in the past', () => {
		const a = makeWatch({ creditAtomic: 1 });
		const b = makeWatch();
		const purged = purgeExpired(db, { nowMs: NOW + 100_000 });
		expect(purged).toBe(1);
		const ids = listActiveWatches(db, { nowMs: NOW + 100_000 }).map((r) => r.id);
		expect(ids).toContain(b.id);
		expect(ids).not.toContain(a.id);
	});
});

describe('statsSnapshot', () => {
	test('counts total/active/dead/chain split + credit aggregates', () => {
		const a = makeWatch();
		const b = makeWatch({ chain: 'zcash', address: 'u1abc' });
		const c = makeWatch();
		cancelWatch(db, c.id, c.token);
		updateWatchState(db, a.id, { dead: 1, delivery_count: 4 });
		updateWatchState(db, b.id, { delivery_count: 2 });
		const stats = statsSnapshot(db, { nowMs: NOW + 1000 });
		expect(stats.total).toBe(3);
		expect(stats.dead).toBe(1);
		expect(stats.by_chain.monero).toBe(2);
		expect(stats.by_chain.zcash).toBe(1);
		expect(stats.total_deliveries).toBe(6);
		// All three watches were seeded with SEVEN_DAY_CREDIT_ATOMIC.
		expect(stats.credit.balance_atomic).toBe(String(3 * SEVEN_DAY_CREDIT_ATOMIC));
		expect(stats.credit.topups_atomic).toBe(String(3 * SEVEN_DAY_CREDIT_ATOMIC));
		expect(stats.credit.billed_atomic).toBe('0');
	});
});

describe('topupWatch', () => {
	test('adds credit + pushes expires_at_ms later', () => {
		const c = makeWatch();
		const before = db.prepare('SELECT expires_at_ms FROM private_watches WHERE id = ?').get(c.id);
		const r = topupWatch(db, c.id, c.token, {
			creditAtomic: 100_000,
			dayRateAtomic: WATCH_CONSTANTS.DAY_RATE_ATOMIC,
			lowThresholdAtomic: WATCH_CONSTANTS.LOW_CREDIT_THRESHOLD_ATOMIC,
			maxLifetimeMs: WATCH_CONSTANTS.MAX_WATCH_LIFETIME_MS,
			nowMs: NOW + 1000
		});
		expect(r.ok).toBe(true);
		expect(r.row.credit_atomic).toBe(SEVEN_DAY_CREDIT_ATOMIC + 100_000);
		expect(r.row.credit_topups_atomic).toBe(SEVEN_DAY_CREDIT_ATOMIC + 100_000);
		expect(r.row.expires_at_ms).toBeGreaterThan(before.expires_at_ms);
	});

	test('forbidden on bad token', () => {
		const c = makeWatch();
		const r = topupWatch(db, c.id, 'bad', {
			creditAtomic: 100_000,
			dayRateAtomic: WATCH_CONSTANTS.DAY_RATE_ATOMIC,
			lowThresholdAtomic: WATCH_CONSTANTS.LOW_CREDIT_THRESHOLD_ATOMIC
		});
		expect(r.ok).toBe(false);
		expect(r.reason).toBe('forbidden');
	});

	test('not_found on unknown id', () => {
		const r = topupWatch(db, 'no-such-id', 'tok', {
			creditAtomic: 100_000,
			dayRateAtomic: WATCH_CONSTANTS.DAY_RATE_ATOMIC,
			lowThresholdAtomic: WATCH_CONSTANTS.LOW_CREDIT_THRESHOLD_ATOMIC
		});
		expect(r.ok).toBe(false);
		expect(r.reason).toBe('not_found');
	});

	test('cancelled watches reject top-up', () => {
		const c = makeWatch();
		cancelWatch(db, c.id, c.token);
		const r = topupWatch(db, c.id, c.token, {
			creditAtomic: 100_000,
			dayRateAtomic: WATCH_CONSTANTS.DAY_RATE_ATOMIC,
			lowThresholdAtomic: WATCH_CONSTANTS.LOW_CREDIT_THRESHOLD_ATOMIC
		});
		expect(r.ok).toBe(false);
		expect(r.reason).toBe('cancelled');
	});

	test('top-up above threshold resets low_credit_warned', () => {
		const c = makeWatch({ creditAtomic: 5_000 });
		updateWatchState(db, c.id, { low_credit_warned: 1 });
		const r = topupWatch(db, c.id, c.token, {
			creditAtomic: WATCH_CONSTANTS.TOPUP_1_ATOMIC,
			dayRateAtomic: WATCH_CONSTANTS.DAY_RATE_ATOMIC,
			lowThresholdAtomic: WATCH_CONSTANTS.LOW_CREDIT_THRESHOLD_ATOMIC
		});
		expect(r.ok).toBe(true);
		expect(r.row.low_credit_warned).toBe(0);
	});

	test('rejects non-positive credit', () => {
		const c = makeWatch();
		expect(() => topupWatch(db, c.id, c.token, {
			creditAtomic: 0,
			dayRateAtomic: WATCH_CONSTANTS.DAY_RATE_ATOMIC
		})).toThrow(/positive integer/);
	});
});
