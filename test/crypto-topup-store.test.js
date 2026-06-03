// Tests for the privacy-coin top-up quote store against a :memory: DB.

import { describe, test, expect, beforeEach } from '@jest/globals';
import Database from 'better-sqlite3';

import {
	ensureCryptoTopupSchema,
	createQuote,
	getQuote,
	getQuoteAuthorised,
	listMatchable,
	hasOpenQuoteWithAmount,
	markSeen,
	markSettled,
	expireStalePending,
	cancelQuote,
	quoteStatsSnapshot
} from '../src/crypto-topup-store.js';

let db;

function baseQuote(over = {}) {
	return {
		watchId: 'w-1',
		watchToken: 'token-abc-12345678',
		chain: 'monero',
		recvAddress: '4Address',
		quotedUsdCents: 500,
		expectedAtomic: 10_400_000_000n,
		usdPriceMilli: 200_000,
		spreadBps: 400,
		createdAtMs: 1_000,
		expiresAtMs: 901_000,
		...over
	};
}

beforeEach(() => {
	db = new Database(':memory:');
	ensureCryptoTopupSchema(db);
});

describe('createQuote / getQuote', () => {
	test('inserts a pending quote and stores only the token hash', () => {
		const row = createQuote(db, baseQuote({ id: 'q1' }));
		expect(row).toMatchObject({
			id: 'q1', watch_id: 'w-1', chain: 'monero', status: 'pending',
			quoted_usd_cents: 500, expected_atomic: '10400000000'
		});
		expect(row.watch_token_hash).toMatch(/^[0-9a-f]{64}$/);
		expect(row.watch_token_hash).not.toContain('token-abc');
	});

	test('rejects bad chain / amounts', () => {
		expect(() => createQuote(db, baseQuote({ chain: 'doge' }))).toThrow(/monero.*zcash/);
		expect(() => createQuote(db, baseQuote({ expectedAtomic: 0n }))).toThrow(/positive BigInt/);
		expect(() => createQuote(db, baseQuote({ quotedUsdCents: 0 }))).toThrow(/positive integer/);
	});
});

describe('getQuoteAuthorised', () => {
	test('enforces the watch token (constant-time)', () => {
		createQuote(db, baseQuote({ id: 'q1' }));
		expect(getQuoteAuthorised(db, 'q1', 'token-abc-12345678')).toMatchObject({ id: 'q1' });
		expect(getQuoteAuthorised(db, 'q1', 'wrong-token-xxxxxx')).toEqual({ error: 'forbidden' });
		expect(getQuoteAuthorised(db, 'nope', 'token-abc-12345678')).toEqual({ error: 'not_found' });
	});
});

describe('listMatchable', () => {
	test('returns pending (not expired) + confirming, excludes expired/settled', () => {
		createQuote(db, baseQuote({ id: 'pending-live', expectedAtomic: 1n }));
		createQuote(db, baseQuote({ id: 'pending-dead', expectedAtomic: 2n, expiresAtMs: 500 }));
		createQuote(db, baseQuote({ id: 'confirming', expectedAtomic: 3n }));
		markSeen(db, 'confirming', { txHash: 'tx', seenAtomic: 3n, blockHeight: 10, confirmations: 1 });
		createQuote(db, baseQuote({ id: 'settled', expectedAtomic: 4n }));
		markSettled(db, 'settled', { creditedUsdCents: 500, txHash: 'tx2', seenAtomic: 4n, confirmations: 10, settledAtMs: 2_000 });

		const ids = listMatchable(db, 'monero', 600).map(r => r.id).sort();
		expect(ids).toEqual(['confirming', 'pending-live']);
	});

	test('scopes to chain', () => {
		createQuote(db, baseQuote({ id: 'm', chain: 'monero', expectedAtomic: 1n }));
		createQuote(db, baseQuote({ id: 'z', chain: 'zcash', memo: 'SNS-1', expectedAtomic: 2n }));
		expect(listMatchable(db, 'zcash', 600).map(r => r.id)).toEqual(['z']);
	});
});

describe('hasOpenQuoteWithAmount', () => {
	test('detects an outstanding amount collision on the same chain', () => {
		createQuote(db, baseQuote({ id: 'q1', expectedAtomic: 12345n }));
		expect(hasOpenQuoteWithAmount(db, 'monero', 12345n)).toBe(true);
		expect(hasOpenQuoteWithAmount(db, 'monero', 999n)).toBe(false);
		expect(hasOpenQuoteWithAmount(db, 'zcash', 12345n)).toBe(false);
	});

	test('a settled quote no longer collides', () => {
		createQuote(db, baseQuote({ id: 'q1', expectedAtomic: 12345n }));
		markSettled(db, 'q1', { creditedUsdCents: 500, txHash: 't', seenAtomic: 12345n, confirmations: 10, settledAtMs: 5 });
		expect(hasOpenQuoteWithAmount(db, 'monero', 12345n)).toBe(false);
	});
});

describe('markSeen / markSettled', () => {
	test('seen moves pending -> confirming with detail', () => {
		createQuote(db, baseQuote({ id: 'q1' }));
		const row = markSeen(db, 'q1', { txHash: 'deadbeef', seenAtomic: 10_400_000_005n, blockHeight: 3_300_000, confirmations: 4 });
		expect(row).toMatchObject({ status: 'confirming', seen_tx_hash: 'deadbeef', seen_atomic: '10400000005', confirmations: 4 });
	});

	test('settled records credited cents and freezes status', () => {
		createQuote(db, baseQuote({ id: 'q1' }));
		markSeen(db, 'q1', { txHash: 'tx', seenAtomic: 10_400_000_000n, blockHeight: 1, confirmations: 2 });
		const row = markSettled(db, 'q1', { creditedUsdCents: 500, txHash: 'tx', seenAtomic: 10_400_000_000n, confirmations: 10, settledAtMs: 9_000 });
		expect(row).toMatchObject({ status: 'settled', credited_usd_cents: 500, settled_at_ms: 9_000 });
		// A second settle is a no-op (status no longer in pending/confirming).
		const again = markSettled(db, 'q1', { creditedUsdCents: 999, confirmations: 11, settledAtMs: 10_000 });
		expect(again.credited_usd_cents).toBe(500);
	});
});

describe('expireStalePending / cancelQuote', () => {
	test('expireStalePending flips only overdue pending rows', () => {
		createQuote(db, baseQuote({ id: 'live', expiresAtMs: 10_000 }));
		createQuote(db, baseQuote({ id: 'dead', expectedAtomic: 2n, expiresAtMs: 500 }));
		expect(expireStalePending(db, 1_000)).toBe(1);
		expect(getQuote(db, 'dead').status).toBe('expired');
		expect(getQuote(db, 'live').status).toBe('pending');
	});

	test('cancelQuote requires the token and only cancels pending', () => {
		createQuote(db, baseQuote({ id: 'q1' }));
		expect(cancelQuote(db, 'q1', 'wrong')).toBe(false);
		expect(cancelQuote(db, 'q1', 'token-abc-12345678')).toBe(true);
		expect(getQuote(db, 'q1').status).toBe('cancelled');
	});
});

describe('quoteStatsSnapshot', () => {
	test('counts by status and sums settled credit', () => {
		createQuote(db, baseQuote({ id: 'p' }));
		createQuote(db, baseQuote({ id: 's', expectedAtomic: 2n }));
		markSettled(db, 's', { creditedUsdCents: 500, txHash: 't', seenAtomic: 2n, confirmations: 10, settledAtMs: 1 });
		const snap = quoteStatsSnapshot(db);
		expect(snap).toMatchObject({ pending: 1, settled: 1, settled_usd_cents: 500 });
	});
});
