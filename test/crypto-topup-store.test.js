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
	claimPayment,
	releasePayment,
	settlePayment,
	listPaymentsForQuote,
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
	test('returns pending (not expired) + confirming; a still-live settled quote stays matchable', () => {
		createQuote(db, baseQuote({ id: 'pending-live', expectedAtomic: 1n }));
		createQuote(db, baseQuote({ id: 'pending-dead', expectedAtomic: 2n, expiresAtMs: 500 }));
		createQuote(db, baseQuote({ id: 'confirming', expectedAtomic: 3n }));
		markSeen(db, 'confirming', { txHash: 'tx', seenAtomic: 3n, blockHeight: 10, confirmations: 1 });
		createQuote(db, baseQuote({ id: 'settled', expectedAtomic: 4n }));
		markSettled(db, 'settled', { creditedUsdCents: 500, txHash: 'tx2', seenAtomic: 4n, confirmations: 10, settledAtMs: 2_000 });
		// Settled long ago: past its deadline, so out of scope with no grace.
		createQuote(db, baseQuote({ id: 'settled-old', expectedAtomic: 5n, expiresAtMs: 500 }));
		markSettled(db, 'settled-old', { creditedUsdCents: 500, txHash: 'tx3', seenAtomic: 5n, confirmations: 10, settledAtMs: 400 });

		// A settled quote inside its window can still take another payment —
		// the per-payment table stops the first one being credited twice.
		const ids = listMatchable(db, 'monero', 600).map(r => r.id).sort();
		expect(ids).toEqual(['confirming', 'pending-live', 'settled']);
	});

	test('scopes to chain', () => {
		createQuote(db, baseQuote({ id: 'm', chain: 'monero', expectedAtomic: 1n }));
		createQuote(db, baseQuote({ id: 'z', chain: 'zcash', memo: 'SNS-1', expectedAtomic: 2n }));
		expect(listMatchable(db, 'zcash', 600).map(r => r.id)).toEqual(['z']);
	});

	test('graceMs re-admits recently-expired quotes, but not older ones', () => {
		createQuote(db, baseQuote({ id: 'just-expired', expectedAtomic: 1n, expiresAtMs: 500 }));
		createQuote(db, baseQuote({ id: 'long-expired', expectedAtomic: 2n, expiresAtMs: 100 }));
		expireStalePending(db, 600);
		expect(getQuote(db, 'just-expired').status).toBe('expired');

		// No grace (default): neither shows up.
		expect(listMatchable(db, 'monero', 600).map(r => r.id)).toEqual([]);
		// Grace window covers 500 but not 100 at now=600.
		const ids = listMatchable(db, 'monero', 600, { graceMs: 200 }).map(r => r.id);
		expect(ids).toEqual(['just-expired']);
	});
});

describe('per-payment claiming', () => {
	beforeEach(() => { createQuote(db, baseQuote({ id: 'q1' })); });

	test('a transaction can only be claimed once', () => {
		expect(claimPayment(db, 'q1', { txHash: 'tx', amountAtomic: '10', nowMs: 1 })).toEqual({ claimed: true });
		expect(claimPayment(db, 'q1', { txHash: 'tx', amountAtomic: '10', nowMs: 2 })).toMatchObject({ claimed: false, reason: 'already_claimed' });
		// ...but a different transaction on the same quote is its own payment.
		expect(claimPayment(db, 'q1', { txHash: 'tx2', amountAtomic: '10', nowMs: 3 })).toEqual({ claimed: true });
		expect(listPaymentsForQuote(db, 'q1')).toHaveLength(2);
	});

	test('a released claim can be re-claimed; a credited one cannot', () => {
		claimPayment(db, 'q1', { txHash: 'tx', amountAtomic: '10', nowMs: 1 });
		expect(releasePayment(db, 'q1', 'tx')).toEqual({ released: true });
		expect(claimPayment(db, 'q1', { txHash: 'tx', amountAtomic: '10', nowMs: 2 })).toEqual({ claimed: true });

		settlePayment(db, 'q1', { txHash: 'tx', creditedUsdCents: 500, seenAtomic: 10n, confirmations: 10, settledAtMs: 3 });
		expect(releasePayment(db, 'q1', 'tx')).toEqual({ released: false });
		expect(claimPayment(db, 'q1', { txHash: 'tx', amountAtomic: '10', nowMs: 4, staleMs: 1 })).toMatchObject({ claimed: false });
	});

	test('a stale uncredited claim is retryable, a fresh one is not', () => {
		claimPayment(db, 'q1', { txHash: 'tx', amountAtomic: '10', nowMs: 1_000 });
		expect(claimPayment(db, 'q1', { txHash: 'tx', amountAtomic: '10', nowMs: 1_500, staleMs: 1_000 })).toMatchObject({ claimed: false });
		expect(claimPayment(db, 'q1', { txHash: 'tx', amountAtomic: '10', nowMs: 5_000, staleMs: 1_000 })).toMatchObject({ claimed: true, retried: true });
	});

	test('settling rolls the quote up to the sum of its payments', () => {
		claimPayment(db, 'q1', { txHash: 'a', amountAtomic: '10', nowMs: 1 });
		settlePayment(db, 'q1', { txHash: 'a', creditedUsdCents: 500, seenAtomic: 10n, confirmations: 10, settledAtMs: 2 });
		claimPayment(db, 'q1', { txHash: 'b', amountAtomic: '5', nowMs: 3 });
		settlePayment(db, 'q1', { txHash: 'b', creditedUsdCents: 250, seenAtomic: 5n, confirmations: 10, settledAtMs: 4 });

		expect(getQuote(db, 'q1')).toMatchObject({
			status: 'settled',
			credited_usd_cents: 750,
			seen_tx_hash: 'b',
			settled_at_ms: 2 // first settlement stands as the settle time
		});
	});

	test('a payment with no tx hash is refused rather than credited blind', () => {
		expect(claimPayment(db, 'q1', { txHash: null, amountAtomic: '10' })).toEqual({ claimed: false, reason: 'no_tx_hash' });
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

	test('an expired quote can still be seen and settled (grace path)', () => {
		createQuote(db, baseQuote({ id: 'q1', expiresAtMs: 500 }));
		expireStalePending(db, 600);
		expect(getQuote(db, 'q1').status).toBe('expired');
		const seen = markSeen(db, 'q1', { txHash: 'late-tx', seenAtomic: 10_400_000_000n, blockHeight: 42, confirmations: 3 });
		expect(seen.status).toBe('confirming');
		const settled = markSettled(db, 'q1', { creditedUsdCents: 500, txHash: 'late-tx', seenAtomic: 10_400_000_000n, confirmations: 10, settledAtMs: 9_000 });
		expect(settled).toMatchObject({ status: 'settled', credited_usd_cents: 500 });
	});

	test('settled and cancelled quotes stay frozen — seen/settle no-ops', () => {
		createQuote(db, baseQuote({ id: 'c1' }));
		cancelQuote(db, 'c1', 'token-abc-12345678');
		expect(markSeen(db, 'c1', { txHash: 't', seenAtomic: 1n, blockHeight: 1, confirmations: 1 }).status).toBe('cancelled');
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
