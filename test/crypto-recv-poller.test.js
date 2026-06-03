// Tests for the privacy-coin receive-poller: pure matching/conf maths
// plus the full match -> confirm -> settle state machine driven against
// a :memory: DB with injected scan + applyCredit.

import { describe, test, expect, beforeEach } from '@jest/globals';

import {
	computeConfirmations,
	memoMatches,
	matchIncoming,
	creditCentsFor,
	runCryptoRecvTick,
	makeWatchCreditApplier,
	CENTS_TO_ATOMIC_USDC
} from '../src/crypto-recv-poller.js';
import {
	ensureCryptoTopupSchema,
	createQuote,
	getQuote
} from '../src/crypto-topup-store.js';
import { openWatchDb, createWatch, getWatchById } from '../src/private-watch-store.js';
import { WATCH_CONSTANTS } from '../src/private-watch.js';

const XMR_AMOUNT = 10_400_000_000n; // 0.0104 XMR

function quoteParams(over = {}) {
	return {
		watchId: 'w-1',
		watchToken: 'token-abc-12345678',
		chain: 'monero',
		recvAddress: '4Recv',
		quotedUsdCents: 500,
		expectedAtomic: XMR_AMOUNT,
		usdPriceMilli: 200_000,
		spreadBps: 400,
		createdAtMs: 1_000,
		// Far-future pay-by so the default Date.now() clock treats the
		// quote as live; the expiry test overrides this explicitly.
		expiresAtMs: 9_999_999_999_999,
		...over
	};
}

function spyApplyCredit(result = { ok: true }) {
	const calls = [];
	const fn = async (args) => { calls.push(args); return typeof result === 'function' ? result(args) : result; };
	fn.calls = calls;
	return fn;
}

describe('pure helpers', () => {
	test('computeConfirmations', () => {
		expect(computeConfirmations(100, 100)).toBe(1);
		expect(computeConfirmations(100, 91)).toBe(10);
		expect(computeConfirmations(100, 0)).toBe(0);
		expect(computeConfirmations(90, 100)).toBe(0); // tip behind tx (reorg/edge)
	});

	test('memoMatches', () => {
		expect(memoMatches('SNS-abc123', 'SNS-abc123')).toBe(true);
		expect(memoMatches('order SNS-abc123 thanks', 'SNS-abc123')).toBe(true);
		expect(memoMatches('SNS-other', 'SNS-abc123')).toBe(false);
		expect(memoMatches(null, 'SNS-abc123')).toBe(false);
		expect(memoMatches('SNS-abc123', null)).toBe(false);
	});

	test('matchIncoming monero by exact amount', () => {
		const q = { chain: 'monero', expected_atomic: XMR_AMOUNT.toString() };
		const inc = [{ amountAtomic: '999' }, { amountAtomic: XMR_AMOUNT.toString(), txHash: 'tx' }];
		expect(matchIncoming('monero', q, inc)).toMatchObject({ txHash: 'tx' });
		expect(matchIncoming('monero', q, [{ amountAtomic: '5' }])).toBeNull();
	});

	test('matchIncoming zcash by memo', () => {
		const q = { chain: 'zcash', memo: 'SNS-xyz' };
		const inc = [{ memo: 'nope' }, { memo: 'SNS-xyz', txHash: 'tx' }];
		expect(matchIncoming('zcash', q, inc)).toMatchObject({ txHash: 'tx' });
	});

	test('creditCentsFor full / over / under payment', () => {
		const q = { expected_atomic: XMR_AMOUNT.toString(), quoted_usd_cents: 500 };
		expect(creditCentsFor(q, { amountAtomic: XMR_AMOUNT.toString() })).toBe(500);
		expect(creditCentsFor(q, { amountAtomic: (XMR_AMOUNT * 2n).toString() })).toBe(500);
		// Half the expected amount -> half the credit.
		expect(creditCentsFor(q, { amountAtomic: (XMR_AMOUNT / 2n).toString() })).toBe(250);
	});
});

describe('runCryptoRecvTick — state machine', () => {
	let db;
	beforeEach(() => {
		db = openWatchDb(':memory:');
		ensureCryptoTopupSchema(db);
	});

	test('insufficient confirmations -> confirming, no credit', async () => {
		createQuote(db, quoteParams({ id: 'q1' }));
		const apply = spyApplyCredit();
		const scan = async () => ({ chainHeight: 100, incoming: [{ amountAtomic: XMR_AMOUNT.toString(), txHash: 'tx1', blockHeight: 96 }] });
		const summary = await runCryptoRecvTick({ db, chains: ['monero'], scan, applyCredit: apply, confirmations: { monero: 10 } });
		expect(summary.confirming).toBe(1);
		expect(summary.settled).toBe(0);
		expect(apply.calls).toHaveLength(0);
		expect(getQuote(db, 'q1')).toMatchObject({ status: 'confirming', confirmations: 5, seen_tx_hash: 'tx1' });
	});

	test('enough confirmations -> credit applied + settled', async () => {
		createQuote(db, quoteParams({ id: 'q1' }));
		const apply = spyApplyCredit({ ok: true, newBalanceAtomic: 7_000_000 });
		const scan = async () => ({ chainHeight: 100, incoming: [{ amountAtomic: XMR_AMOUNT.toString(), txHash: 'tx1', blockHeight: 91 }] });
		const summary = await runCryptoRecvTick({ db, chains: ['monero'], scan, applyCredit: apply, confirmations: { monero: 10 } });
		expect(summary.settled).toBe(1);
		expect(apply.calls[0]).toEqual({ watchId: 'w-1', usdCents: 500 });
		expect(getQuote(db, 'q1')).toMatchObject({ status: 'settled', credited_usd_cents: 500, confirmations: 10 });
	});

	test('settled quotes are not re-credited on a later tick', async () => {
		createQuote(db, quoteParams({ id: 'q1' }));
		const apply = spyApplyCredit();
		const scan = async () => ({ chainHeight: 100, incoming: [{ amountAtomic: XMR_AMOUNT.toString(), txHash: 'tx1', blockHeight: 91 }] });
		await runCryptoRecvTick({ db, chains: ['monero'], scan, applyCredit: apply, confirmations: { monero: 10 } });
		await runCryptoRecvTick({ db, chains: ['monero'], scan, applyCredit: apply, confirmations: { monero: 10 } });
		expect(apply.calls).toHaveLength(1); // not double-credited
	});

	test('zcash settles via memo match', async () => {
		createQuote(db, quoteParams({ id: 'z1', chain: 'zcash', memo: 'SNS-xyz', expectedAtomic: 2_000_000n }));
		const apply = spyApplyCredit();
		const scan = async () => ({ chainHeight: 50, incoming: [{ amountAtomic: '2000000', txHash: 'ztx', blockHeight: 43, memo: 'SNS-xyz' }] });
		const summary = await runCryptoRecvTick({ db, chains: ['zcash'], scan, applyCredit: apply, confirmations: { zcash: 8 } });
		expect(summary.settled).toBe(1);
		expect(getQuote(db, 'z1').status).toBe('settled');
	});

	test('a scan failure on one chain is isolated', async () => {
		createQuote(db, quoteParams({ id: 'q1' }));
		const apply = spyApplyCredit();
		const scan = async (chain) => { if (chain === 'monero') throw new Error('nfpt down'); return { chainHeight: 1, incoming: [] }; };
		const summary = await runCryptoRecvTick({ db, chains: ['monero', 'zcash'], scan, applyCredit: apply, confirmations: { monero: 10, zcash: 8 } });
		expect(summary.errors).toBe(1);
		expect(getQuote(db, 'q1').status).toBe('pending'); // untouched
	});

	test('confirmed payment but failed credit is recorded, not settled', async () => {
		createQuote(db, quoteParams({ id: 'q1' }));
		const apply = spyApplyCredit({ ok: false, reason: 'cancelled' });
		const scan = async () => ({ chainHeight: 100, incoming: [{ amountAtomic: XMR_AMOUNT.toString(), txHash: 'tx1', blockHeight: 91 }] });
		const summary = await runCryptoRecvTick({ db, chains: ['monero'], scan, applyCredit: apply, confirmations: { monero: 10 } });
		expect(summary.settled).toBe(0);
		expect(summary.errors).toBe(1);
		expect(getQuote(db, 'q1').status).toBe('confirming');
	});

	test('stale pending quotes are expired', async () => {
		createQuote(db, quoteParams({ id: 'q1', expiresAtMs: 500 }));
		const apply = spyApplyCredit();
		const scan = async () => ({ chainHeight: 100, incoming: [] });
		const summary = await runCryptoRecvTick({ db, chains: ['monero'], scan, applyCredit: apply, confirmations: { monero: 10 }, now: () => 10_000 });
		expect(summary.expired).toBe(1);
		expect(getQuote(db, 'q1').status).toBe('expired');
	});
});

describe('makeWatchCreditApplier', () => {
	let db;
	beforeEach(() => {
		db = openWatchDb(':memory:');
		ensureCryptoTopupSchema(db);
	});

	function seedWatch() {
		return createWatch(db, {
			chain: 'monero',
			address: '4Addr',
			viewKeyCiphertext: 'ct',
			webhookUrl: 'https://example.com/hook',
			webhookSecret: 'secret',
			creditAtomic: 100_000,
			dayRateAtomic: WATCH_CONSTANTS.DAY_RATE_ATOMIC,
			nowMs: 1_000
		});
	}

	test('credits a real watch by USD cents at the locked rate', () => {
		const { id } = seedWatch();
		const apply = makeWatchCreditApplier(db);
		const before = getWatchById(db, id).credit_atomic;
		const res = apply({ watchId: id, usdCents: 200 });
		expect(res.ok).toBe(true);
		expect(res.creditAtomicApplied).toBe(200 * CENTS_TO_ATOMIC_USDC); // $2.00 = 2_000_000 atomic
		expect(getWatchById(db, id).credit_atomic).toBe(before + 2_000_000);
	});

	test('rejects unknown watch + bad amounts', () => {
		const apply = makeWatchCreditApplier(db);
		expect(apply({ watchId: 'nope', usdCents: 200 })).toEqual({ ok: false, reason: 'not_found' });
		expect(apply({ watchId: 'nope', usdCents: 0 })).toEqual({ ok: false, reason: 'invalid_amount' });
	});
});
