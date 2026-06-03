// Tests for the privacy-coin price oracle + USD↔coin atomic maths.
// The oracle is exercised with a stubbed fetch so no network is hit.

import { describe, test, expect } from '@jest/globals';

import {
	COIN_DECIMALS,
	usdCentsToCoinAtomic,
	coinAtomicToUsdCents,
	formatCoinAmount,
	createPriceOracle
} from '../src/crypto-price.js';

describe('usdCentsToCoinAtomic', () => {
	test('converts USD cents to piconero at a flat price', () => {
		// $2.00 at $200/XMR = 0.01 XMR = 1e10 piconero
		expect(usdCentsToCoinAtomic(200, 200, 'monero', 0)).toBe(10_000_000_000n);
	});

	test('applies the spread and rounds up', () => {
		// 0.01 XMR * 1.04 = 0.0104 XMR ≈ 1.04e10 piconero. Allow the
		// ceil to land a sliver above the float ideal (still negligible:
		// 1 piconero ≈ $1.5e-10) — what matters is it never rounds down.
		const got = usdCentsToCoinAtomic(200, 200, 'monero', 400);
		expect(got).toBeGreaterThanOrEqual(10_400_000_000n);
		expect(got).toBeLessThanOrEqual(10_400_000_002n);
	});

	test('converts USD cents to zatoshi (8 decimals)', () => {
		// $1.00 at $50/ZEC = 0.02 ZEC = 2e6 zatoshi
		expect(usdCentsToCoinAtomic(100, 50, 'zcash', 0)).toBe(2_000_000n);
	});

	test('always rounds the coin amount up (never under-funds)', () => {
		// A price that yields a fractional atomic unit must ceil.
		const atomic = usdCentsToCoinAtomic(101, 333.33, 'monero', 0);
		const asNumber = Number(atomic);
		const exact = (1.01 / 333.33) * 10 ** COIN_DECIMALS.monero;
		expect(asNumber).toBeGreaterThanOrEqual(Math.floor(exact));
		expect(asNumber).toBe(Math.ceil(exact));
	});

	test('rejects bad inputs', () => {
		expect(() => usdCentsToCoinAtomic(0, 200, 'monero')).toThrow(/positive integer/);
		expect(() => usdCentsToCoinAtomic(200, 0, 'monero')).toThrow(/positive finite/);
		expect(() => usdCentsToCoinAtomic(200, 200, 'dogecoin')).toThrow(/monero.*zcash/);
		expect(() => usdCentsToCoinAtomic(200, 200, 'monero', -1)).toThrow(/non-negative/);
	});
});

describe('coinAtomicToUsdCents', () => {
	test('round-trips a clean conversion', () => {
		expect(coinAtomicToUsdCents(10_000_000_000n, 200, 'monero')).toBe(200);
		expect(coinAtomicToUsdCents(2_000_000n, 50, 'zcash')).toBe(100);
	});

	test('floors partial value (never over-credits)', () => {
		// Slightly less than 0.01 XMR should floor below $2.00.
		expect(coinAtomicToUsdCents(9_999_999_999n, 200, 'monero')).toBe(199);
	});
});

describe('formatCoinAmount', () => {
	test('renders piconero as a trimmed decimal', () => {
		expect(formatCoinAmount(10_400_000_000n, 'monero')).toBe('0.0104');
		expect(formatCoinAmount(1_500_000_000_000n, 'monero')).toBe('1.5');
		expect(formatCoinAmount(2_000_000n, 'zcash')).toBe('0.02');
	});

	test('renders whole amounts with no point', () => {
		expect(formatCoinAmount(3_000_000_000_000n, 'monero')).toBe('3');
	});
});

function jsonResponse(body, { ok = true, status = 200 } = {}) {
	return { ok, status, json: async () => body };
}

describe('createPriceOracle', () => {
	const goodBody = { monero: { usd: 150.5 }, zcash: { usd: 28.25 } };

	test('returns live prices from the oracle', async () => {
		const oracle = createPriceOracle({ fetchImpl: async () => jsonResponse(goodBody) });
		const xmr = await oracle.getUsdPrice('monero');
		expect(xmr).toMatchObject({ usd: 150.5, source: 'coingecko' });
		const zec = await oracle.getUsdPrice('zcash');
		expect(zec.usd).toBe(28.25);
	});

	test('caches within the TTL (one fetch for both coins)', async () => {
		let calls = 0;
		const oracle = createPriceOracle({
			cacheTtlMs: 60_000,
			fetchImpl: async () => { calls += 1; return jsonResponse(goodBody); }
		});
		await oracle.getUsdPrice('monero');
		await oracle.getUsdPrice('zcash');
		await oracle.getUsdPrice('monero');
		expect(calls).toBe(1);
	});

	test('serves a stale cache before falling back', async () => {
		let calls = 0;
		let t = 1_000;
		const oracle = createPriceOracle({
			cacheTtlMs: 100,
			now: () => t,
			fetchImpl: async () => {
				calls += 1;
				if (calls === 1) return jsonResponse(goodBody);
				throw new Error('oracle down');
			}
		});
		const first = await oracle.getUsdPrice('monero');
		expect(first.source).toBe('coingecko');
		t += 10_000; // blow past the TTL so a refresh is attempted
		const second = await oracle.getUsdPrice('monero');
		expect(second).toMatchObject({ usd: 150.5, source: 'coingecko-stale' });
	});

	test('falls back to a configured price when oracle is cold + down', async () => {
		const oracle = createPriceOracle({
			fallback: { monero: 140, zcash: 26 },
			fetchImpl: async () => { throw new Error('oracle down'); }
		});
		const xmr = await oracle.getUsdPrice('monero');
		expect(xmr).toMatchObject({ usd: 140, source: 'fallback' });
	});

	test('throws when oracle down and no fallback', async () => {
		const oracle = createPriceOracle({
			fallback: { monero: 0, zcash: 0 },
			fetchImpl: async () => { throw new Error('oracle down'); }
		});
		await expect(oracle.getUsdPrice('monero')).rejects.toThrow(/no price.*no fallback/);
	});

	test('rejects an oracle payload with no usable prices', async () => {
		const oracle = createPriceOracle({
			fetchImpl: async () => jsonResponse({ monero: {}, zcash: {} })
		});
		await expect(oracle.getUsdPrice('monero')).rejects.toThrow(/no price.*no fallback|no usable/);
	});
});
