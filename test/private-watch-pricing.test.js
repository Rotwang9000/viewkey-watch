// Tests for the active-load surge pricing engine.
// Pure math + a couple of integration smoke tests that exercise
// `effectiveRatesForRow` against a real DB row.

import { describe, test, expect, beforeEach } from '@jest/globals';

import {
	PRICING_DEFAULTS,
	computeWatchRate,
	atomicToUsdString,
	buildPricingConfig,
	effectiveDayRate,
	effectiveCallRate,
	describeCurrentPricing
} from '../src/private-watch-pricing.js';
import { effectiveRatesForRow, WATCH_CONSTANTS } from '../src/private-watch.js';
import { openWatchDb, createWatch } from '../src/private-watch-store.js';

describe('computeWatchRate — surge formula', () => {
	test('zero active watches → base rate, source=base', () => {
		const r = computeWatchRate({ activeWatches: 0 });
		expect(r.dayRateAtomic).toBe(PRICING_DEFAULTS.BASE_DAY_RATE_ATOMIC);
		expect(r.callRateAtomic).toBe(PRICING_DEFAULTS.BASE_CALL_RATE_ATOMIC);
		expect(r.source).toBe('base');
		expect(r.factor).toBe(1);
	});

	test('linear increase with active watches (rate = base * (1 + n/100))', () => {
		// 100 active watches doubles the rate.
		const r = computeWatchRate({ activeWatches: 100 });
		expect(r.dayRateAtomic).toBe(40_000);  // 20_000 * 2
		expect(r.callRateAtomic).toBe(10_000); // 5_000 * 2
		expect(r.source).toBe('surge');
		expect(r.factor).toBeCloseTo(2, 6);
	});

	test('caps at MAX_DAY_RATE_ATOMIC', () => {
		// 1150 active watches would be 12.5x = $0.25/day, exactly
		// the cap. 2000 active watches should also cap.
		const atCap = computeWatchRate({ activeWatches: 1150 });
		const wayPast = computeWatchRate({ activeWatches: 2000 });
		expect(atCap.dayRateAtomic).toBe(PRICING_DEFAULTS.MAX_DAY_RATE_ATOMIC);
		expect(atCap.callRateAtomic).toBe(PRICING_DEFAULTS.MAX_CALL_RATE_ATOMIC);
		expect(atCap.source).toBe('cap');
		expect(wayPast.dayRateAtomic).toBe(PRICING_DEFAULTS.MAX_DAY_RATE_ATOMIC);
		expect(wayPast.source).toBe('cap');
	});

	test('low-credit threshold scales with the day rate (12-day window)', () => {
		const r1 = computeWatchRate({ activeWatches: 0 });
		expect(r1.lowCreditThresholdAtomic).toBe(20_000 * 12);
		const r2 = computeWatchRate({ activeWatches: 100 });
		expect(r2.lowCreditThresholdAtomic).toBe(40_000 * 12);
	});

	test('preserves the 4:1 day-to-call ratio across the curve', () => {
		for (const n of [0, 25, 50, 100, 250, 1000]) {
			const r = computeWatchRate({ activeWatches: n });
			// Allow rounding slack of 1 atomic unit either way.
			expect(Math.abs(r.dayRateAtomic - 4 * r.callRateAtomic)).toBeLessThanOrEqual(4);
		}
	});

	test('throws on bad inputs', () => {
		expect(() => computeWatchRate({ activeWatches: -1 })).toThrow();
		expect(() => computeWatchRate({ activeWatches: 1.5 })).toThrow();
		expect(() => computeWatchRate({ activeWatches: 'one' })).toThrow();
		expect(() => computeWatchRate({ activeWatches: 0, base: 0 })).toThrow();
		expect(() => computeWatchRate({ activeWatches: 0, max: 10, base: 100 })).toThrow();
		expect(() => computeWatchRate({ activeWatches: 0, divisor: 0 })).toThrow();
	});
});

describe('atomicToUsdString', () => {
	test('handles whole + fractional cents', () => {
		expect(atomicToUsdString(0)).toBe('$0.00');
		expect(atomicToUsdString(10_000)).toBe('$0.01');
		expect(atomicToUsdString(20_000)).toBe('$0.02');
		expect(atomicToUsdString(100_000)).toBe('$0.10');
		expect(atomicToUsdString(1_000_000)).toBe('$1.00');
		expect(atomicToUsdString(1_234_567)).toBe('$1.234567');
		expect(atomicToUsdString(250_000)).toBe('$0.25');
	});

	test('accepts strings and bigints', () => {
		expect(atomicToUsdString('100000')).toBe('$0.10');
		expect(atomicToUsdString(100_000n)).toBe('$0.10');
	});
});

describe('buildPricingConfig', () => {
	test('returns defaults when cfg is empty', () => {
		const p = buildPricingConfig({});
		expect(p.base).toBe(PRICING_DEFAULTS.BASE_DAY_RATE_ATOMIC);
		expect(p.callBase).toBe(PRICING_DEFAULTS.BASE_CALL_RATE_ATOMIC);
		expect(p.max).toBe(PRICING_DEFAULTS.MAX_DAY_RATE_ATOMIC);
		expect(p.divisor).toBe(PRICING_DEFAULTS.SURGE_DIVISOR);
		expect(p.lowCreditRatio).toBe(PRICING_DEFAULTS.LOW_CREDIT_RATIO);
	});

	test('honours operator overrides', () => {
		const p = buildPricingConfig({
			privateWatchBaseDayRateAtomic: 50_000,
			privateWatchMaxDayRateAtomic: 500_000,
			privateWatchSurgeDivisor: 50
		});
		expect(p.base).toBe(50_000);
		expect(p.max).toBe(500_000);
		expect(p.divisor).toBe(50);
	});

	test('rejects invalid overrides', () => {
		expect(() => buildPricingConfig({ privateWatchBaseDayRateAtomic: -1 })).toThrow();
		expect(() => buildPricingConfig({ privateWatchSurgeDivisor: 0 })).toThrow();
		expect(() => buildPricingConfig({ privateWatchMaxDayRateAtomic: 'high' })).toThrow();
	});
});

describe('effectiveDayRate / effectiveCallRate', () => {
	test('uses the stored value when present', () => {
		expect(effectiveDayRate({ day_rate_atomic: 42_000 }, 20_000)).toBe(42_000);
		expect(effectiveCallRate({ call_rate_atomic: 10_500 }, 5_000)).toBe(10_500);
	});

	test('falls back when the column is NULL / 0 / missing', () => {
		expect(effectiveDayRate({}, 20_000)).toBe(20_000);
		expect(effectiveDayRate({ day_rate_atomic: null }, 20_000)).toBe(20_000);
		expect(effectiveDayRate({ day_rate_atomic: 0 }, 20_000)).toBe(20_000);
		expect(effectiveCallRate(null, 5_000)).toBe(5_000);
	});
});

describe('effectiveRatesForRow', () => {
	test('returns stored rates for a surge-priced row', () => {
		const row = {
			day_rate_atomic: 80_000,
			call_rate_atomic: 20_000,
			low_credit_threshold_atomic: 960_000
		};
		const r = effectiveRatesForRow(row);
		expect(r.dayRateAtomic).toBe(80_000);
		expect(r.callRateAtomic).toBe(20_000);
		expect(r.lowCreditThresholdAtomic).toBe(960_000);
	});

	test('falls back to constants for a legacy row', () => {
		const r = effectiveRatesForRow({});
		expect(r.dayRateAtomic).toBe(WATCH_CONSTANTS.DAY_RATE_ATOMIC);
		expect(r.callRateAtomic).toBe(WATCH_CONSTANTS.CALL_RATE_ATOMIC);
		// Threshold falls back to the legacy global constant so
		// pre-surge starter-credit values don't suddenly trip
		// low-credit warnings on legacy rows.
		expect(r.lowCreditThresholdAtomic).toBe(WATCH_CONSTANTS.LOW_CREDIT_THRESHOLD_ATOMIC);
	});

	test('uses the stored threshold when present', () => {
		const r = effectiveRatesForRow({ day_rate_atomic: 50_000, low_credit_threshold_atomic: 600_000 });
		expect(r.lowCreditThresholdAtomic).toBe(600_000);
	});
});

describe('describeCurrentPricing', () => {
	test('emits a public block with current + base + max rates', () => {
		const pricing = buildPricingConfig({});
		const block = describeCurrentPricing({ pricing, activeWatches: 50 });
		expect(block.base_day_rate_atomic).toBe('20000');
		expect(block.base_day_rate_usd).toBe('$0.02');
		expect(block.max_day_rate_usd).toBe('$0.25');
		expect(block.current_day_rate_atomic).toBe('30000');
		expect(block.current_day_rate_usd).toBe('$0.03');
		expect(block.current_factor).toBe(1.5);
		expect(block.current_tier).toBe('surge');
		expect(block.surge_divisor).toBe(100);
		expect(block.active_watches).toBe(50);
		expect(block.formula).toMatch(/activeWatches \/ 100/);
	});

	test('reports tier=cap at saturation', () => {
		const pricing = buildPricingConfig({});
		const block = describeCurrentPricing({ pricing, activeWatches: 2000 });
		expect(block.current_tier).toBe('cap');
		expect(block.current_day_rate_usd).toBe('$0.25');
	});
});

describe('createWatch persists the surge fields', () => {
	let db;
	beforeEach(() => { db = openWatchDb(':memory:'); });

	test('writes day_rate_atomic + call_rate_atomic + threshold to the row', () => {
		const created = createWatch(db, {
			chain: 'monero',
			address: '4'.repeat(95),
			viewKeyCiphertext: 'ct',
			webhookUrl: 'https://example.com/hook',
			webhookSecret: 'sec'.repeat(20),
			creditAtomic: 100_000,
			dayRateAtomic: 60_000,
			callRateAtomic: 15_000,
			lowCreditThresholdAtomic: 720_000,
			maxLifetimeMs: 7 * 86_400_000,
			nowMs: 1_700_000_000_000
		});
		const row = db.prepare('SELECT day_rate_atomic, call_rate_atomic, low_credit_threshold_atomic FROM private_watches WHERE id = ?').get(created.id);
		expect(row.day_rate_atomic).toBe(60_000);
		expect(row.call_rate_atomic).toBe(15_000);
		expect(row.low_credit_threshold_atomic).toBe(720_000);
		// Effective rates should now match the stored values.
		const eff = effectiveRatesForRow(row);
		expect(eff.dayRateAtomic).toBe(60_000);
		expect(eff.callRateAtomic).toBe(15_000);
		expect(eff.lowCreditThresholdAtomic).toBe(720_000);
	});

	test('legacy callers (no callRateAtomic, no threshold) still work', () => {
		const created = createWatch(db, {
			chain: 'zcash',
			address: 'u1' + 'q'.repeat(100),
			viewKeyCiphertext: 'ct',
			webhookUrl: 'https://example.com/hook',
			webhookSecret: 'sec'.repeat(20),
			creditAtomic: 100_000,
			dayRateAtomic: 20_000,
			maxLifetimeMs: 7 * 86_400_000,
			nowMs: 1_700_000_000_000
		});
		const row = db.prepare('SELECT day_rate_atomic, call_rate_atomic, low_credit_threshold_atomic FROM private_watches WHERE id = ?').get(created.id);
		expect(row.day_rate_atomic).toBe(20_000);
		expect(row.call_rate_atomic).toBeNull();
		expect(row.low_credit_threshold_atomic).toBeNull();
		// effectiveRatesForRow should fill the gaps from the
		// hard-coded constants. Legacy rows fall back to the
		// global LOW_CREDIT_THRESHOLD_ATOMIC so a $0.10 starter
		// doesn't trip an immediate low-credit warning.
		const eff = effectiveRatesForRow(row);
		expect(eff.callRateAtomic).toBe(WATCH_CONSTANTS.CALL_RATE_ATOMIC);
		expect(eff.lowCreditThresholdAtomic).toBe(WATCH_CONSTANTS.LOW_CREDIT_THRESHOLD_ATOMIC);
	});
});
