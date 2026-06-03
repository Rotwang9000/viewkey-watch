// Active-load surge pricing for Private Watch.
//
// Per-day idle and per-call delivery rates are no longer a flat
// constant — they scale up with the number of currently active
// watches so early adopters get the cheap rate and later users
// pay a fair share. The rate is locked in at watch-creation time
// and stored on the watch row, so a customer never sees their
// running cost climb retroactively (the existing
// `private_watches.day_rate_atomic` + `call_rate_atomic` columns,
// added by the migration in private-watch-store.js, persist it).
//
// Formula:
//
//   factor = 1 + activeWatches / SURGE_DIVISOR     (linear)
//   factor = min(factor, MAX_FACTOR)                (cap so the
//                                                    top tier is
//                                                    a known
//                                                    number)
//   dayRateAtomic  = round(BASE_DAY_RATE  * factor)
//   callRateAtomic = round(BASE_CALL_RATE * factor)
//
// Where BASE_DAY_RATE = 20_000 (= $0.02) and SURGE_DIVISOR = 100.
// The 4:1 day-to-call ratio is preserved by applying the same
// factor to both rates.
//
// Why "active watches" specifically?
//   * Total-watches-ever-created climbs forever and would punish
//     people for our churn (good problem to have, bad pricing
//     signal). Active is what actually consumes the resources.
//   * Active is a single SELECT-COUNT-WHERE-cancelled=0-AND-dead=0
//     against a column already indexed for the poller.
//   * It's monotone-with-load: more active customers ⇒ more rate;
//     when watches expire the rate floats back down for the next
//     newcomer (existing watches keep their locked rate).
//
// Why linear?
//   * Easy to explain on the docs page: "rate goes up 1% for each
//     active watch; capped at the documented top".
//   * Not surprising in the small (one customer doesn't suddenly
//     pay 10x because of a noisy neighbour).

const ATOMIC_TO_USD = 1_000_000n;

/**
 * Hard, code-pinned defaults so the surge engine is fully
 * deterministic without env config. Each operator-tunable value
 * also reads from `cfg`/`env` so a misconfiguration doesn't
 * suddenly bill everyone $25/day by accident.
 */
export const PRICING_DEFAULTS = Object.freeze({
	BASE_DAY_RATE_ATOMIC:  20_000,   // $0.02 / UTC day, the entry tier
	BASE_CALL_RATE_ATOMIC:  5_000,   // $0.005 / webhook, the entry tier
	MAX_DAY_RATE_ATOMIC:  250_000,   // $0.25 / day — the documented cap
	MAX_CALL_RATE_ATOMIC:  62_500,   // $0.0625 / webhook — same 4:1 ratio
	SURGE_DIVISOR: 100,              // 1 active watch ⇒ +1% rate
	LOW_CREDIT_RATIO: 12             // low-credit threshold = 12 * dayRate (~12 days)
});

/**
 * Pure: pick the per-watch rates a brand-new watch should be
 * billed at, given the snapshot of currently-active watches. The
 * caller is responsible for taking that snapshot at the moment
 * of creation — it can come from the store's `statsSnapshot()`,
 * a cheap SELECT, or a stubbed integer in tests.
 *
 * Returns `{ dayRateAtomic, callRateAtomic, factor,
 * activeWatches, lowCreditThresholdAtomic, source }`.
 *
 * Source is one of:
 *   "base"  — below the surge floor, default tier
 *   "surge" — between floor and cap, factor > 1
 *   "cap"   — factor saturated at MAX_FACTOR
 */
export function computeWatchRate({
	activeWatches = 0,
	base = PRICING_DEFAULTS.BASE_DAY_RATE_ATOMIC,
	callBase = PRICING_DEFAULTS.BASE_CALL_RATE_ATOMIC,
	max = PRICING_DEFAULTS.MAX_DAY_RATE_ATOMIC,
	callMax = PRICING_DEFAULTS.MAX_CALL_RATE_ATOMIC,
	divisor = PRICING_DEFAULTS.SURGE_DIVISOR,
	lowCreditRatio = PRICING_DEFAULTS.LOW_CREDIT_RATIO
} = {}) {
	if (!Number.isInteger(activeWatches) || activeWatches < 0) {
		throw new TypeError(`computeWatchRate: activeWatches must be a non-negative integer (got ${activeWatches})`);
	}
	if (!Number.isInteger(base) || base <= 0) throw new TypeError('base day-rate must be a positive integer');
	if (!Number.isInteger(callBase) || callBase <= 0) throw new TypeError('base call-rate must be a positive integer');
	if (!Number.isInteger(max) || max < base) throw new TypeError('max day-rate must be ≥ base');
	if (!Number.isInteger(callMax) || callMax < callBase) throw new TypeError('max call-rate must be ≥ call-base');
	if (!Number.isInteger(divisor) || divisor <= 0) throw new TypeError('surge divisor must be positive');

	const factor = 1 + (activeWatches / divisor);
	let dayRateAtomic = Math.round(base * factor);
	let callRateAtomic = Math.round(callBase * factor);
	let source = 'base';
	if (activeWatches > 0) source = 'surge';
	if (dayRateAtomic >= max || callRateAtomic >= callMax) {
		dayRateAtomic = max;
		callRateAtomic = callMax;
		source = 'cap';
	}
	const lowCreditThresholdAtomic = dayRateAtomic * lowCreditRatio;
	return Object.freeze({
		dayRateAtomic,
		callRateAtomic,
		factor: source === 'cap' ? max / base : factor,
		activeWatches,
		lowCreditThresholdAtomic,
		source
	});
}

/**
 * Cheap conversion for use in docs / API responses — `atomic` is
 * either a number or a string of digits.
 */
export function atomicToUsdString(atomic) {
	const big = typeof atomic === 'bigint' ? atomic : BigInt(atomic ?? 0);
	const whole = big / ATOMIC_TO_USD;
	const fraction = big % ATOMIC_TO_USD;
	const fracStr = fraction.toString().padStart(6, '0').replace(/0+$/, '') || '0';
	return `$${whole}.${fracStr.padEnd(2, '0')}`;
}

/**
 * Operator-tunable pricing config. Reads from `cfg` (the
 * `config.js` snapshot) so env overrides land without code
 * changes, and falls back to the defaults above. Use this from
 * rest-server.js when sizing a new watch.
 */
export function buildPricingConfig(cfg = {}) {
	const pick = (cfgKey, dflt) => {
		const v = cfg[cfgKey];
		if (v == null) return dflt;
		const n = typeof v === 'number' ? v : parseInt(String(v), 10);
		if (!Number.isFinite(n) || !Number.isInteger(n) || n <= 0) {
			throw new TypeError(`pricing config: ${cfgKey} must be a positive integer (got ${v})`);
		}
		return n;
	};
	return Object.freeze({
		base:           pick('privateWatchBaseDayRateAtomic',  PRICING_DEFAULTS.BASE_DAY_RATE_ATOMIC),
		callBase:       pick('privateWatchBaseCallRateAtomic', PRICING_DEFAULTS.BASE_CALL_RATE_ATOMIC),
		max:            pick('privateWatchMaxDayRateAtomic',   PRICING_DEFAULTS.MAX_DAY_RATE_ATOMIC),
		callMax:        pick('privateWatchMaxCallRateAtomic',  PRICING_DEFAULTS.MAX_CALL_RATE_ATOMIC),
		divisor:        pick('privateWatchSurgeDivisor',       PRICING_DEFAULTS.SURGE_DIVISOR),
		lowCreditRatio: pick('privateWatchLowCreditRatio',     PRICING_DEFAULTS.LOW_CREDIT_RATIO)
	});
}

/**
 * Convenience: read the stored rate off a watch row, falling
 * back to the operator's current base rate if the column is
 * NULL (pre-surge rows). Keeps the meter math working for legacy
 * watches without re-pricing them retroactively.
 */
export function effectiveDayRate(row, fallback) {
	const stored = Number(row?.day_rate_atomic ?? 0);
	if (Number.isFinite(stored) && stored > 0) return stored;
	return fallback;
}
export function effectiveCallRate(row, fallback) {
	const stored = Number(row?.call_rate_atomic ?? 0);
	if (Number.isFinite(stored) && stored > 0) return stored;
	return fallback;
}

/**
 * Public describe-block emitted by `/v1/private/info` and the
 * stats overview so clients can preview what their next watch
 * would cost without having to pay first.
 */
export function describeCurrentPricing({ pricing, activeWatches }) {
	const rate = computeWatchRate({ ...pricing, activeWatches });
	return {
		base_day_rate_atomic:    String(pricing.base),
		base_day_rate_usd:       atomicToUsdString(pricing.base),
		base_call_rate_atomic:   String(pricing.callBase),
		base_call_rate_usd:      atomicToUsdString(pricing.callBase),
		max_day_rate_atomic:     String(pricing.max),
		max_day_rate_usd:        atomicToUsdString(pricing.max),
		max_call_rate_atomic:    String(pricing.callMax),
		max_call_rate_usd:       atomicToUsdString(pricing.callMax),
		surge_divisor:           pricing.divisor,
		active_watches:          activeWatches,
		current_day_rate_atomic:  String(rate.dayRateAtomic),
		current_day_rate_usd:     atomicToUsdString(rate.dayRateAtomic),
		current_call_rate_atomic: String(rate.callRateAtomic),
		current_call_rate_usd:    atomicToUsdString(rate.callRateAtomic),
		current_factor:          Number(rate.factor.toFixed(3)),
		current_tier:            rate.source,
		formula:                 `dayRate = base * (1 + activeWatches / ${pricing.divisor}), capped at ${atomicToUsdString(pricing.max)}/day`,
		notes:                   'Your watch locks in the rate that was in effect at creation time and keeps that rate for its lifetime. Existing watches do not re-price when the global surge climbs.'
	};
}
