// USD price oracle + USD↔coin atomic conversion for privacy-coin
// credit top-ups.
//
// We price top-ups in USD (the credit meter is denominated in atomic
// USDC) but accept payment in Monero or Zcash, so we need a spot
// XMR/USD and ZEC/USD rate at quote time. The default source is
// CoinGecko's keyless `simple/price` endpoint; results are cached and
// an optional hard fallback covers a brief outage.
//
// Everything here is dependency-injected (fetchImpl, clock) so the
// unit tests never touch the network and the maths is verified in
// isolation.

/**
 * Atomic units per whole coin. Monero = piconero (1e12), Zcash =
 * zatoshi (1e8), Dash = duffs (1e8 — shielded top-ups arrive on the
 * Platform Orchard pool but the unit is the same).
 */
export const COIN_DECIMALS = Object.freeze({ monero: 12, zcash: 8, dash: 8 });

/** CoinGecko `ids` for each chain we support. */
export const COIN_IDS = Object.freeze({ monero: 'monero', zcash: 'zcash', dash: 'dash' });

/** Basis-points denominator — 10_000 bps = 100%. */
const BPS = 10_000n;

function assertCoin(coin) {
	if (!Object.hasOwn(COIN_DECIMALS, coin)) {
		throw new TypeError(`crypto-price: coin must be one of ${Object.keys(COIN_DECIMALS).join('/')}, got ${coin}`);
	}
}

/**
 * Required coin amount (in atomic units, as a BigInt) to buy
 * `usdCents` of credit at `usdPrice` USD/coin, after adding a spread.
 *
 * The spread protects us against the rate moving against us during the
 * quote window. We always round the coin amount UP (ceil) so a payer
 * can never under-fund the quoted USD value by a rounding sliver.
 *
 *   atomic = ceil( (usdCents/100) / usdPrice * (1 + spreadBps/1e4) * 10^decimals )
 *
 * `usdCents` is a positive integer; `usdPrice` a positive finite
 * number (USD per 1 whole coin); `spreadBps` a non-negative integer.
 */
export function usdCentsToCoinAtomic(usdCents, usdPrice, coin, spreadBps = 0) {
	assertCoin(coin);
	if (!Number.isInteger(usdCents) || usdCents <= 0) {
		throw new TypeError('usdCentsToCoinAtomic: usdCents must be a positive integer');
	}
	if (typeof usdPrice !== 'number' || !Number.isFinite(usdPrice) || usdPrice <= 0) {
		throw new TypeError('usdCentsToCoinAtomic: usdPrice must be a positive finite number');
	}
	if (!Number.isInteger(spreadBps) || spreadBps < 0) {
		throw new TypeError('usdCentsToCoinAtomic: spreadBps must be a non-negative integer');
	}
	const decimals = COIN_DECIMALS[coin];
	const usd = usdCents / 100;
	const withSpread = (usd / usdPrice) * (1 + spreadBps / 10_000);
	const atomicFloat = withSpread * 10 ** decimals;
	if (!Number.isFinite(atomicFloat) || atomicFloat <= 0) {
		throw new Error(`usdCentsToCoinAtomic: non-finite result (usdCents=${usdCents}, usdPrice=${usdPrice})`);
	}
	// ceil via Math.ceil is safe: the largest sensible top-up
	// (~$500 of XMR at $50 ≈ 1e13 piconero) is well under 2^53.
	return BigInt(Math.ceil(atomicFloat));
}

/**
 * Reverse: how many whole USD cents is `atomic` coin worth at
 * `usdPrice`? Rounded DOWN so we never over-credit on a partial /
 * over-payment. Returns a non-negative integer (cents).
 */
export function coinAtomicToUsdCents(atomic, usdPrice, coin) {
	assertCoin(coin);
	const a = typeof atomic === 'bigint' ? atomic : BigInt(atomic);
	if (a < 0n) throw new TypeError('coinAtomicToUsdCents: atomic must be >= 0');
	if (typeof usdPrice !== 'number' || !Number.isFinite(usdPrice) || usdPrice <= 0) {
		throw new TypeError('coinAtomicToUsdCents: usdPrice must be a positive finite number');
	}
	const decimals = COIN_DECIMALS[coin];
	const whole = Number(a) / 10 ** decimals;
	return Math.floor(whole * usdPrice * 100);
}

/** Format an atomic coin amount as a human decimal string (no rounding). */
export function formatCoinAmount(atomic, coin) {
	assertCoin(coin);
	const a = typeof atomic === 'bigint' ? atomic : BigInt(atomic);
	const decimals = COIN_DECIMALS[coin];
	const base = 10n ** BigInt(decimals);
	const whole = a / base;
	const frac = a % base;
	const fracStr = frac.toString().padStart(decimals, '0').replace(/0+$/u, '');
	return fracStr.length ? `${whole}.${fracStr}` : `${whole}`;
}

/**
 * Create a cached USD price oracle.
 *
 *   getUsdPrice(coin) -> { usd, source: 'coingecko'|'fallback', asOfMs }
 *
 * One network call fetches both coins; the result is cached for
 * `cacheTtlMs`. On failure we fall back to `fallback[coin]` (whole USD)
 * if it's > 0, otherwise we throw so a caller never quotes on a guess.
 */
export function createPriceOracle({
	url = 'https://api.coingecko.com/api/v3/simple/price',
	timeoutMs = 5_000,
	cacheTtlMs = 60_000,
	fetchImpl = globalThis.fetch,
	fallback = { monero: 0, zcash: 0, dash: 0 },
	now = () => Date.now()
} = {}) {
	if (typeof fetchImpl !== 'function') {
		throw new TypeError('createPriceOracle: fetchImpl must be a function');
	}
	let cache = null; // { [coin]: usd, asOfMs }

	async function refresh() {
		const ids = Object.values(COIN_IDS).join(',');
		const full = `${url}?ids=${encodeURIComponent(ids)}&vs_currencies=usd`;
		const ac = new AbortController();
		const t = setTimeout(() => ac.abort(new Error('crypto-price: request timed out')), timeoutMs);
		try {
			const res = await fetchImpl(full, { signal: ac.signal, headers: { accept: 'application/json' } });
			if (!res.ok) throw new Error(`crypto-price: oracle HTTP ${res.status}`);
			const body = await res.json();
			// Per-coin tolerance: cache every usable price and let
			// getUsdPrice decide per coin — one missing id must not take
			// pricing down for the chains that DID come back.
			const fresh = { asOfMs: now() };
			let usable = 0;
			for (const [coin, id] of Object.entries(COIN_IDS)) {
				const usd = Number(body?.[id]?.usd);
				if (Number.isFinite(usd) && usd > 0) {
					fresh[coin] = usd;
					usable += 1;
				}
			}
			if (usable === 0) {
				throw new Error(`crypto-price: oracle returned no usable prices (${JSON.stringify(body)})`);
			}
			cache = fresh;
			return cache;
		}
		finally {
			clearTimeout(t);
		}
	}

	const hasPrice = (obj, coin) => Number.isFinite(obj?.[coin]) && obj[coin] > 0;

	async function getUsdPrice(coin) {
		assertCoin(coin);
		if (cache && (now() - cache.asOfMs) < cacheTtlMs && hasPrice(cache, coin)) {
			return { usd: cache[coin], source: 'coingecko', asOfMs: cache.asOfMs };
		}
		let lastErr = null;
		try {
			const fresh = await refresh();
			if (hasPrice(fresh, coin)) {
				return { usd: fresh[coin], source: 'coingecko', asOfMs: fresh.asOfMs };
			}
			lastErr = new Error(`crypto-price: oracle returned no usable ${coin} price`);
		}
		catch (err) {
			lastErr = err;
		}
		// Serve a still-warm cache even if slightly stale before
		// resorting to the hard fallback.
		if (cache && hasPrice(cache, coin)) {
			return { usd: cache[coin], source: 'coingecko-stale', asOfMs: cache.asOfMs };
		}
		const fb = Number(fallback?.[coin] ?? 0);
		if (Number.isFinite(fb) && fb > 0) {
			return { usd: fb, source: 'fallback', asOfMs: now() };
		}
		throw new Error(`crypto-price: no price for ${coin} and no fallback configured (${lastErr?.message ?? lastErr})`);
	}

	return Object.freeze({ getUsdPrice });
}
