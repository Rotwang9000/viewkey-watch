// Receive-poller for privacy-coin credit top-ups.
//
// Runs on a timer (scripts/crypto-recv-poller.mjs) and, on each tick,
// scans OUR receiving wallet through NFPT, matches incoming payments to
// open quotes, counts confirmations, and — once a payment is buried
// deep enough — credits the watch at the quote's locked rate.
//
// The tick itself is dependency-injected: `scan(chain)` and
// `applyCredit({watchId, usdCents})` are passed in, so the unit tests
// exercise the full match→confirm→settle state machine against a
// :memory: DB with zero network and zero NFPT.

import {
	listMatchable,
	markSeen,
	markSettled,
	expireStalePending
} from './crypto-topup-store.js';
import { getWatchById, topupWatchById } from './private-watch-store.js';
import { WATCH_CONSTANTS, effectiveRatesForRow } from './private-watch.js';

/** Atomic USDC units per US cent (USDC has 6 decimals: $0.01 = 10_000). */
export const CENTS_TO_ATOMIC_USDC = 10_000;

function safeBig(v) {
	try { return BigInt(v); }
	catch { return null; }
}

/** Confirmations of a tx at `blockHeight` given the chain tip `chainHeight`. */
export function computeConfirmations(chainHeight, blockHeight) {
	const ch = Number(chainHeight);
	const bh = Number(blockHeight);
	if (!Number.isFinite(ch) || !Number.isFinite(bh) || bh <= 0 || ch < bh) return 0;
	return ch - bh + 1;
}

/** A Zcash/Dash note memo attributes to a quote when it equals (or contains) the token. */
export function memoMatches(noteMemo, quoteMemo) {
	if (!noteMemo || !quoteMemo) return false;
	const a = String(noteMemo).trim();
	const b = String(quoteMemo).trim();
	return a === b || a.includes(b);
}

/**
 * Find the incoming payment that satisfies a quote:
 *   - Monero: exact atomic-amount match (the quote amount carries
 *     random low digits so it's unique among open quotes).
 *   - Zcash/Dash: memo-token match (amount is validated at credit
 *     time; Dash's 36-byte Platform memo fits the token fine).
 * Returns the payment record or null.
 */
export function matchIncoming(chain, quote, incoming) {
	if (!Array.isArray(incoming)) return null;
	if (chain === 'monero') {
		const want = safeBig(quote.expected_atomic);
		if (want === null) return null;
		return incoming.find((p) => safeBig(p.amountAtomic) === want) ?? null;
	}
	return incoming.find((p) => memoMatches(p.memo, quote.memo)) ?? null;
}

/**
 * Cents to credit for a matched payment. A full / over-payment credits
 * the quoted amount; a Zcash under-payment (memo matched, sent less)
 * credits pro-rata at the locked rate the quote already embeds
 * (quoted_usd_cents per expected_atomic). Pure integer maths.
 */
export function creditCentsFor(quote, payment) {
	const expected = safeBig(quote.expected_atomic);
	const received = safeBig(payment.amountAtomic);
	const quoted = BigInt(quote.quoted_usd_cents);
	if (expected === null || received === null || expected <= 0n) return Number(quoted);
	if (received >= expected) return Number(quoted);
	return Number((quoted * received) / expected);
}

/**
 * One poller pass. Returns a summary object for logging/metrics.
 *
 * deps:
 *   - db            shared watch DB handle (quotes + watches live here)
 *   - chains        e.g. ['monero','zcash'] — only configured chains
 *   - scan(chain)   async -> { chainHeight, incoming: [...] }
 *   - applyCredit({watchId, usdCents}) -> { ok, ... } | { ok:false, reason }
 *   - confirmations { monero: 10, zcash: 8 }
 *   - matchGraceMs  how long after a quote's pay-by deadline a matching
 *                   payment can still settle it (default 0 = never).
 *                   Memo/amount matching makes late settling safe; the
 *                   deadline only bounds the *rate lock*, not honesty.
 *   - now()         clock (testable)
 *   - logger        pino-like (info/warn/error)
 */
export async function runCryptoRecvTick({
	db,
	chains,
	scan,
	applyCredit,
	confirmations = {},
	matchGraceMs = 0,
	now = () => Date.now(),
	logger = { info() {}, warn() {}, error() {} }
}) {
	if (!db) throw new TypeError('runCryptoRecvTick: db is required');
	if (typeof scan !== 'function') throw new TypeError('runCryptoRecvTick: scan(chain) must be a function');
	if (typeof applyCredit !== 'function') throw new TypeError('runCryptoRecvTick: applyCredit() must be a function');

	const chainList = Array.isArray(chains) ? chains : [];
	const summary = { settled: 0, confirming: 0, matched: 0, expired: 0, errors: 0, byChain: {} };

	for (const chain of chainList) {
		const cs = { scanned: 0, matched: 0, settled: 0, confirming: 0, errors: 0 };
		let scanResult;
		try {
			scanResult = await scan(chain);
		}
		catch (err) {
			cs.errors += 1; summary.errors += 1;
			logger.warn({ chain, err: err?.message ?? String(err) }, 'crypto-recv: scan failed');
			summary.byChain[chain] = cs;
			continue;
		}
		const incoming = Array.isArray(scanResult?.incoming) ? scanResult.incoming : [];
		const chainHeight = scanResult?.chainHeight ?? 0;
		const required = Number(confirmations?.[chain] ?? 0);
		cs.scanned = incoming.length;

		for (const quote of listMatchable(db, chain, now(), { graceMs: matchGraceMs })) {
			const payment = matchIncoming(chain, quote, incoming);
			if (!payment) continue;
			cs.matched += 1; summary.matched += 1;

			const confs = computeConfirmations(chainHeight, payment.blockHeight);
			if (confs < required) {
				markSeen(db, quote.id, {
					txHash: payment.txHash,
					seenAtomic: payment.amountAtomic,
					blockHeight: payment.blockHeight,
					confirmations: confs
				});
				cs.confirming += 1; summary.confirming += 1;
				continue;
			}

			const usdCents = creditCentsFor(quote, payment);
			if (usdCents <= 0) {
				logger.warn({ quoteId: quote.id }, 'crypto-recv: computed non-positive credit; skipping');
				continue;
			}

			let res;
			// quoteId lets the applier dispatch on the EXACT quote that was
			// paid — amount-based dispatch confuses two same-priced products
			// (e.g. a $5 scan top-up vs a $5 one-day feature).
			try { res = await applyCredit({ watchId: quote.watch_id, usdCents, quoteId: quote.id }); }
			catch (err) { res = { ok: false, reason: err?.message ?? String(err) }; }

			if (res?.ok) {
				markSettled(db, quote.id, {
					creditedUsdCents: usdCents,
					txHash: payment.txHash,
					seenAtomic: payment.amountAtomic,
					confirmations: confs,
					settledAtMs: now()
				});
				cs.settled += 1; summary.settled += 1;
				logger.info({ quoteId: quote.id, watchId: quote.watch_id, chain, usdCents, txHash: payment.txHash }, 'crypto-recv: top-up settled');
			}
			else {
				// Confirmed on-chain but the credit didn't land (watch
				// cancelled or gone). Record the sighting and shout —
				// never mark settled, so we don't lie about credit.
				markSeen(db, quote.id, {
					txHash: payment.txHash,
					seenAtomic: payment.amountAtomic,
					blockHeight: payment.blockHeight,
					confirmations: confs
				});
				cs.errors += 1; summary.errors += 1;
				logger.error({ quoteId: quote.id, watchId: quote.watch_id, reason: res?.reason, txHash: payment.txHash, usdCents }, 'crypto-recv: confirmed payment but credit failed — reconcile manually');
			}
		}
		summary.byChain[chain] = cs;
	}

	try { summary.expired = expireStalePending(db, now()); }
	catch (err) { logger.warn({ err: err?.message ?? String(err) }, 'crypto-recv: expire sweep failed'); }

	return summary;
}

/**
 * Production credit applier: looks up the watch's locked-in surge rate
 * then applies the credit token-lessly. Returned closure is what the
 * poller script passes as `applyCredit`.
 */
export function makeWatchCreditApplier(watchDb) {
	if (!watchDb) throw new TypeError('makeWatchCreditApplier: watchDb required');
	return ({ watchId, usdCents }) => {
		if (!Number.isInteger(usdCents) || usdCents <= 0) return { ok: false, reason: 'invalid_amount' };
		const row = getWatchById(watchDb, watchId);
		if (!row) return { ok: false, reason: 'not_found' };
		const rates = effectiveRatesForRow(row);
		const creditAtomic = usdCents * CENTS_TO_ATOMIC_USDC;
		const out = topupWatchById(watchDb, watchId, {
			creditAtomic,
			dayRateAtomic: rates.dayRateAtomic,
			lowThresholdAtomic: rates.lowCreditThresholdAtomic,
			maxLifetimeMs: WATCH_CONSTANTS.MAX_WATCH_LIFETIME_MS
		});
		return out.ok
			? { ok: true, newBalanceAtomic: out.row.credit_atomic, creditAtomicApplied: creditAtomic }
			: { ok: false, reason: out.reason };
	};
}
