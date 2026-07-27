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
	claimPayment,
	releasePayment,
	settlePayment,
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
	return matchIncomingAll(chain, quote, incoming)[0] ?? null;
}

/**
 * Every incoming payment attributable to a quote, not just the first.
 * A memo is not a single-use token: people pay in instalments, re-send
 * after a wallet error, or simply pay the same quote twice. Each such
 * payment is money we received and each earns its own credit.
 */
export function matchIncomingAll(chain, quote, incoming) {
	if (!Array.isArray(incoming)) return [];
	if (chain === 'monero') {
		const want = safeBig(quote.expected_atomic);
		if (want === null) return [];
		return incoming.filter((p) => safeBig(p.amountAtomic) === want);
	}
	return incoming.filter((p) => memoMatches(p.memo, quote.memo));
}

/**
 * How far under the quoted amount still counts as paying it in full.
 * The rate moves between quoting and sending, and wallets round: someone
 * who typed the amount off a slightly stale quote has paid it, and
 * shaving a few cents off their credit for that would be mean.
 */
export const CREDIT_TOLERANCE_BPS = 200; // 2%

/**
 * How long a claimed-but-uncredited payment stays untouchable. Only a
 * crash between claiming and crediting leaves one behind (a failed credit
 * releases its own claim), and after this it is safe to retry.
 */
export const CLAIM_STALE_MS = 10 * 60 * 1000;

/**
 * Cents to credit for a matched payment: whatever was actually sent,
 * valued at the rate the quote locked in (quoted_usd_cents per
 * expected_atomic). Under-payments credit pro-rata and over-payments
 * credit the excess too — the quote picks the price, the payer picks
 * the size. Keeping the change for an over-payment would be theft, and
 * a quote is a price, not an invoice. Within CREDIT_TOLERANCE_BPS of the
 * quoted amount it rounds up to the full quote. Pure integer maths
 * (truncating, so rounding is otherwise in the house's favour by at most
 * one cent).
 */
export function creditCentsFor(quote, payment) {
	const expected = safeBig(quote.expected_atomic);
	const received = safeBig(payment.amountAtomic);
	const quoted = BigInt(quote.quoted_usd_cents);
	if (expected === null || received === null || expected <= 0n) return Number(quoted);
	if (received >= (expected * BigInt(10_000 - CREDIT_TOLERANCE_BPS)) / 10_000n && received < expected) {
		return Number(quoted);
	}
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
			// Every payment carrying this memo, not just the first: a memo is
			// reusable, so instalments and repeat payments each earn credit.
			for (const payment of matchIncomingAll(chain, quote, incoming)) {
				const confs = computeConfirmations(chainHeight, payment.blockHeight);
				if (confs < required) {
					markSeen(db, quote.id, {
						txHash: payment.txHash,
						seenAtomic: payment.amountAtomic,
						blockHeight: payment.blockHeight,
						confirmations: confs
					});
					cs.matched += 1; summary.matched += 1;
					cs.confirming += 1; summary.confirming += 1;
					continue;
				}

				// Claim before crediting: the (quote, tx) primary key is what
				// stops a re-scan — or a payment we already credited on an
				// earlier tick — from being paid out twice.
				const claim = claimPayment(db, quote.id, {
					txHash: payment.txHash,
					amountAtomic: payment.amountAtomic,
					blockHeight: payment.blockHeight,
					confirmations: confs,
					nowMs: now(),
					staleMs: CLAIM_STALE_MS
				});
				if (!claim.claimed) {
					if (claim.reason === 'no_tx_hash') {
						cs.errors += 1; summary.errors += 1;
						logger.error({ quoteId: quote.id, chain }, 'crypto-recv: confirmed payment has no tx hash — cannot credit safely');
					}
					continue; // already credited (or another worker has it)
				}
				cs.matched += 1; summary.matched += 1;

				const usdCents = creditCentsFor(quote, payment);
				if (usdCents <= 0) {
					releasePayment(db, quote.id, payment.txHash);
					logger.warn({ quoteId: quote.id, txHash: payment.txHash }, 'crypto-recv: computed non-positive credit; skipping');
					continue;
				}

				let res;
				// quoteId lets the applier dispatch on the EXACT quote that was
				// paid — amount-based dispatch confuses two same-priced products
				// (e.g. a $5 scan top-up vs a $5 one-day feature).
				try { res = await applyCredit({ watchId: quote.watch_id, usdCents, quoteId: quote.id }); }
				catch (err) { res = { ok: false, reason: err?.message ?? String(err) }; }

				if (res?.ok) {
					settlePayment(db, quote.id, {
						txHash: payment.txHash,
						creditedUsdCents: usdCents,
						seenAtomic: payment.amountAtomic,
						confirmations: confs,
						settledAtMs: now()
					});
					cs.settled += 1; summary.settled += 1;
					logger.info({ quoteId: quote.id, watchId: quote.watch_id, chain, usdCents, txHash: payment.txHash }, 'crypto-recv: top-up settled');
				}
				else {
					// Confirmed on-chain but the credit didn't land (watch
					// cancelled or gone). Drop the claim so a later tick can
					// retry, record the sighting, and shout — never settle,
					// so we don't lie about credit.
					releasePayment(db, quote.id, payment.txHash);
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
