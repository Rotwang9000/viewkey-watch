// Private-watch poller: one tick walks every active watch, pulls the
// latest balance from NFPT, and ships a signed webhook on change.
//
// The module exports `runPollerTick(deps)` so a systemd timer or a
// long-running loop can drive it. Everything dependency-injectable
// (DB handle, NFPT client, fetch impl, master key) lives in `deps`
// so the unit tests can wire a `:memory:` DB plus stubs in ~10 LoC.
//
// State machine per watch (rough sketch):
//
//   - First tick: NFPT job missing -> start one, store {jobId, jobToken}
//   - Subsequent: GET the existing job, normalise the balance
//   - If NFPT returns 404 -> job aged out (1 h TTL upstream), clear + restart next tick
//   - If balance differs from `last_delivered_balance` -> sign + POST webhook
//     - Success: update `last_delivered_balance`, reset attempts
//     - Failure: bump attempts, leave for next cycle (next webhook delivery
//       happens 1 poll interval later — built-in 3-min backoff)
//     - After MAX_DELIVERY_ATTEMPTS consecutive failures: mark dead
//   - Always update last_polled_at_ms + last_known_balance
//
// Side-effecty bits (HTTP + DB writes) are kept in the dispatch
// functions; the diff/sign/payload helpers in private-watch.js stay
// pure and easily testable.

import {
	decryptViewKey,
	signWebhookBody
} from './private-watch-crypto.js';
import {
	startMoneroJob,
	pollMoneroJob,
	startOrchardJob,
	pollOrchardJob
} from './private-watch-nfpt.js';
import {
	listActiveWatches,
	updateWatchState,
	clearNfptJob,
	purgeExpired
} from './private-watch-store.js';
import {
	diffBalance,
	buildWebhookBody,
	buildLowCreditBody,
	applyDayCharge,
	applyCallCharge,
	effectiveRatesForRow,
	WATCH_CONSTANTS
} from './private-watch.js';

const DEFAULT_WEBHOOK_TIMEOUT_MS = 8_000;
const MAX_LOG_REASON_LEN = 200;
// Outbound webhook header namespace + UA. Overridable per-call on
// deliverWebhook so an operator can brand the headers; kept vendor-
// neutral by default. Suffixes are `-signature`, `-watch-id`, `-event`.
const DEFAULT_WEBHOOK_HEADER_PREFIX = 'x-viewkey';
const DEFAULT_WEBHOOK_USER_AGENT = 'viewkey-watch/0.1.0';
// Max bytes we'll buffer from a misbehaving receiver before
// abandoning the read. 4 KB is enough for any reasonable status
// payload, and tiny enough that a hostile responder can't tie up the
// poller with a slow-loris megabyte.
const DEFAULT_RESPONSE_MAX_BYTES = WATCH_CONSTANTS.WEBHOOK_RESPONSE_MAX_BYTES;

/**
 * Run a single poller tick. Returns a summary object so the CLI
 * driver / tests can assert on what happened.
 *
 * Required deps:
 *   - db: better-sqlite3 handle to the watch DB
 *   - masterKey: Buffer(32) for decrypting view keys
 *   - nfptClient: from createNfptClient()
 * Optional deps:
 *   - fetchImpl: defaults to globalThis.fetch (used for webhook POST)
 *   - webhookTimeoutMs
 *   - logger: { info, warn, error } (default console)
 *   - now: () => ms (defaults Date.now)
 */
export async function runPollerTick(deps) {
	const {
		db,
		masterKey,
		nfptClient,
		fetchImpl = globalThis.fetch,
		webhookTimeoutMs = DEFAULT_WEBHOOK_TIMEOUT_MS,
		responseMaxBytes = DEFAULT_RESPONSE_MAX_BYTES,
		logger = console,
		now = () => Date.now()
	} = deps;
	if (!db) throw new TypeError('runPollerTick: db is required');
	if (!Buffer.isBuffer(masterKey)) throw new TypeError('runPollerTick: masterKey must be a Buffer');
	if (!nfptClient) throw new TypeError('runPollerTick: nfptClient is required');
	if (typeof fetchImpl !== 'function') throw new TypeError('runPollerTick: fetchImpl must be a function');

	const startMs = now();
	const summary = {
		started_at_ms: startMs,
		watches_seen: 0,
		watches_polled: 0,
		watches_dead: 0,
		watches_out_of_credit: 0,
		jobs_started: 0,
		webhooks_attempted: 0,
		webhooks_delivered: 0,
		webhooks_failed: 0,
		low_credit_warnings: 0,
		credit_billed_atomic: 0,
		watches_skipped: 0,
		errors: []
	};
	const active = listActiveWatches(db, { nowMs: startMs });
	summary.watches_seen = active.length;
	for (const row of active) {
		try {
			await pollOne({
				row, db, masterKey, nfptClient,
				fetchImpl, webhookTimeoutMs, responseMaxBytes,
				logger, now, summary
			});
		}
		catch (err) {
			summary.errors.push({
				watchId: row.id,
				message: truncate(err?.message ?? String(err))
			});
			logger.warn?.({
				watchId: row.id,
				err: err?.message ?? String(err)
			}, 'private-watch: tick error');
		}
	}
	summary.expired_purged = purgeExpired(db, { nowMs: startMs });
	summary.elapsed_ms = now() - startMs;
	return summary;
}

async function pollOne({ row, db, masterKey, nfptClient, fetchImpl, webhookTimeoutMs, responseMaxBytes, logger, now, summary }) {
	const tickStartMs = now();

	// Surge pricing: the meter math reads the locked-in rate from
	// the row (falling back to the constant for legacy rows that
	// pre-date the schema migration). Compute once per tick — used
	// by step (1), (2) and (4).
	const rates = effectiveRatesForRow(row);

	// 1) Per-day billing. Always applied first so the credit block
	//    we emit later reflects the live meter. The patch may charge
	//    zero atomic units if not enough time has elapsed since the
	//    last bill — in that case we leave the row untouched.
	const dayPatch = applyDayCharge(row, tickStartMs, { dayRateAtomic: rates.dayRateAtomic });
	if (dayPatch.chargeAtomic > 0) {
		updateWatchState(db, row.id, {
			credit_atomic: dayPatch.credit_atomic,
			credit_billed_atomic: dayPatch.credit_billed_atomic,
			credit_last_billed_ms: dayPatch.credit_last_billed_ms,
			expires_at_ms: dayPatch.expires_at_ms
		});
		// Reflect the charge on the in-memory row so subsequent
		// steps (low-credit check, webhook body) see fresh values.
		row.credit_atomic = dayPatch.credit_atomic;
		row.credit_billed_atomic = dayPatch.credit_billed_atomic;
		row.credit_last_billed_ms = dayPatch.credit_last_billed_ms;
		row.expires_at_ms = dayPatch.expires_at_ms;
		summary.credit_billed_atomic += dayPatch.chargeAtomic;
	}

	// 2) Low-credit warning. One-shot: we fire exactly once per
	//    threshold-crossing. Top-ups reset `low_credit_warned` so a
	//    user who tops up and then runs down again gets a fresh
	//    warning. Deliberately not charged as a regular call — this
	//    is a service-driven courtesy notification.
	if (Number(row.credit_atomic ?? 0) <= rates.lowCreditThresholdAtomic
		&& Number(row.low_credit_warned ?? 0) === 0
		&& Number(row.credit_atomic ?? 0) > 0) {
		const fired = await maybeFireLowCredit({
			row, db, fetchImpl, webhookTimeoutMs, responseMaxBytes,
			nowMs: tickStartMs, logger
		});
		if (fired) {
			summary.low_credit_warnings += 1;
			row.low_credit_warned = 1;
		}
	}

	// 3) If we've run out of credit (day-charge took us to zero), skip
	//    the NFPT poll. The watch will not appear in listActiveWatches
	//    on the next tick until the receiver tops up.
	if (Number(row.credit_atomic ?? 0) <= 0) {
		summary.watches_out_of_credit += 1;
		updateWatchState(db, row.id, { last_polled_at_ms: tickStartMs });
		return;
	}

	const viewKey = decryptViewKey(row.view_key_ct, masterKey);
	let jobId = row.nfpt_job_id;
	let jobToken = row.nfpt_job_token;
	let snapshot = null;
	let needsNewJob = !jobId || !jobToken;

	// Try the existing job first (cheap GET). If NFPT lost it (404
	// because the API restarted, or 5 min idle window), fall through
	// to start a fresh one.
	if (!needsNewJob) {
		const polled = row.chain === 'monero'
			? await pollMoneroJob(nfptClient, { jobId, jobToken })
			: await pollOrchardJob(nfptClient, { jobId, jobToken });
		if (!polled.found) {
			clearNfptJob(db, row.id);
			needsNewJob = true;
		}
		else {
			snapshot = polled.snapshot;
		}
	}

	if (needsNewJob) {
		const started = await startJobForRow({ row, viewKey, nfptClient });
		jobId = started.jobId;
		jobToken = started.jobToken;
		summary.jobs_started += 1;
		updateWatchState(db, row.id, {
			nfpt_job_id: jobId,
			nfpt_job_token: jobToken,
			nfpt_job_started_at_ms: now()
		});
		// Immediate poll so first balance shows up without waiting a
		// full tick interval.
		const polled = row.chain === 'monero'
			? await pollMoneroJob(nfptClient, { jobId, jobToken })
			: await pollOrchardJob(nfptClient, { jobId, jobToken });
		snapshot = polled.snapshot ?? null;
	}

	summary.watches_polled += 1;
	const beforeJson = row.last_delivered_balance;
	const before = beforeJson ? safeJson(beforeJson) : null;
	const diff = diffBalance(before, snapshot);
	const nowMs = now();
	const knownJson = snapshot ? JSON.stringify(snapshot) : null;
	updateWatchState(db, row.id, {
		last_polled_at_ms: nowMs,
		last_known_balance: knownJson
	});
	if (!diff) return;

	summary.webhooks_attempted += 1;
	const body = buildWebhookBody({
		watchId: row.id,
		chain: row.chain,
		address: row.address,
		before,
		after: snapshot,
		diff,
		row,
		nowMs
	});
	const result = await deliverWebhook({
		url: row.webhook_url,
		body,
		secret: row.webhook_secret,
		watchId: row.id,
		fetchImpl,
		timeoutMs: webhookTimeoutMs,
		responseMaxBytes
	});
	if (result.ok) {
		summary.webhooks_delivered += 1;
		const eventLabel = diff.first_complete
			? 'scan_complete'
			: diff.balance_changed
				? 'balance_change'
				: 'status_change';
		// 4) Per-call billing. Burns CALL_RATE_ATOMIC. May take credit
		//    to zero — the watch silently pauses next tick.
		const callPatch = applyCallCharge(row, nowMs, { callRateAtomic: rates.callRateAtomic, dayRateAtomic: rates.dayRateAtomic });
		updateWatchState(db, row.id, {
			last_delivered_balance: knownJson,
			last_delivered_at_ms: nowMs,
			last_delivered_event: eventLabel,
			delivery_attempts: 0,
			delivery_count: (row.delivery_count ?? 0) + 1,
			last_delivery_error: null,
			credit_atomic: callPatch.credit_atomic,
			credit_billed_atomic: callPatch.credit_billed_atomic,
			expires_at_ms: callPatch.expires_at_ms
		});
		row.credit_atomic = callPatch.credit_atomic;
		row.credit_billed_atomic = callPatch.credit_billed_atomic;
		row.expires_at_ms = callPatch.expires_at_ms;
		summary.credit_billed_atomic += callPatch.chargeAtomic;
		logger.info?.({
			watchId: row.id,
			chain: row.chain,
			status: result.status,
			delta: diff.delta_atomic,
			credit_remaining_atomic: row.credit_atomic
		}, 'private-watch: webhook delivered');
	}
	else {
		summary.webhooks_failed += 1;
		const attempts = (row.delivery_attempts ?? 0) + 1;
		const dead = attempts >= WATCH_CONSTANTS.MAX_DELIVERY_ATTEMPTS;
		updateWatchState(db, row.id, {
			delivery_attempts: attempts,
			last_delivery_error: truncate(result.error ?? `HTTP ${result.status}`),
			dead: dead ? 1 : 0
		});
		if (dead) summary.watches_dead += 1;
		logger.warn?.({
			watchId: row.id,
			chain: row.chain,
			status: result.status,
			attempts,
			err: result.error
		}, dead ? 'private-watch: webhook dead-letter' : 'private-watch: webhook failed');
	}
}

/**
 * Send a low-credit warning webhook. Always attempts delivery; on
 * success we mark `low_credit_warned = 1` so it doesn't repeat. On
 * failure we silently leave the flag at 0 — the next tick will retry,
 * which is fine for this kind of soft notification.
 *
 * Returns true if the webhook was successfully delivered.
 */
async function maybeFireLowCredit({ row, db, fetchImpl, webhookTimeoutMs, responseMaxBytes, nowMs, logger }) {
	const body = buildLowCreditBody({
		watchId: row.id,
		chain: row.chain,
		address: row.address,
		row,
		nowMs
	});
	const result = await deliverWebhook({
		url: row.webhook_url,
		body,
		secret: row.webhook_secret,
		watchId: row.id,
		fetchImpl,
		timeoutMs: webhookTimeoutMs,
		responseMaxBytes
	});
	if (!result.ok) {
		logger.warn?.({
			watchId: row.id,
			chain: row.chain,
			status: result.status,
			err: result.error
		}, 'private-watch: low-credit warning failed');
		return false;
	}
	updateWatchState(db, row.id, { low_credit_warned: 1 });
	logger.info?.({
		watchId: row.id,
		chain: row.chain,
		credit_remaining_atomic: row.credit_atomic
	}, 'private-watch: low-credit warning delivered');
	return true;
}

async function startJobForRow({ row, viewKey, nfptClient }) {
	if (row.chain === 'monero') {
		return startMoneroJob(nfptClient, {
			address: row.address,
			viewKey,
			fromHeight: row.birthday_height ?? undefined
		});
	}
	// NEVER autoDetect for Zcash — it walks the chain backwards from
	// the tip and can run for hours, holding an NFPT scanner slot for
	// a single $0.10 watch. The validator already defaults missing
	// birthdayHeight to NU6 (post-April-2024), which covers virtually
	// all live wallets. Older wallets must pass an explicit
	// birthdayHeight.
	return startOrchardJob(nfptClient, {
		ufvk: viewKey,
		birthdayHeight: row.birthday_height ?? WATCH_CONSTANTS.ZCASH_NU6_HEIGHT,
		autoDetect: false
	});
}

/**
 * Deliver a signed webhook with the given body. Returns
 * `{ ok, status, error }`. Pure HTTP — no DB writes — so the caller
 * has full control over retry / state bookkeeping.
 *
 * Exported so unit tests can call it directly with a stub fetch.
 */
export async function deliverWebhook({
	url, body, secret, watchId,
	fetchImpl = globalThis.fetch,
	timeoutMs = DEFAULT_WEBHOOK_TIMEOUT_MS,
	responseMaxBytes = DEFAULT_RESPONSE_MAX_BYTES,
	headerPrefix = DEFAULT_WEBHOOK_HEADER_PREFIX,
	userAgent = DEFAULT_WEBHOOK_USER_AGENT
}) {
	if (typeof url !== 'string') throw new TypeError('deliverWebhook: url is required');
	if (typeof body !== 'string') throw new TypeError('deliverWebhook: body must be a string');
	if (typeof secret !== 'string') throw new TypeError('deliverWebhook: secret is required');
	const signature = signWebhookBody(body, secret);
	const ac = new AbortController();
	const t = setTimeout(() => ac.abort(new Error('webhook: timed out')), timeoutMs);
	try {
		const res = await fetchImpl(url, {
			method: 'POST',
			signal: ac.signal,
			headers: {
				'content-type': 'application/json',
				'user-agent': userAgent,
				[`${headerPrefix}-signature`]: `sha256=${signature}`,
				[`${headerPrefix}-watch-id`]: watchId ?? '',
				[`${headerPrefix}-event`]: safeEventFromBody(body)
			},
			body
		});
		// Drain a bounded number of bytes from the response so a
		// receiver returning a multi-megabyte body can't slow-loris
		// us. We don't actually use the contents — the status code is
		// the source of truth.
		await drainBodyBounded(res, responseMaxBytes, ac);
		const ok = res.status >= 200 && res.status < 300;
		return { ok, status: res.status, error: ok ? null : `non-2xx HTTP ${res.status}` };
	}
	catch (err) {
		return {
			ok: false,
			status: 0,
			error: truncate(err?.message ?? String(err))
		};
	}
	finally {
		clearTimeout(t);
	}
}

async function drainBodyBounded(res, maxBytes, ac) {
	const reader = res?.body?.getReader?.();
	if (!reader) return; // node-fetch shims without streaming bodies
	let total = 0;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) return;
			if (value) total += value.byteLength;
			if (total > maxBytes) {
				try { ac.abort(new Error(`webhook response exceeded ${maxBytes} bytes`)); }
				catch { /* swallow */ }
				try { await reader.cancel(); }
				catch { /* swallow */ }
				return;
			}
		}
	}
	catch { /* aborted or socket gone — we don't care about the body */ }
}

function safeJson(s) {
	try { return JSON.parse(s); }
	catch { return null; }
}

function safeEventFromBody(body) {
	try {
		const obj = JSON.parse(body);
		return obj.event ?? 'unknown';
	}
	catch { return 'unknown'; }
}

function truncate(s) {
	if (typeof s !== 'string') return String(s);
	return s.length > MAX_LOG_REASON_LEN ? `${s.slice(0, MAX_LOG_REASON_LEN)}…` : s;
}

export const POLLER_CONSTANTS = Object.freeze({
	DEFAULT_WEBHOOK_TIMEOUT_MS
});
