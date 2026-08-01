// End-to-end-ish tests for the poller tick. We wire:
//   - an in-memory watch DB (real SQLite)
//   - a stub NFPT client (programmable fetchImpl)
//   - a stub webhook fetchImpl that records POSTs
// then call runPollerTick and assert on what happened.
//
// The crypto module is real (encryptViewKey + decryptViewKey are
// stable round-trips), so we can verify the poller actually decrypts
// the view key before passing it to NFPT.

import { describe, test, expect, beforeEach } from '@jest/globals';

import {
	openWatchDb,
	createWatch,
	getWatch
} from '../src/private-watch-store.js';
import {
	parseMasterKey,
	encryptViewKey,
	signWebhookBody
} from '../src/private-watch-crypto.js';
import { createNfptClient } from '../src/private-watch-nfpt.js';
import { runPollerTick, deliverWebhook } from '../src/private-watch-poller.js';
import { WATCH_CONSTANTS } from '../src/private-watch.js';

const MASTER_KEY_HEX = '00'.repeat(32);
const MASTER_KEY = parseMasterKey(MASTER_KEY_HEX);
const XMR_ADDR = '4' + 'A'.repeat(94);
const XMR_VK = '7'.repeat(64);
const DAY = 86_400_000;
const NOW = 1_800_000_000_000;

let db;
const webhookEvents = [];

beforeEach(() => {
	db = openWatchDb(':memory:');
	webhookEvents.length = 0;
});

function makeMoneroWatch({ webhookUrl = 'https://example.com/hook', creditAtomic = WATCH_CONSTANTS.STARTER_CREDIT_ATOMIC, nowMs = NOW } = {}) {
	const ct = encryptViewKey(XMR_VK, MASTER_KEY);
	return createWatch(db, {
		chain: 'monero',
		address: XMR_ADDR,
		viewKeyCiphertext: ct,
		webhookUrl,
		webhookSecret: '5e'.repeat(32),
		creditAtomic,
		dayRateAtomic: WATCH_CONSTANTS.DAY_RATE_ATOMIC,
		maxLifetimeMs: WATCH_CONSTANTS.MAX_WATCH_LIFETIME_MS,
		nowMs
	});
}

function stubNfpt(scriptedResponses) {
	// scriptedResponses is an array; each call returns the next element
	// (looping forever after the last one).
	let i = 0;
	const calls = [];
	return {
		calls,
		client: createNfptClient({
			baseUrl: 'http://nfpt',
			apiKey: 'k',
			fetchImpl: async (url, init) => {
				const idx = Math.min(i, scriptedResponses.length - 1);
				const r = scriptedResponses[idx];
				i += 1;
				calls.push({ url, method: init.method, body: init.body });
				return {
					status: r.status,
					text: async () => JSON.stringify(r.body)
				};
			}
		})
	};
}

function webhookCapture(reply = { ok: true }) {
	return async (url, init) => {
		webhookEvents.push({ url, init });
		return { status: reply.ok ? 200 : 500, text: async () => 'ok' };
	};
}

describe('runPollerTick — first poll', () => {
	test('starts a Monero job, polls, and emits a scan_complete webhook', async () => {
		const w = makeMoneroWatch();
		const responses = [
			{ status: 202, body: { data: { jobId: 'J1', jobToken: 'T1' } } },        // POST start
			{ status: 200, body: { data: { job: {                                    // GET poll
				jobId: 'J1', status: 'completed',
				progress: { scannedHeight: 100, chainHeight: 100, scanProgress: 1, percentComplete: 100 },
				balance: { totalAtomic: '0', spendableAtomic: '0', lockedAtomic: '0' },
				error: null
			} } } }
		];
		const nfpt = stubNfpt(responses);
		const summary = await runPollerTick({
			db, masterKey: MASTER_KEY,
			nfptClient: nfpt.client,
			fetchImpl: webhookCapture(),
			now: () => NOW + 1000,
			logger: { info: () => {}, warn: () => {}, error: () => {} }
		});
		expect(summary.jobs_started).toBe(1);
		expect(summary.watches_polled).toBe(1);
		expect(summary.webhooks_attempted).toBe(1);
		expect(summary.webhooks_delivered).toBe(1);
		expect(webhookEvents.length).toBe(1);
		const payload = JSON.parse(webhookEvents[0].init.body);
		expect(payload.event).toBe('scan_complete');
		expect(payload.chain).toBe('monero');
		expect(payload.address).toBe(XMR_ADDR);
		const row = getWatch(db, w.id, w.token);
		expect(row.delivery_count).toBe(1);
		expect(row.delivery_attempts).toBe(0);
		expect(row.nfpt_job_id).toBe('J1');
	});
});

describe('runPollerTick — webhook branding', () => {
	test('threads a custom headerPrefix + userAgent to the delivered webhook', async () => {
		makeMoneroWatch();
		const responses = [
			{ status: 202, body: { data: { jobId: 'J1', jobToken: 'T1' } } },
			{ status: 200, body: { data: { job: {
				jobId: 'J1', status: 'completed',
				progress: { scannedHeight: 100, chainHeight: 100, scanProgress: 1, percentComplete: 100 },
				balance: { totalAtomic: '0', spendableAtomic: '0', lockedAtomic: '0' },
				error: null
			} } } }
		];
		const nfpt = stubNfpt(responses);
		await runPollerTick({
			db, masterKey: MASTER_KEY,
			nfptClient: nfpt.client,
			fetchImpl: webhookCapture(),
			headerPrefix: 'x-payment',
			userAgent: 'PaymentsGateway-PrivateWatch/1.0',
			now: () => NOW + 1000,
			logger: { info: () => {}, warn: () => {}, error: () => {} }
		});
		expect(webhookEvents.length).toBe(1);
		const headers = webhookEvents[0].init.headers;
		expect(headers['x-payment-watch-id']).toBeDefined();
		expect(headers['x-payment-signature'].startsWith('sha256=')).toBe(true);
		expect(headers['user-agent']).toBe('PaymentsGateway-PrivateWatch/1.0');
		expect(headers['x-viewkey-signature']).toBeUndefined();
	});
});

describe('runPollerTick — balance change', () => {
	test('emits balance_change when balance grows', async () => {
		const w = makeMoneroWatch();
		// First tick: scan completes at zero. Second tick: balance grows.
		const tick1 = stubNfpt([
			{ status: 202, body: { data: { jobId: 'J1', jobToken: 'T1' } } },
			{ status: 200, body: { data: { job: {
				status: 'completed',
				progress: { scannedHeight: 1, chainHeight: 1, scanProgress: 1, percentComplete: 100 },
				balance: { totalAtomic: '0' },
				error: null
			} } } }
		]);
		await runPollerTick({
			db, masterKey: MASTER_KEY,
			nfptClient: tick1.client,
			fetchImpl: webhookCapture(),
			now: () => NOW + 1000,
			logger: { info: () => {}, warn: () => {}, error: () => {} }
		});
		webhookEvents.length = 0;
		// Second tick: GET existing job returns higher balance.
		const tick2 = stubNfpt([
			{ status: 200, body: { data: { job: {
				status: 'completed',
				progress: { scannedHeight: 2, chainHeight: 2, scanProgress: 1, percentComplete: 100 },
				balance: { totalAtomic: '1234567890' },
				error: null
			} } } }
		]);
		const s2 = await runPollerTick({
			db, masterKey: MASTER_KEY,
			nfptClient: tick2.client,
			fetchImpl: webhookCapture(),
			now: () => NOW + 2000,
			logger: { info: () => {}, warn: () => {}, error: () => {} }
		});
		expect(s2.jobs_started).toBe(0);
		expect(s2.webhooks_delivered).toBe(1);
		const payload = JSON.parse(webhookEvents[0].init.body);
		expect(payload.event).toBe('balance_change');
		expect(payload.delta.balance_atomic).toBe('1234567890');
		expect(payload.delta.after_atomic).toBe('1234567890');
	});

	test('skips webhook if balance unchanged', async () => {
		makeMoneroWatch();
		const tick1 = stubNfpt([
			{ status: 202, body: { data: { jobId: 'J1', jobToken: 'T1' } } },
			{ status: 200, body: { data: { job: {
				status: 'completed',
				progress: { scannedHeight: 1, chainHeight: 1, scanProgress: 1, percentComplete: 100 },
				balance: { totalAtomic: '7' },
				error: null
			} } } }
		]);
		await runPollerTick({ db, masterKey: MASTER_KEY, nfptClient: tick1.client, fetchImpl: webhookCapture(), now: () => NOW + 1000, logger: { info: () => {}, warn: () => {}, error: () => {} } });
		webhookEvents.length = 0;
		const tick2 = stubNfpt([
			{ status: 200, body: { data: { job: {
				status: 'completed',
				progress: { scannedHeight: 2, chainHeight: 2, scanProgress: 1, percentComplete: 100 },
				balance: { totalAtomic: '7' },
				error: null
			} } } }
		]);
		const s = await runPollerTick({ db, masterKey: MASTER_KEY, nfptClient: tick2.client, fetchImpl: webhookCapture(), now: () => NOW + 2000, logger: { info: () => {}, warn: () => {}, error: () => {} } });
		expect(s.webhooks_attempted).toBe(0);
		expect(webhookEvents.length).toBe(0);
	});
});

describe('runPollerTick — failure paths', () => {
	test('restarts job after NFPT 404', async () => {
		makeMoneroWatch();
		// First tick: gives us a job and a balance
		const tick1 = stubNfpt([
			{ status: 202, body: { data: { jobId: 'J1', jobToken: 'T1' } } },
			{ status: 200, body: { data: { job: {
				status: 'completed',
				progress: { scannedHeight: 1, chainHeight: 1, scanProgress: 1, percentComplete: 100 },
				balance: { totalAtomic: '10' },
				error: null
			} } } }
		]);
		await runPollerTick({ db, masterKey: MASTER_KEY, nfptClient: tick1.client, fetchImpl: webhookCapture(), now: () => NOW + 1000, logger: { info: () => {}, warn: () => {}, error: () => {} } });
		webhookEvents.length = 0;
		// Second tick: existing job 404s -> we expect a new POST start + a fresh poll.
		const tick2 = stubNfpt([
			{ status: 404, body: { error: 'gone' } },
			{ status: 202, body: { data: { jobId: 'J2', jobToken: 'T2' } } },
			{ status: 200, body: { data: { job: {
				status: 'completed',
				progress: { scannedHeight: 5, chainHeight: 5, scanProgress: 1, percentComplete: 100 },
				balance: { totalAtomic: '10' },
				error: null
			} } } }
		]);
		const s = await runPollerTick({ db, masterKey: MASTER_KEY, nfptClient: tick2.client, fetchImpl: webhookCapture(), now: () => NOW + 2000, logger: { info: () => {}, warn: () => {}, error: () => {} } });
		expect(s.jobs_started).toBe(1);
		expect(tick2.calls.some((c) => c.method === 'POST')).toBe(true);
	});

	test('records delivery failure but keeps watch alive below MAX_ATTEMPTS', async () => {
		const w = makeMoneroWatch();
		const responses = [
			{ status: 202, body: { data: { jobId: 'J1', jobToken: 'T1' } } },
			{ status: 200, body: { data: { job: {
				status: 'completed',
				progress: { scannedHeight: 1, chainHeight: 1, scanProgress: 1, percentComplete: 100 },
				balance: { totalAtomic: '999' },
				error: null
			} } } }
		];
		const nfpt = stubNfpt(responses);
		const s = await runPollerTick({
			db, masterKey: MASTER_KEY,
			nfptClient: nfpt.client,
			fetchImpl: webhookCapture({ ok: false }),
			now: () => NOW + 1000,
			logger: { info: () => {}, warn: () => {}, error: () => {} }
		});
		expect(s.webhooks_failed).toBe(1);
		const row = getWatch(db, w.id, w.token);
		expect(row.delivery_attempts).toBe(1);
		expect(row.dead).toBe(0);
		expect(row.last_delivery_error).toMatch(/non-2xx/);
	});
});

describe('deliverWebhook', () => {
	test('signs the body and sets headers', async () => {
		let captured = null;
		const fetchImpl = async (url, init) => {
			captured = { url, init };
			return { status: 200, text: async () => 'ok' };
		};
		const body = JSON.stringify({ hello: 'world' });
		const secret = '3a'.repeat(32);
		const r = await deliverWebhook({
			url: 'https://example.com/hook',
			body,
			secret,
			watchId: 'w1',
			fetchImpl
		});
		expect(r.ok).toBe(true);
		expect(captured.url).toBe('https://example.com/hook');
		expect(captured.init.method).toBe('POST');
		expect(captured.init.headers['content-type']).toBe('application/json');
		expect(captured.init.headers['x-viewkey-watch-id']).toBe('w1');
		const sig = captured.init.headers['x-viewkey-signature'];
		expect(sig.startsWith('sha256=')).toBe(true);
		const expected = signWebhookBody(body, secret);
		expect(sig).toBe(`sha256=${expected}`);
	});

	test('honours a custom headerPrefix + userAgent', async () => {
		let captured = null;
		const fetchImpl = async (url, init) => {
			captured = { url, init };
			return { status: 200, text: async () => 'ok' };
		};
		await deliverWebhook({
			url: 'https://example.com/hook',
			body: JSON.stringify({ hello: 'world' }),
			secret: '3a'.repeat(32),
			watchId: 'w1',
			fetchImpl,
			headerPrefix: 'x-payment',
			userAgent: 'PaymentsGateway-PrivateWatch/1.0'
		});
		expect(captured.init.headers['x-payment-watch-id']).toBe('w1');
		expect(captured.init.headers['x-payment-signature'].startsWith('sha256=')).toBe(true);
		expect(captured.init.headers['user-agent']).toBe('PaymentsGateway-PrivateWatch/1.0');
		// The default namespace must NOT leak through when overridden.
		expect(captured.init.headers['x-viewkey-watch-id']).toBeUndefined();
	});

	test('returns ok:false on 500', async () => {
		const fetchImpl = async () => ({ status: 500, text: async () => 'down' });
		const r = await deliverWebhook({
			url: 'https://example.com/hook',
			body: '{}',
			secret: '00'.repeat(32),
			watchId: 'w1',
			fetchImpl
		});
		expect(r.ok).toBe(false);
		expect(r.status).toBe(500);
	});

	test('returns ok:false on fetch throw', async () => {
		const fetchImpl = async () => { throw new Error('boom'); };
		const r = await deliverWebhook({
			url: 'https://example.com/hook',
			body: '{}',
			secret: '00'.repeat(32),
			watchId: 'w1',
			fetchImpl
		});
		expect(r.ok).toBe(false);
		expect(r.status).toBe(0);
		expect(r.error).toMatch(/boom/);
	});
});

describe('runPollerTick — credit billing', () => {
	test('charges per-day on each tick and persists the new balance', async () => {
		// Watch starts with 100_000 atomic credit; we advance the
		// poller's clock by 1 day so per-day billing should subtract
		// 20_000 (= DAY_RATE_ATOMIC) on the tick.
		const w = makeMoneroWatch();
		const responses = [
			{ status: 202, body: { data: { jobId: 'J1', jobToken: 'T1' } } },
			{ status: 200, body: { data: { job: {
				status: 'completed',
				progress: { scannedHeight: 1, chainHeight: 1, scanProgress: 1, percentComplete: 100 },
				balance: { totalAtomic: '0' },
				error: null
			} } } }
		];
		const nfpt = stubNfpt(responses);
		const s = await runPollerTick({
			db, masterKey: MASTER_KEY,
			nfptClient: nfpt.client,
			fetchImpl: webhookCapture(),
			now: () => NOW + DAY,
			logger: { info: () => {}, warn: () => {}, error: () => {} }
		});
		// Day charge: 20_000. Call charge for the scan_complete
		// webhook: 5_000. Both should be reflected in row + summary.
		expect(s.credit_billed_atomic).toBe(25_000);
		expect(s.webhooks_delivered).toBe(1);
		const row = getWatch(db, w.id, w.token);
		expect(row.credit_atomic).toBe(WATCH_CONSTANTS.STARTER_CREDIT_ATOMIC - 25_000);
		expect(row.credit_billed_atomic).toBe(25_000);
		// Webhook body carries the post-day-charge credit block.
		const payload = JSON.parse(webhookEvents[0].init.body);
		expect(payload.credit.remaining_atomic).toBe(String(WATCH_CONSTANTS.STARTER_CREDIT_ATOMIC - 20_000));
		expect(payload.credit.billed_atomic).toBe('20000');
	});

	test('fires a one-shot low_credit warning when crossing threshold', async () => {
		// Seed credit just above threshold (40_001). 1.001 days
		// elapsed crosses the bound at the second tick.
		const w = makeMoneroWatch({ creditAtomic: 50_000 });
		const responses = [
			{ status: 202, body: { data: { jobId: 'J1', jobToken: 'T1' } } },
			{ status: 200, body: { data: { job: {
				status: 'completed',
				progress: { scannedHeight: 1, chainHeight: 1, scanProgress: 1, percentComplete: 100 },
				balance: { totalAtomic: '0' },
				error: null
			} } } }
		];
		const nfpt = stubNfpt(responses);
		// Advance ~12 hours = $0.01 charge -> 50_000 - 10_000 = 40_000
		// which equals threshold (≤). Should fire warning.
		const s = await runPollerTick({
			db, masterKey: MASTER_KEY,
			nfptClient: nfpt.client,
			fetchImpl: webhookCapture(),
			now: () => NOW + DAY / 2,
			logger: { info: () => {}, warn: () => {}, error: () => {} }
		});
		expect(s.low_credit_warnings).toBe(1);
		// First webhook should be the low_credit warning, then the
		// scan_complete (different events).
		const events = webhookEvents.map(e => JSON.parse(e.init.body).event);
		expect(events[0]).toBe('low_credit');
		expect(events).toContain('scan_complete');
		const row = getWatch(db, w.id, w.token);
		expect(row.low_credit_warned).toBe(1);

		// Reset; next tick another 12h elapse -> already warned,
		// should NOT fire another low_credit.
		webhookEvents.length = 0;
		const nfpt2 = stubNfpt([
			{ status: 200, body: { data: { job: {
				status: 'completed',
				progress: { scannedHeight: 2, chainHeight: 2, scanProgress: 1, percentComplete: 100 },
				balance: { totalAtomic: '0' },
				error: null
			} } } }
		]);
		const s2 = await runPollerTick({
			db, masterKey: MASTER_KEY,
			nfptClient: nfpt2.client,
			fetchImpl: webhookCapture(),
			now: () => NOW + DAY,
			logger: { info: () => {}, warn: () => {}, error: () => {} }
		});
		expect(s2.low_credit_warnings).toBe(0);
		const events2 = webhookEvents.map(e => JSON.parse(e.init.body).event);
		expect(events2).not.toContain('low_credit');
	});

	test('paused watches (credit_atomic = 0) are excluded by listActiveWatches', async () => {
		// Manually zero a watch's credit to mimic the steady-state
		// after burn (the meter math means day-charge can only ever
		// drive credit to zero precisely as expires_at_ms ticks
		// past now — the next tick's listActiveWatches filters the
		// row out before pollOne sees it).
		const w = makeMoneroWatch();
		db.prepare('UPDATE private_watches SET credit_atomic = 0 WHERE id = ?').run(w.id);
		const nfpt = stubNfpt([
			{ status: 202, body: { data: { jobId: 'NOPE', jobToken: 'X' } } }
		]);
		const s = await runPollerTick({
			db, masterKey: MASTER_KEY,
			nfptClient: nfpt.client,
			fetchImpl: webhookCapture(),
			now: () => NOW + 1000,
			logger: { info: () => {}, warn: () => {}, error: () => {} }
		});
		expect(s.watches_seen).toBe(0);
		expect(s.jobs_started).toBe(0);
		expect(nfpt.calls.length).toBe(0);
	});

	test('per-call charge is not applied when webhook delivery fails', async () => {
		const w = makeMoneroWatch();
		const nfpt = stubNfpt([
			{ status: 202, body: { data: { jobId: 'J1', jobToken: 'T1' } } },
			{ status: 200, body: { data: { job: {
				status: 'completed',
				progress: { scannedHeight: 1, chainHeight: 1, scanProgress: 1, percentComplete: 100 },
				balance: { totalAtomic: '5' },
				error: null
			} } } }
		]);
		await runPollerTick({
			db, masterKey: MASTER_KEY,
			nfptClient: nfpt.client,
			fetchImpl: webhookCapture({ ok: false }),
			now: () => NOW + DAY,
			logger: { info: () => {}, warn: () => {}, error: () => {} }
		});
		const row = getWatch(db, w.id, w.token);
		// Day charge applied (20_000) but NOT the call charge (5_000)
		// because the webhook returned 500.
		expect(row.credit_atomic).toBe(WATCH_CONSTANTS.STARTER_CREDIT_ATOMIC - WATCH_CONSTANTS.DAY_RATE_ATOMIC);
		expect(row.credit_billed_atomic).toBe(WATCH_CONSTANTS.DAY_RATE_ATOMIC);
		expect(row.delivery_attempts).toBe(1);
	});
});

describe('runPollerTick — premature snapshots (phantom balance oscillation)', () => {
	// Regression for a defect found by a live post-activation smoke:
	// upstream expires idle scan jobs faster than the poll interval, so
	// every few ticks the poller found its job gone, started a fresh one
	// and immediately polled it. That first poll always answers
	// "running / no notes / scannedHeight 0", which was diffed against
	// real prior knowledge as a drain to zero — then a refill when the
	// scan landed, then another drain, forever. One deposit produced an
	// endless ±balance stream, re-crediting downstream consumers and
	// burning the watch's own per-call credit on non-events.
	const settled = { status: 200, body: { data: { job: {
		jobId: 'J1', status: 'completed',
		progress: { scannedHeight: 100, chainHeight: 100, scanProgress: 1, percentComplete: 100 },
		balance: { totalAtomic: '50000', spendableAtomic: '50000', lockedAtomic: '0' },
		error: null
	} } } };

	async function tick(nfpt, nowMs) {
		return runPollerTick({
			db, masterKey: MASTER_KEY,
			nfptClient: nfpt.client,
			fetchImpl: webhookCapture(),
			now: () => nowMs,
			logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} }
		});
	}

	test('a restarted job does not publish a phantom drain to zero', async () => {
		const w = makeMoneroWatch();

		// Tick 1: job starts, scan completes, real balance delivered.
		await tick(stubNfpt([
			{ status: 202, body: { data: { jobId: 'J1', jobToken: 'T1' } } },
			settled
		]), NOW + 1000);
		expect(webhookEvents.length).toBe(1);
		const first = JSON.parse(webhookEvents[0].init.body);
		expect(first.current.balanceAtomic).toBe('50000');
		const afterFirst = getWatch(db, w.id, w.token);
		const creditAfterFirst = afterFirst.credit_atomic;

		// Tick 2: upstream has dropped the job (404). The poller starts a
		// new one and polls it immediately — nothing scanned yet.
		const summary = await tick(stubNfpt([
			{ status: 404, body: { error: 'not found' } },
			{ status: 202, body: { data: { jobId: 'J2', jobToken: 'T2' } } },
			{ status: 200, body: { data: { job: {
				jobId: 'J2', status: 'running',
				progress: { scannedHeight: 0, chainHeight: 0, scanProgress: 0, percentComplete: 0 },
				balance: { totalAtomic: '0', spendableAtomic: '0', lockedAtomic: '0' },
				error: null
			} } } }
		]), NOW + 2000);

		expect(summary.premature_snapshots).toBe(1);
		// The whole point: no second webhook, and nothing billed for it.
		expect(webhookEvents.length).toBe(1);
		expect(summary.webhooks_attempted).toBe(0);
		const afterSecond = getWatch(db, w.id, w.token);
		expect(afterSecond.credit_atomic).toBe(creditAfterFirst);
		// What we know must not regress to the phantom zero.
		expect(JSON.parse(afterSecond.last_known_balance).balanceAtomic).toBe('50000');
		expect(afterSecond.last_polled_at_ms).toBe(NOW + 2000);
	});

	test('the balance is delivered once the restarted scan actually lands', async () => {
		makeMoneroWatch();
		await tick(stubNfpt([
			{ status: 202, body: { data: { jobId: 'J1', jobToken: 'T1' } } },
			settled
		]), NOW + 1000);
		await tick(stubNfpt([
			{ status: 404, body: { error: 'not found' } },
			{ status: 202, body: { data: { jobId: 'J2', jobToken: 'T2' } } },
			{ status: 200, body: { data: { job: {
				jobId: 'J2', status: 'running',
				progress: { scannedHeight: 0, chainHeight: 0, scanProgress: 0, percentComplete: 0 },
				balance: { totalAtomic: '0' }, error: null
			} } } }
		]), NOW + 2000);
		expect(webhookEvents.length).toBe(1);

		// Tick 3: the new job has caught up and found a further deposit.
		await tick(stubNfpt([{ status: 200, body: { data: { job: {
			jobId: 'J2', status: 'completed',
			progress: { scannedHeight: 200, chainHeight: 200, scanProgress: 1, percentComplete: 100 },
			balance: { totalAtomic: '70000', spendableAtomic: '70000', lockedAtomic: '0' },
			error: null
		} } } }]), NOW + 3000);

		expect(webhookEvents.length).toBe(2);
		const second = JSON.parse(webhookEvents[1].init.body);
		expect(second.event).toBe('balance_change');
		// Diffed against the last real balance, not against the phantom
		// zero — so the delta is the genuine +20000, not +70000.
		expect(second.delta.before_atomic).toBe('50000');
		expect(second.delta.balance_atomic).toBe('20000');
	});

	test('a genuine spend is still reported', async () => {
		makeMoneroWatch();
		await tick(stubNfpt([
			{ status: 202, body: { data: { jobId: 'J1', jobToken: 'T1' } } },
			settled
		]), NOW + 1000);
		// Same job, scan advanced, balance genuinely gone.
		await tick(stubNfpt([{ status: 200, body: { data: { job: {
			jobId: 'J1', status: 'completed',
			progress: { scannedHeight: 300, chainHeight: 300, scanProgress: 1, percentComplete: 100 },
			balance: { totalAtomic: '0', spendableAtomic: '0', lockedAtomic: '0' },
			error: null
		} } } }]), NOW + 2000);

		expect(webhookEvents.length).toBe(2);
		const spend = JSON.parse(webhookEvents[1].init.body);
		expect(spend.event).toBe('balance_change');
		expect(spend.delta.balance_atomic).toBe('-50000');
	});
});
