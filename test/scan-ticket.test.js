// Tests for scan-ticket minting and the scanner-queue fields on
// startOrchardJob.
//
// Context: NFPT is one scanner shared by zecmon, Seneschal and the
// winbit32 MCP tools. It accounts the free tier per END USER rather than
// per socket, and runs one queue for everybody. We reach it over
// loopback, which used to mean "uncapped" and now means "say who you are
// acting for" — so these tests care mostly about headers going out
// correctly, since getting them wrong silently lumps every watch we own
// into one shared allowance.

import { describe, test, expect } from '@jest/globals';
import crypto from 'node:crypto';

import {
	mintScanTicket,
	isTicketingEnabled,
	normaliseSubject,
	MAX_TICKET_TTL_SEC
} from '../src/scan-ticket.js';
import { createNfptClient, startOrchardJob, scanHistorical } from '../src/private-watch-nfpt.js';

const SECRET = 'shared-secret-at-least-16-chars';

/**
 * Independent re-implementation of the verifier, deliberately NOT
 * importing our own minting code. If this and NFPT ever disagree about
 * the wire format, every paid queue jump silently degrades to the free
 * lane — which nobody would notice from the outside.
 */
function verifyIndependently(ticket, secret) {
	const parts = String(ticket).split('.');
	if (parts.length !== 5) return { ok: false, reason: 'shape' };
	const [v, subject, exp, nonce, mac] = parts;
	if (v !== 'v1') return { ok: false, reason: 'version' };
	const expected = crypto
		.createHmac('sha256', secret)
		.update(`v1|${subject}|${exp}|${nonce}`)
		.digest('base64url');
	if (mac !== expected) return { ok: false, reason: 'signature' };
	if (Number(exp) * 1000 <= Date.now()) return { ok: false, reason: 'expired' };
	return { ok: true, subject, exp: Number(exp) };
}

function captureFetch(body = { success: true, data: { jobId: 'j1', jobToken: 't1' } }) {
	const calls = [];
	const fetchImpl = async (url, init) => {
		calls.push({ url, init });
		return {
			ok: true,
			status: 202,
			headers: { get: () => 'application/json' },
			text: async () => JSON.stringify(body),
			json: async () => body
		};
	};
	return { calls, fetchImpl };
}

describe('mintScanTicket', () => {
	test('produces a token the scanner side can verify', () => {
		const t = mintScanTicket('watch:abc123', { secret: SECRET });
		const out = verifyIndependently(t, SECRET);
		expect(out.ok).toBe(true);
		expect(out.subject).toBe('watch:abc123');
	});

	test('a different secret does not verify', () => {
		const t = mintScanTicket('watch:abc123', { secret: SECRET });
		expect(verifyIndependently(t, 'some-other-secret-value-16').ok).toBe(false);
	});

	test('every ticket is unique, so one payment cannot mint many jumps', () => {
		const a = mintScanTicket('watch:abc', { secret: SECRET });
		const b = mintScanTicket('watch:abc', { secret: SECRET });
		expect(a).not.toBe(b);
		// The nonce is what NFPT keys single-use on.
		expect(a.split('.')[3]).not.toBe(b.split('.')[3]);
	});

	test('TTL is clamped to what the scanner will accept', () => {
		const t = mintScanTicket('watch:abc', { secret: SECRET, ttlSec: 86_400 });
		const exp = Number(t.split('.')[2]);
		expect(exp - Math.floor(Date.now() / 1000)).toBeLessThanOrEqual(MAX_TICKET_TTL_SEC);
	});

	test('refuses to mint without a usable secret', () => {
		expect(() => mintScanTicket('watch:abc', { secret: undefined })).toThrow(/SCAN_TICKET_SECRET/u);
		expect(() => mintScanTicket('watch:abc', { secret: 'tooshort' })).toThrow(/SCAN_TICKET_SECRET/u);
		expect(isTicketingEnabled('tooshort')).toBe(false);
		expect(isTicketingEnabled(SECRET)).toBe(true);
	});

	test('rejects subjects that would break the token format', () => {
		// A dot would make the five-field split ambiguous.
		expect(normaliseSubject('1.2.3.4')).toBeNull();
		expect(() => mintScanTicket('1.2.3.4', { secret: SECRET })).toThrow();
		expect(() => mintScanTicket('', { secret: SECRET })).toThrow();
	});

	test('normalises case and padding so one user cannot hold two allowances', () => {
		expect(normaliseSubject('  Watch:ABC  ')).toBe('watch:abc');
	});
});

describe('startOrchardJob — shared-queue fields', () => {
	const client = (fetchImpl) => createNfptClient({
		baseUrl: 'http://127.0.0.1:3555',
		apiKey: 'k',
		fetchImpl
	});

	test('passes the subject through so the free tier is per end user', async () => {
		const { calls, fetchImpl } = captureFetch();
		await startOrchardJob(client(fetchImpl), { ufvk: 'uview1x', subject: 'watch:abc' });
		expect(calls[0].init.headers['x-scan-subject']).toBe('watch:abc');
	});

	test('passes a ticket through when one was bought', async () => {
		const { calls, fetchImpl } = captureFetch();
		const ticket = mintScanTicket('watch:abc', { secret: SECRET });
		await startOrchardJob(client(fetchImpl), { ufvk: 'uview1x', subject: 'watch:abc', ticket });
		expect(calls[0].init.headers['x-scan-ticket']).toBe(ticket);
	});

	test('sends NEITHER header when not given — no empty values', async () => {
		// An empty x-scan-subject would be worse than none: it looks like a
		// declaration and normalises to nothing.
		const { calls, fetchImpl } = captureFetch();
		await startOrchardJob(client(fetchImpl), { ufvk: 'uview1x' });
		expect(calls[0].init.headers['x-scan-subject']).toBeUndefined();
		expect(calls[0].init.headers['x-scan-ticket']).toBeUndefined();
	});

	test('deepScan is off unless asked for', async () => {
		const { calls, fetchImpl } = captureFetch();
		await startOrchardJob(client(fetchImpl), { ufvk: 'uview1x' });
		expect(JSON.parse(calls[0].init.body).deepScan).toBe(false);

		const second = captureFetch();
		await startOrchardJob(client(second.fetchImpl), { ufvk: 'uview1x', deepScan: true });
		expect(JSON.parse(second.calls[0].init.body).deepScan).toBe(true);
	});

	test('reports when the scanner queued the job rather than starting it', async () => {
		// A caller that reads "accepted" as "running" will report a stall.
		const { fetchImpl } = captureFetch({
			success: true,
			data: {
				jobId: 'j1',
				jobToken: 't1',
				queued: true,
				queue: { position: 2, queueLength: 5, lane: 'standard', estimatedStartSec: 300 }
			}
		});
		const out = await startOrchardJob(client(fetchImpl), { ufvk: 'uview1x' });
		expect(out.queued).toBe(true);
		expect(out.queue.position).toBe(2);
	});

	test('a job that started immediately is not reported as queued', async () => {
		const { fetchImpl } = captureFetch();
		const out = await startOrchardJob(client(fetchImpl), { ufvk: 'uview1x' });
		expect(out.queued).toBe(false);
		expect(out.queue).toBeNull();
	});
});

describe('scanHistorical — the paid path', () => {
	const ZCASH_JOB = {
		success: true,
		data: { job: { status: 'succeeded', progress: {}, results: { notes: [] } } }
	};

	function twoStepFetch() {
		const calls = [];
		const fetchImpl = async (url, init) => {
			calls.push({ url, init });
			const started = { success: true, data: { jobId: 'j1', jobToken: 't1' } };
			const body = String(url).includes('/job/') ? ZCASH_JOB : started;
			return {
				ok: true, status: 200,
				headers: { get: () => 'application/json' },
				text: async () => JSON.stringify(body),
				json: async () => body
			};
		};
		return { calls, fetchImpl };
	}

	const client = (fetchImpl) => createNfptClient({
		baseUrl: 'http://127.0.0.1:3555', apiKey: 'k', fetchImpl
	});

	afterEach(() => { delete process.env.SCAN_TICKET_SECRET; });

	test('a paid scan carries a ticket when ticketing is configured', async () => {
		process.env.SCAN_TICKET_SECRET = SECRET;
		const { calls, fetchImpl } = twoStepFetch();
		await scanHistorical(client(fetchImpl), {
			chain: 'zcash', address: 'u1abc', viewKey: 'uview1x', priority: true
		});
		const ticket = calls[0].init.headers['x-scan-ticket'];
		expect(ticket).toBeTruthy();
		expect(verifyIndependently(ticket, SECRET).ok).toBe(true);
	});

	test('an UNPAID scan carries no ticket even with a secret present', async () => {
		process.env.SCAN_TICKET_SECRET = SECRET;
		const { calls, fetchImpl } = twoStepFetch();
		await scanHistorical(client(fetchImpl), {
			chain: 'zcash', address: 'u1abc', viewKey: 'uview1x'
		});
		expect(calls[0].init.headers['x-scan-ticket']).toBeUndefined();
	});

	test('a paid scan still RUNS when our secret is missing — free lane, not an error', async () => {
		// Someone who has paid must never see a failure because of a
		// configuration gap on our side.
		delete process.env.SCAN_TICKET_SECRET;
		const { calls, fetchImpl } = twoStepFetch();
		const out = await scanHistorical(client(fetchImpl), {
			chain: 'zcash', address: 'u1abc', viewKey: 'uview1x', priority: true
		});
		expect(out).toBeTruthy();
		expect(calls[0].init.headers['x-scan-ticket']).toBeUndefined();
		// The subject is still declared, so free-tier accounting stays per user.
		expect(calls[0].init.headers['x-scan-subject']).toMatch(/^addr:[0-9a-f]{16}$/u);
	});

	test('the default subject is derived from the ADDRESS, never the view key', async () => {
		const { calls, fetchImpl } = twoStepFetch();
		await scanHistorical(client(fetchImpl), {
			chain: 'zcash', address: 'u1abc', viewKey: 'uview1SECRETKEYMATERIAL'
		});
		const subject = calls[0].init.headers['x-scan-subject'];
		expect(subject).toMatch(/^addr:[0-9a-f]{16}$/u);
		// Neither the address nor any part of the key travels in clear.
		expect(subject).not.toContain('u1abc');
		expect(subject.toLowerCase()).not.toContain('secretkey');
	});

	test('two addresses get two subjects, so they do not share an allowance', async () => {
		const a = twoStepFetch();
		await scanHistorical(client(a.fetchImpl), { chain: 'zcash', address: 'u1aaa', viewKey: 'uview1x' });
		const b = twoStepFetch();
		await scanHistorical(client(b.fetchImpl), { chain: 'zcash', address: 'u1bbb', viewKey: 'uview1x' });
		expect(a.calls[0].init.headers['x-scan-subject'])
			.not.toBe(b.calls[0].init.headers['x-scan-subject']);
	});
});
