// Tests for the NFPT scanner client. We stub fetchImpl with predictable
// responses to verify the wire calls + parse logic without touching
// the real upstream. The normalisers are exercised against fixture
// payloads matching NFPT's actual output shape (Monero LWS + Orchard
// scanner).

import { describe, test, expect } from '@jest/globals';

import {
	createNfptClient,
	startMoneroJob,
	pollMoneroJob,
	cancelMoneroJob,
	startOrchardJob,
	pollOrchardJob,
	cancelOrchardJob,
	healthCheck,
	normaliseMonero,
	normaliseOrchard,
	scanHistorical
} from '../src/private-watch-nfpt.js';

function fetchOk(body, status = 200) {
	return async () => ({
		status,
		text: async () => JSON.stringify(body)
	});
}

function fetchStatus(status, body) {
	return async () => ({
		status,
		text: async () => (body == null ? '' : JSON.stringify(body))
	});
}

function captureFetch(handler) {
	const calls = [];
	return {
		calls,
		fetch: async (url, init) => {
			calls.push({ url, init });
			return handler(url, init);
		}
	};
}

describe('createNfptClient', () => {
	test('rejects non-http baseUrl', () => {
		expect(() => createNfptClient({ baseUrl: 'ftp://x' })).toThrow(/baseUrl/);
	});

	test('rejects empty apiKey', () => {
		expect(() => createNfptClient({ apiKey: '' })).toThrow(/apiKey/);
	});

	test('rejects non-function fetchImpl', () => {
		expect(() => createNfptClient({ fetchImpl: null })).toThrow(/fetchImpl/);
		expect(() => createNfptClient({ fetchImpl: 'not-a-fn' })).toThrow(/fetchImpl/);
	});

	test('strips trailing slash from baseUrl', () => {
		const c = createNfptClient({ baseUrl: 'http://x/', fetchImpl: async () => ({ status: 200, text: async () => '{}' }) });
		expect(c.baseUrl).toBe('http://x');
	});
});

describe('startMoneroJob', () => {
	test('POSTs to NFPT and returns jobId + jobToken', async () => {
		const cap = captureFetch(fetchOk({ data: { jobId: 'J1', jobToken: 'T1' } }, 202));
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: cap.fetch });
		const out = await startMoneroJob(c, { address: 'addr', viewKey: 'vk' });
		expect(out).toEqual({ jobId: 'J1', jobToken: 'T1' });
		expect(cap.calls[0].url).toBe('http://nfpt/api/wallet-scanner/monero/scan/job');
		expect(cap.calls[0].init.method).toBe('POST');
		expect(cap.calls[0].init.headers['x-api-key']).toBe('k');
		expect(JSON.parse(cap.calls[0].init.body)).toEqual({ address: 'addr', viewKey: 'vk' });
	});

	test('throws on non-202/200', async () => {
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: fetchStatus(500, { error: 'oops' }) });
		await expect(startMoneroJob(c, { address: 'addr', viewKey: 'vk' })).rejects.toThrow(/HTTP 500/);
	});

	test('throws on missing fields', async () => {
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: fetchOk({ data: {} }) });
		await expect(startMoneroJob(c, { address: 'addr' })).rejects.toThrow(/address and viewKey/);
	});

	test('throws when NFPT returns 200 but no jobId', async () => {
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: fetchOk({ data: {} }) });
		await expect(startMoneroJob(c, { address: 'a', viewKey: 'v' })).rejects.toThrow(/no jobId/);
	});
});

describe('pollMoneroJob', () => {
	test('returns normalised snapshot on 200', async () => {
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: fetchOk({
			data: { job: {
				jobId: 'J1',
				status: 'running',
				progress: { scannedHeight: 100, chainHeight: 200, scanProgress: 0.5, percentComplete: 50 },
				balance: { totalAtomic: '1000', spendableAtomic: '900', lockedAtomic: '100' },
				error: null
			} }
		}) });
		const out = await pollMoneroJob(c, { jobId: 'J1', jobToken: 'T1' });
		expect(out.found).toBe(true);
		expect(out.snapshot.balanceAtomic).toBe('1000');
		expect(out.snapshot.spendableAtomic).toBe('900');
		expect(out.snapshot.scanProgress).toBe(0.5);
		expect(out.snapshot.percentComplete).toBe(50);
	});

	test('returns found:false on 404', async () => {
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: fetchStatus(404) });
		const out = await pollMoneroJob(c, { jobId: 'gone', jobToken: 'x' });
		expect(out).toEqual({ found: false });
	});

	test('returns found:false + forbidden on 403', async () => {
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: fetchStatus(403) });
		const out = await pollMoneroJob(c, { jobId: 'x', jobToken: 'wrong' });
		expect(out.forbidden).toBe(true);
	});

	test('throws on 500', async () => {
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: fetchStatus(500, { error: 'down' }) });
		await expect(pollMoneroJob(c, { jobId: 'J' })).rejects.toThrow(/HTTP 500/);
	});

	test('sends x-job-token header', async () => {
		const cap = captureFetch(fetchOk({ data: { job: { progress: {}, balance: {} } } }));
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: cap.fetch });
		await pollMoneroJob(c, { jobId: 'J', jobToken: 'TOK' });
		expect(cap.calls[0].init.headers['x-job-token']).toBe('TOK');
	});
});

describe('cancelMoneroJob', () => {
	test('returns cancelled:true on HTTP 200', async () => {
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: fetchStatus(200, { success: true }) });
		expect(await cancelMoneroJob(c, { jobId: 'J', jobToken: 'T' })).toEqual({ cancelled: true });
	});

	test('returns cancelled:false on 404', async () => {
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: fetchStatus(404) });
		expect(await cancelMoneroJob(c, { jobId: 'J', jobToken: 'T' })).toEqual({ cancelled: false });
	});

	test('does nothing if jobId is missing', async () => {
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: async () => { throw new Error('should not be called'); } });
		expect(await cancelMoneroJob(c, {})).toEqual({ cancelled: false });
	});
});

describe('startOrchardJob + pollOrchardJob', () => {
	test('POSTs ufvk and parses progress', async () => {
		const cap = captureFetch(fetchOk({ data: { jobId: 'J', jobToken: 'T' } }, 202));
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: cap.fetch });
		const out = await startOrchardJob(c, { ufvk: 'uview1...', birthdayHeight: 3042000 });
		expect(out).toEqual({ jobId: 'J', jobToken: 'T' });
		expect(cap.calls[0].url).toBe('http://nfpt/api/wallet-scanner/orchard/scan-ufvk/job');
		expect(JSON.parse(cap.calls[0].init.body)).toEqual({
			ufvk: 'uview1...', birthdayHeight: 3042000, endHeight: undefined, autoDetect: false
		});
	});

	test('normalises orchard notes into balance', async () => {
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: fetchOk({
			data: { job: {
				jobId: 'J',
				status: 'completed',
				progress: { percentComplete: 100, scannedToHeight: 3500000, chainTip: 3500000 },
				results: { notes: [
					{ value: '100' },
					{ value: '50' },
					{ value: '70', spent: true }
				] }
			} }
		}) });
		const out = await pollOrchardJob(c, { jobId: 'J' });
		expect(out.found).toBe(true);
		expect(out.snapshot.balanceAtomic).toBe('150');
		expect(out.snapshot.receivedAtomic).toBe('220');
		expect(out.snapshot.notes).toBe(3);
		expect(out.snapshot.unspentNotes).toBe(2);
	});
});

describe('cancelOrchardJob', () => {
	test('returns cancelled:true on 200', async () => {
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: fetchStatus(200, { success: true }) });
		expect(await cancelOrchardJob(c, { jobId: 'J' })).toEqual({ cancelled: true });
	});
});

describe('scanHistorical completion (Orchard succeeded status)', () => {
	test('breaks the poll loop on status "succeeded" without scanProgress', async () => {
		// Orchard's terminal status is 'succeeded' and the job carries no
		// fractional scanProgress, so the loop must key off the status. A
		// regression here would spin until maxWaitMs.
		const succeededJob = {
			jobId: 'J',
			status: 'succeeded',
			progress: { scannedToHeight: 3_500_000, chainTip: 3_500_000 },
			results: {
				notes: [
					{ value: '100' },
					{ value: '50' },
					{ value: '70', spent: true }
				]
			}
		};
		let getCount = 0;
		const cap = captureFetch((_url, init) => {
			if (init.method === 'POST') {
				return { status: 202, text: async () => JSON.stringify({ data: { jobId: 'J', jobToken: 'T' } }) };
			}
			if (init.method === 'DELETE') {
				return { status: 200, text: async () => JSON.stringify({ success: true }) };
			}
			getCount += 1;
			const job = getCount === 1
				? { jobId: 'J', status: 'running', progress: {}, results: { notes: [] } }
				: succeededJob;
			return { status: 200, text: async () => JSON.stringify({ data: { job } }) };
		});
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: cap.fetch });

		const res = await scanHistorical(c, {
			chain: 'zcash',
			viewKey: 'uview1...',
			includeNotes: true,
			pollIntervalMs: 5,
			maxWaitMs: 2_000
		});

		expect(res.chain).toBe('zcash');
		expect(res.totals.received_atomic).toBe('220');
		expect(res.totals.spent_atomic).toBe('70');
		expect(res.totals.balance_atomic).toBe('150');
		expect(res.notes).toHaveLength(3);
		// Completion must come from the status, not from exhausting the
		// budget: 1 running poll + 1 succeeded poll + 1 raw fetch.
		const getCalls = cap.calls.filter((x) => x.init.method === 'GET').length;
		expect(getCalls).toBeLessThanOrEqual(3);
	});

	test('throws when the job ends in a terminal failure state', async () => {
		const cap = captureFetch((_url, init) => {
			if (init.method === 'POST') {
				return { status: 202, text: async () => JSON.stringify({ data: { jobId: 'J', jobToken: 'T' } }) };
			}
			return { status: 200, text: async () => JSON.stringify({ data: { job: { jobId: 'J', status: 'cancelled', progress: {}, results: { notes: [] } } } }) };
		});
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: cap.fetch });
		await expect(scanHistorical(c, {
			chain: 'zcash', viewKey: 'uview1...', pollIntervalMs: 5, maxWaitMs: 2_000
		})).rejects.toThrow(/cancelled/);
	});
});

describe('healthCheck', () => {
	test('returns ok:true when lightwallet status is healthy', async () => {
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: fetchOk({
			success: true, data: { lightwallet: { connected: true, blockHeight: 3_400_000 } }
		}) });
		const h = await healthCheck(c);
		expect(h.ok).toBe(true);
		expect(h.lightwallet.connected).toBe(true);
	});

	test('returns ok:false on non-200', async () => {
		const c = createNfptClient({ baseUrl: 'http://nfpt', apiKey: 'k', fetchImpl: fetchStatus(500) });
		const h = await healthCheck(c);
		expect(h.ok).toBe(false);
	});
});

describe('normaliseMonero / normaliseOrchard', () => {
	test('normaliseMonero handles missing balance', () => {
		const out = normaliseMonero({ status: 'running', progress: { scannedHeight: 1, chainHeight: 2, scanProgress: 0.5 } });
		expect(out.chain).toBe('monero');
		expect(out.balanceAtomic).toBeNull();
		expect(out.percentComplete).toBe(50);
	});

	test('normaliseOrchard returns 0 balance on empty notes', () => {
		const out = normaliseOrchard({ status: 'running', progress: {}, results: { notes: [] } });
		expect(out.chain).toBe('zcash');
		expect(out.balanceAtomic).toBe('0');
		expect(out.notes).toBe(0);
	});
});
