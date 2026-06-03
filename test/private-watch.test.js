// Tests for the pure-function business logic in private-watch.js.
// All inputs/outputs are plain JS objects; no DB, no network. Covers
// validation (happy + bad paths), SSRF guard (sync + DNS-aware),
// balance diffing, and webhook payload shape.

import { describe, test, expect } from '@jest/globals';

import {
	validateWatchRequest,
	validateTopupRequest,
	validateHistoricalRequest,
	validateDeriveRequest,
	resolveAndValidateWatchRequest,
	assertWebhookUrlSafe,
	assertWebhookHostResolvesPublic,
	diffBalance,
	buildWebhookBody,
	buildLowCreditBody,
	buildCreditBlock,
	buildWatchSummary,
	buildPrivateInfo,
	buildSyntheticTestBody,
	applyDayCharge,
	applyCallCharge,
	applyTopup,
	atomicToUsdString,
	daysRemainingFromCredit,
	WATCH_CONSTANTS
} from '../src/private-watch.js';

const XMR_ADDR = '4' + 'A'.repeat(94);
const XMR_VK = '5'.repeat(64);
const ZEC_UADDR = 'u1' + 'q'.repeat(100);
const ZEC_UFVK = 'uview1' + 'q'.repeat(400);

describe('validateWatchRequest — monero', () => {
	test('accepts a well-formed request', () => {
		const out = validateWatchRequest({
			chain: 'monero',
			address: XMR_ADDR,
			viewKey: XMR_VK,
			webhookUrl: 'https://example.com/hook'
		});
		expect(out.chain).toBe('monero');
		// Monero default has no NU6-like floor: scanner starts from
		// current tip when birthdayHeight is absent.
		expect(out.birthdayHeight).toBeNull();
	});

	test('accepts an explicit birthdayHeight for monero', () => {
		const out = validateWatchRequest({
			chain: 'monero',
			address: XMR_ADDR,
			viewKey: XMR_VK,
			webhookUrl: 'https://example.com/hook',
			birthdayHeight: 3_200_000
		});
		expect(out.birthdayHeight).toBe(3_200_000);
	});

	test('silently ignores positive durationDays (back-compat for old clients)', () => {
		for (const d of [7, 14, 30, 100]) {
			expect(() => validateWatchRequest({
				chain: 'monero', address: XMR_ADDR, viewKey: XMR_VK,
				webhookUrl: 'https://example.com/hook',
				durationDays: d
			})).not.toThrow();
		}
	});

	test('rejects clearly-nonsense durationDays values', () => {
		for (const bad of [0, -1, 'oops']) {
			expect(() => validateWatchRequest({
				chain: 'monero', address: XMR_ADDR, viewKey: XMR_VK,
				webhookUrl: 'https://example.com/hook',
				durationDays: bad
			})).toThrow(/durationDays is deprecated/);
		}
	});

	test('rejects a short monero address', () => {
		expect(() => validateWatchRequest({
			chain: 'monero',
			address: '4short',
			viewKey: XMR_VK,
			webhookUrl: 'https://example.com/hook'
		})).toThrow(/monero address/);
	});

	test('rejects a non-hex view key', () => {
		expect(() => validateWatchRequest({
			chain: 'monero',
			address: XMR_ADDR,
			viewKey: 'not-hex-at-all',
			webhookUrl: 'https://example.com/hook'
		})).toThrow(/viewKey must be 64 hex/);
	});

	test('rejects birthdayHeight above the bound', () => {
		expect(() => validateWatchRequest({
			chain: 'monero',
			address: XMR_ADDR,
			viewKey: XMR_VK,
			webhookUrl: 'https://example.com/hook',
			birthdayHeight: WATCH_CONSTANTS.MAX_BIRTHDAY_HEIGHT + 1
		})).toThrow(/birthdayHeight/);
	});
});

describe('validateWatchRequest — zcash', () => {
	test('defaults birthdayHeight to NU6 when omitted', () => {
		const out = validateWatchRequest({
			chain: 'zcash',
			address: ZEC_UADDR,
			viewKey: ZEC_UFVK,
			webhookUrl: 'https://example.com/hook'
		});
		expect(out.birthdayHeight).toBe(WATCH_CONSTANTS.ZCASH_NU6_HEIGHT);
	});

	test('accepts an explicit birthdayHeight below MAX', () => {
		const out = validateWatchRequest({
			chain: 'zcash',
			address: ZEC_UADDR,
			viewKey: ZEC_UFVK,
			webhookUrl: 'https://example.com/hook',
			birthdayHeight: 3_042_000
		});
		expect(out.birthdayHeight).toBe(3_042_000);
	});

	test('rejects non-UFVK view key', () => {
		expect(() => validateWatchRequest({
			chain: 'zcash',
			address: ZEC_UADDR,
			viewKey: 'sk-something',
			webhookUrl: 'https://example.com/hook'
		})).toThrow(/UFVK/);
	});

	test('rejects negative birthdayHeight', () => {
		expect(() => validateWatchRequest({
			chain: 'zcash',
			address: ZEC_UADDR,
			viewKey: ZEC_UFVK,
			webhookUrl: 'https://example.com/hook',
			birthdayHeight: -1
		})).toThrow(/birthdayHeight/);
	});
});

describe('assertWebhookUrlSafe — scheme + literal IPv4', () => {
	const valid = ['https://example.com/hook', 'http://example.com/hook', 'https://sub.domain.io/path?x=1'];
	for (const u of valid) {
		test(`accepts ${u}`, () => {
			expect(() => assertWebhookUrlSafe(u)).not.toThrow();
		});
	}

	const banned = [
		'http://localhost/',
		'http://127.0.0.1:6379',
		'http://0.0.0.0/',
		'http://169.254.169.254/latest/meta-data',
		'http://10.0.0.5/',
		'http://192.168.1.1/x',
		'http://172.16.0.1/',
		'http://172.31.0.1/',
		'http://100.64.0.1/' // RFC6598 CGNAT
	];
	for (const u of banned) {
		test(`rejects ${u}`, () => {
			expect(() => assertWebhookUrlSafe(u)).toThrow();
		});
	}

	test('rejects ftp scheme', () => {
		expect(() => assertWebhookUrlSafe('ftp://example.com/')).toThrow(/protocol/);
	});

	test('rejects garbage', () => {
		expect(() => assertWebhookUrlSafe('not a url')).toThrow();
	});

	test('allows private addresses when allowPrivate', () => {
		expect(() => assertWebhookUrlSafe('http://127.0.0.1/', { allowPrivate: true })).not.toThrow();
	});

	test('rejects over-length URL', () => {
		const big = 'https://example.com/' + 'a'.repeat(WATCH_CONSTANTS.WEBHOOK_URL_MAX_LEN);
		expect(() => assertWebhookUrlSafe(big)).toThrow(/exceeds/);
	});

	test('rejects URL with embedded credentials', () => {
		expect(() => assertWebhookUrlSafe('https://user:pw@example.com/'))
			.toThrow(/userinfo/);
	});

	test('rejects http when requireHttps is set', () => {
		expect(() => assertWebhookUrlSafe('http://example.com/', { requireHttps: true }))
			.toThrow(/https:\/\//);
		expect(() => assertWebhookUrlSafe('https://example.com/', { requireHttps: true }))
			.not.toThrow();
	});
});

describe('assertWebhookUrlSafe — IPv6 literals', () => {
	const badV6 = [
		'http://[::1]/',
		'http://[::]/',
		'http://[fe80::1]/',
		'http://[fc00::1]/',
		'http://[fd00::1234]/',
		'http://[::ffff:127.0.0.1]/' // v4-mapped loopback
	];
	for (const u of badV6) {
		test(`rejects ${u}`, () => {
			expect(() => assertWebhookUrlSafe(u)).toThrow(/(IPv6|not allowed)/);
		});
	}

	test('accepts a globally-routable IPv6 host', () => {
		expect(() => assertWebhookUrlSafe('http://[2606:4700::1]/')).not.toThrow();
	});
});

describe('assertWebhookHostResolvesPublic', () => {
	function makeResolver(map4 = {}, map6 = {}) {
		return {
			async resolve4(host) {
				if (host in map4) return map4[host];
				const err = new Error('no A'); err.code = 'ENODATA'; throw err;
			},
			async resolve6(host) {
				if (host in map6) return map6[host];
				const err = new Error('no AAAA'); err.code = 'ENODATA'; throw err;
			}
		};
	}

	test('accepts a host that resolves to a public IPv4', async () => {
		const resolver = makeResolver({ 'example.com': ['93.184.216.34'] });
		await expect(assertWebhookHostResolvesPublic('https://example.com/x', { resolver }))
			.resolves.toBeUndefined();
	});

	test('rejects DNS rebind to 127.0.0.1', async () => {
		const resolver = makeResolver({ 'evil.example.com': ['127.0.0.1'] });
		await expect(assertWebhookHostResolvesPublic('https://evil.example.com/x', { resolver }))
			.rejects.toThrow(/private IPv4 127\.0\.0\.1/);
	});

	test('rejects DNS rebind to private IPv6', async () => {
		const resolver = makeResolver({}, { 'evil6.example.com': ['fc00::1'] });
		await expect(assertWebhookHostResolvesPublic('https://evil6.example.com/x', { resolver }))
			.rejects.toThrow(/private IPv6/);
	});

	test('skips DNS lookup if hostname is already a literal IP', async () => {
		// resolver would throw if called; literal IPs short-circuit.
		const resolver = {
			resolve4() { throw new Error('should not be called'); },
			resolve6() { throw new Error('should not be called'); }
		};
		await expect(assertWebhookHostResolvesPublic('http://93.184.216.34/x', { resolver }))
			.resolves.toBeUndefined();
	});
});

describe('resolveAndValidateWatchRequest', () => {
	test('passes when DNS resolves to public IPs', async () => {
		const resolver = {
			resolve4: async () => ['93.184.216.34'],
			resolve6: async () => { const e = new Error('na'); e.code = 'ENODATA'; throw e; }
		};
		const out = await resolveAndValidateWatchRequest({
			chain: 'monero', address: XMR_ADDR, viewKey: XMR_VK,
			webhookUrl: 'https://example.com/hook'
		}, { resolver });
		expect(out.chain).toBe('monero');
	});

	test('fails on DNS-resolved private IP', async () => {
		const resolver = {
			resolve4: async () => ['10.0.0.5'],
			resolve6: async () => { const e = new Error('na'); e.code = 'ENODATA'; throw e; }
		};
		await expect(resolveAndValidateWatchRequest({
			chain: 'monero', address: XMR_ADDR, viewKey: XMR_VK,
			webhookUrl: 'https://attacker.example/hook'
		}, { resolver })).rejects.toThrow(/private IPv4/);
	});

	test('skips DNS check when allowPrivateWebhooks is set', async () => {
		const resolver = { resolve4: async () => ['10.0.0.5'], resolve6: async () => [] };
		const out = await resolveAndValidateWatchRequest({
			chain: 'monero', address: XMR_ADDR, viewKey: XMR_VK,
			webhookUrl: 'http://127.0.0.1/hook'
		}, { resolver, allowPrivateWebhooks: true });
		expect(out.webhookUrl).toBe('http://127.0.0.1/hook');
	});
});

describe('diffBalance', () => {
	test('returns null when there is no change', () => {
		const a = { balanceAtomic: '100', scannedHeight: 5, error: null };
		const b = { balanceAtomic: '100', scannedHeight: 5, error: null };
		expect(diffBalance(a, b)).toBeNull();
	});

	test('reports balance increase', () => {
		const before = { balanceAtomic: '100', scannedHeight: 5, error: null };
		const after = { balanceAtomic: '300', scannedHeight: 6, error: null };
		const d = diffBalance(before, after);
		expect(d.changed).toBe(true);
		expect(d.balance_changed).toBe(true);
		expect(d.delta_atomic).toBe('200');
		expect(d.before_atomic).toBe('100');
		expect(d.after_atomic).toBe('300');
	});

	test('reports first-complete scan even on zero balance', () => {
		const after = { balanceAtomic: '0', scannedHeight: 10, status: 'completed', scanProgress: 1, error: null };
		const d = diffBalance(null, after);
		expect(d).toBeTruthy();
		expect(d.first_complete).toBe(true);
		expect(d.delta_atomic).toBe('0');
	});

	test('reports error transitions', () => {
		const before = { balanceAtomic: '100', error: null };
		const after = { balanceAtomic: '100', error: 'lws: timeout' };
		const d = diffBalance(before, after);
		expect(d).toBeTruthy();
		expect(d.error_changed).toBe(true);
		expect(d.balance_changed).toBe(false);
	});

	test('returns null when after is null', () => {
		expect(diffBalance({}, null)).toBeNull();
	});
});

describe('buildWebhookBody', () => {
	test('serialises a balance_change payload', () => {
		const body = buildWebhookBody({
			watchId: 'w1',
			chain: 'monero',
			address: XMR_ADDR,
			before: { balanceAtomic: '100', chain: 'monero' },
			after: { balanceAtomic: '300', chain: 'monero', status: 'completed' },
			diff: {
				balance_changed: true,
				first_complete: false,
				delta_atomic: '200',
				before_atomic: '100',
				after_atomic: '300'
			},
			nowMs: 1_700_000_000_000
		});
		const obj = JSON.parse(body);
		expect(obj.event).toBe('balance_change');
		expect(obj.watchId).toBe('w1');
		expect(obj.chain).toBe('monero');
		expect(obj.delta.balance_atomic).toBe('200');
		expect(obj.timestamp).toBe(new Date(1_700_000_000_000).toISOString());
	});

	test('classifies a first-complete event', () => {
		const body = buildWebhookBody({
			watchId: 'w1',
			chain: 'zcash',
			address: ZEC_UADDR,
			before: null,
			after: { balanceAtomic: '0', chain: 'zcash', status: 'completed' },
			diff: { balance_changed: false, first_complete: true, delta_atomic: '0', before_atomic: '0', after_atomic: '0' }
		});
		const obj = JSON.parse(body);
		expect(obj.event).toBe('scan_complete');
		expect(obj.previous).toBeNull();
	});
});

describe('buildSyntheticTestBody', () => {
	test('returns a valid signed-payload-shaped JSON marked synthetic', () => {
		const body = buildSyntheticTestBody({
			watchId: 'w1', chain: 'monero', address: XMR_ADDR, nowMs: 1_700_000_000_000
		});
		const obj = JSON.parse(body);
		expect(obj.event).toBe('synthetic_test');
		expect(obj.watchId).toBe('w1');
		expect(obj.timestamp).toBe(new Date(1_700_000_000_000).toISOString());
		expect(obj.delta.balance_atomic).toBe('0');
		expect(obj.current.note).toMatch(/synthetic test event/);
	});
});

describe('buildWatchSummary', () => {
	test('strips sensitive fields and keeps state counters + credit block', () => {
		const row = {
			id: 'w1',
			token_hash: 'abc',
			view_key_ct: 'should-not-leak',
			webhook_url: 'https://secret.example/hook',
			webhook_secret: 'top-secret',
			chain: 'monero',
			created_at_ms: 1000,
			expires_at_ms: 8_000,
			cancelled: 0,
			dead: 0,
			delivery_attempts: 2,
			delivery_count: 5,
			last_polled_at_ms: 7000,
			last_delivered_at_ms: 6000,
			last_delivered_event: 'balance_change',
			last_delivery_error: 'old timeout',
			credit_atomic: 95_000,
			credit_billed_atomic: 5_000,
			credit_topups_atomic: 100_000,
			last_known_balance: '{"balanceAtomic":"1"}',
			last_delivered_balance: '{"balanceAtomic":"0"}'
		};
		const out = buildWatchSummary(row, { nowMs: 4000, pollIntervalSec: 180 });
		expect(out.watchId).toBe('w1');
		expect(out.expires_in_ms).toBe(4000);
		expect(out.delivery_count).toBe(5);
		expect(out.last_delivered_event).toBe('balance_change');
		expect(out.next_poll_eta_ms).toBe((7000 + 180_000) - 4000);
		expect(out.last_known_balance).toEqual({ balanceAtomic: '1' });
		expect(out.state).toBe('active');
		expect(out.credit.remaining_atomic).toBe('95000');
		expect(out.credit.billed_atomic).toBe('5000');
		expect(out).not.toHaveProperty('view_key_ct');
		expect(out).not.toHaveProperty('webhook_secret');
		expect(out).not.toHaveProperty('webhook_url');
		expect(JSON.stringify(out)).not.toContain('top-secret');
		expect(JSON.stringify(out)).not.toContain('secret.example');
	});

	test('reports out_of_credit state when credit_atomic = 0', () => {
		const row = {
			id: 'w1', chain: 'monero',
			created_at_ms: 1000, expires_at_ms: 1500,
			cancelled: 0, dead: 0,
			credit_atomic: 0, credit_billed_atomic: 100_000, credit_topups_atomic: 100_000,
			delivery_attempts: 0, delivery_count: 0,
			last_polled_at_ms: 2000,
			last_known_balance: null, last_delivered_balance: null
		};
		const out = buildWatchSummary(row, { nowMs: 4000, pollIntervalSec: 180 });
		expect(out.state).toBe('out_of_credit');
		expect(out.out_of_credit).toBe(true);
		expect(out.credit.days_remaining_if_idle).toBe(0);
	});

	test('next_poll_eta_ms is null before first poll', () => {
		const row = {
			id: 'w1', chain: 'monero',
			created_at_ms: 1000, expires_at_ms: 8_000,
			cancelled: 0, dead: 0,
			delivery_attempts: 0, delivery_count: 0,
			credit_atomic: 50_000, credit_billed_atomic: 0, credit_topups_atomic: 50_000,
			last_polled_at_ms: null,
			last_known_balance: null, last_delivered_balance: null
		};
		const out = buildWatchSummary(row, { nowMs: 4000, pollIntervalSec: 60 });
		expect(out.next_poll_eta_ms).toBeNull();
	});
});

describe('buildPrivateInfo', () => {
	test('reflects paywall configuration + chain support + credit-meter fields', () => {
		const info = buildPrivateInfo({
			x402Cfg: {
				enabled: true,
				routes: {
					'POST /v1/private/watch': { accepts: { price: '$0.10' } },
					'POST /v1/private/topup': { accepts: { price: '$0.10' } },
					'POST /v1/private/topup-1': { accepts: { price: '$1.00' } },
					'POST /v1/private/topup-5': { accepts: { price: '$5.00' } },
					'POST /v1/private/historical': { accepts: { price: '$0.50' } }
				}
			},
			nfptHealth: { ok: true },
			requireHttps: true
		});
		expect(info.chains).toEqual(['monero', 'zcash']);
		expect(info.pricing.model).toMatch(/credit meter/);
		expect(info.pricing.rate_per_day_atomic).toBe(String(WATCH_CONSTANTS.DAY_RATE_ATOMIC));
		expect(info.pricing.rate_per_call_atomic).toBe(String(WATCH_CONSTANTS.CALL_RATE_ATOMIC));
		expect(info.pricing.starter_credit_atomic).toBe(String(WATCH_CONSTANTS.STARTER_CREDIT_ATOMIC));
		expect(info.pricing.watch_creation).toBe('$0.10');
		expect(info.pricing.topup_tiers).toHaveLength(3);
		expect(info.pricing.historical_lookup.price).toBe('$0.50');
		expect(info.pricing.derive_viewkey.price).toMatch(/free/);
		expect(info.paywall_enabled).toBe(true);
		expect(info.security.webhook_url_scheme).toBe('https only');
		expect(info.security.webhook_ssrf_guard).toMatch(/DNS-resolved/);
		expect(info.security.historical_view_key_handling).toMatch(/in-memory only/);
		expect(info.upstream).toEqual({ ok: true });
	});

	test('handles disabled paywall + http allowed', () => {
		const info = buildPrivateInfo({
			x402Cfg: { enabled: false },
			nfptHealth: { ok: false },
			requireHttps: false
		});
		expect(info.pricing.watch_creation).toBeNull();
		expect(info.paywall_enabled).toBe(false);
		expect(info.security.webhook_url_scheme).toBe('http or https');
	});
});

// ── Credit meter ──────────────────────────────────────────────────

describe('atomicToUsdString', () => {
	test('formats round dollars', () => {
		expect(atomicToUsdString(1_000_000)).toBe('1');
		expect(atomicToUsdString(0)).toBe('0');
	});

	test('trims trailing zeros', () => {
		expect(atomicToUsdString(20_000)).toBe('0.02');
		expect(atomicToUsdString(5_000)).toBe('0.005');
	});

	test('handles negatives', () => {
		expect(atomicToUsdString(-100_000)).toBe('-0.1');
	});
});

describe('daysRemainingFromCredit', () => {
	test('balance / day-rate', () => {
		expect(daysRemainingFromCredit(100_000)).toBe(5);
		expect(daysRemainingFromCredit(0)).toBe(0);
	});

	test('zero day-rate is treated as no time remaining', () => {
		expect(daysRemainingFromCredit(100_000, 0)).toBe(0);
	});
});

describe('buildCreditBlock', () => {
	test('reflects current balance, rates, and low-credit flag', () => {
		const block = buildCreditBlock({
			credit_atomic: 30_000,
			credit_billed_atomic: 5_000,
			credit_topups_atomic: 100_000
		});
		expect(block.remaining_atomic).toBe('30000');
		expect(block.remaining_usd).toBe('0.03');
		expect(block.rate_per_day_atomic).toBe(String(WATCH_CONSTANTS.DAY_RATE_ATOMIC));
		expect(block.rate_per_call_atomic).toBe(String(WATCH_CONSTANTS.CALL_RATE_ATOMIC));
		expect(block.days_remaining_if_idle).toBeCloseTo(1.5, 3);
		expect(block.low_credit).toBe(true);  // 30_000 < 40_000 threshold
	});

	test('clears low_credit flag well above threshold', () => {
		const block = buildCreditBlock({
			credit_atomic: 1_000_000,
			credit_billed_atomic: 0,
			credit_topups_atomic: 1_000_000
		});
		expect(block.low_credit).toBe(false);
	});

	test('returns null for missing row', () => {
		expect(buildCreditBlock(null)).toBeNull();
	});
});

describe('applyDayCharge', () => {
	test('charges proportionally to elapsed time', () => {
		const row = {
			credit_atomic: 100_000,
			credit_billed_atomic: 0,
			credit_last_billed_ms: 1_000_000,
			created_at_ms: 1_000_000
		};
		// 12 hours = 0.5 days at $0.02/day = 10_000 atomic.
		const patch = applyDayCharge(row, 1_000_000 + 12 * 3_600_000);
		expect(patch.chargeAtomic).toBe(10_000);
		expect(patch.credit_atomic).toBe(90_000);
		expect(patch.credit_billed_atomic).toBe(10_000);
		expect(patch.credit_last_billed_ms).toBe(1_000_000 + 12 * 3_600_000);
		// Expires-at projected from REMAINING credit, not original.
		// 90_000 / 20_000 = 4.5 days remaining from nowMs.
		expect(patch.expires_at_ms).toBe(1_000_000 + 12 * 3_600_000 + 4.5 * 86_400_000);
	});

	test('charges nothing when zero time has elapsed', () => {
		const row = {
			credit_atomic: 100_000,
			credit_billed_atomic: 0,
			credit_last_billed_ms: 1_000_000
		};
		const patch = applyDayCharge(row, 1_000_000);
		expect(patch.chargeAtomic).toBe(0);
	});

	test('cannot drive credit below zero', () => {
		const row = {
			credit_atomic: 1_000,
			credit_billed_atomic: 0,
			credit_last_billed_ms: 1_000_000
		};
		// 10 days elapsed @ $0.02/day = 200_000 charge but only 1_000 left.
		const patch = applyDayCharge(row, 1_000_000 + 10 * 86_400_000);
		expect(patch.credit_atomic).toBe(0);
		// chargeAtomic is the full computed amount; the SQL UPDATE
		// caps via Math.max(0, …) inside the patch.
		expect(patch.chargeAtomic).toBe(200_000);
	});
});

describe('applyCallCharge', () => {
	test('debits CALL_RATE_ATOMIC', () => {
		const row = {
			credit_atomic: 100_000,
			credit_billed_atomic: 0
		};
		const patch = applyCallCharge(row, 1_000_000);
		expect(patch.chargeAtomic).toBe(WATCH_CONSTANTS.CALL_RATE_ATOMIC);
		expect(patch.credit_atomic).toBe(100_000 - WATCH_CONSTANTS.CALL_RATE_ATOMIC);
	});
});

describe('applyTopup', () => {
	test('adds credit and resets low_credit_warned above threshold', () => {
		const row = { credit_atomic: 5_000, credit_topups_atomic: 100_000, low_credit_warned: 1 };
		const patch = applyTopup(row, 1_000_000, 1_700_000_000_000);
		expect(patch.credit_atomic).toBe(1_005_000);
		expect(patch.credit_topups_atomic).toBe(1_100_000);
		expect(patch.low_credit_warned).toBe(0);
	});

	test('keeps low_credit_warned set if top-up stays under threshold', () => {
		const row = { credit_atomic: 5_000, credit_topups_atomic: 100_000, low_credit_warned: 1 };
		// Add only 1 atomic — still below 40_000 threshold.
		const patch = applyTopup(row, 1, 1_700_000_000_000);
		expect(patch.low_credit_warned).toBe(1);
	});

	test('caps expires_at at maxLifetimeMs', () => {
		const row = { credit_atomic: 0, credit_topups_atomic: 0, low_credit_warned: 0 };
		// Huge top-up — naive expiry far in future. Should clamp.
		const patch = applyTopup(row, 100_000_000_000, 1_000, {
			maxLifetimeMs: 365 * 86_400_000
		});
		expect(patch.expires_at_ms).toBe(1_000 + 365 * 86_400_000);
	});

	test('rejects non-positive credit', () => {
		expect(() => applyTopup({}, 0, 1)).toThrow(/positive integer/);
		expect(() => applyTopup({}, -1, 1)).toThrow(/positive integer/);
	});
});

describe('buildLowCreditBody', () => {
	test('emits a low_credit event with credit block', () => {
		const body = buildLowCreditBody({
			watchId: 'w1', chain: 'monero', address: XMR_ADDR,
			row: { credit_atomic: 30_000, credit_billed_atomic: 70_000, credit_topups_atomic: 100_000 },
			nowMs: 1_700_000_000_000
		});
		const parsed = JSON.parse(body);
		expect(parsed.event).toBe('low_credit');
		expect(parsed.credit.remaining_atomic).toBe('30000');
		expect(parsed.credit.low_credit).toBe(true);
		expect(parsed.previous).toBeNull();
		expect(parsed.current).toBeNull();
	});
});

describe('buildWebhookBody — credit block embedded', () => {
	test('regular balance change webhook carries credit info', () => {
		const before = { chain: 'monero', balanceAtomic: '0', status: 'completed' };
		const after = { chain: 'monero', balanceAtomic: '100', status: 'completed' };
		const diff = diffBalance(before, after);
		const body = buildWebhookBody({
			watchId: 'w1', chain: 'monero', address: XMR_ADDR,
			before, after, diff,
			row: { credit_atomic: 95_000, credit_billed_atomic: 5_000, credit_topups_atomic: 100_000 },
			nowMs: 1_700_000_000_000
		});
		const parsed = JSON.parse(body);
		expect(parsed.event).toBe('balance_change');
		expect(parsed.credit.remaining_atomic).toBe('95000');
		expect(parsed.credit.billed_atomic).toBe('5000');
	});
});

// ── New validators ────────────────────────────────────────────────

describe('validateTopupRequest', () => {
	test('accepts UUID + token', () => {
		const out = validateTopupRequest({
			watchId: '550e8400-e29b-41d4-a716-446655440000',
			watchToken: 'abc123'
		});
		expect(out.watchId).toBe('550e8400-e29b-41d4-a716-446655440000');
	});

	test('rejects non-UUID watchId', () => {
		expect(() => validateTopupRequest({ watchId: 'nope', watchToken: 't' })).toThrow(/UUID/);
	});

	test('rejects missing watchToken', () => {
		expect(() => validateTopupRequest({ watchId: '550e8400-e29b-41d4-a716-446655440000' })).toThrow(/watchToken/);
	});
});

describe('validateHistoricalRequest', () => {
	test('accepts a chain + credentials + optional toHeight', () => {
		const out = validateHistoricalRequest({
			chain: 'zcash',
			address: ZEC_UADDR,
			viewKey: ZEC_UFVK,
			toHeight: 3_500_000,
			includeNotes: true
		});
		expect(out.chain).toBe('zcash');
		expect(out.toHeight).toBe(3_500_000);
		expect(out.includeNotes).toBe(true);
		// Zcash defaults birthdayHeight to NU6.
		expect(out.birthdayHeight).toBe(WATCH_CONSTANTS.ZCASH_NU6_HEIGHT);
	});

	test('defaults includeNotes to false', () => {
		const out = validateHistoricalRequest({
			chain: 'monero', address: XMR_ADDR, viewKey: XMR_VK
		});
		expect(out.includeNotes).toBe(false);
	});

	test('rejects out-of-range toHeight', () => {
		expect(() => validateHistoricalRequest({
			chain: 'zcash', address: ZEC_UADDR, viewKey: ZEC_UFVK,
			toHeight: -1
		})).toThrow(/toHeight/);
	});
});

describe('validateDeriveRequest', () => {
	const phrase24 = Array(24).fill('abandon').join(' ');
	const phrase12 = Array(12).fill('abandon').join(' ');

	test('accepts 24-word mnemonic for zcash', () => {
		const out = validateDeriveRequest({ chain: 'zcash', phrase: phrase24 });
		expect(out.wordCount).toBe(24);
		expect(out.network).toBe('mainnet');
	});

	test('accepts 12-word mnemonic too', () => {
		const out = validateDeriveRequest({ chain: 'zcash', phrase: phrase12 });
		expect(out.wordCount).toBe(12);
	});

	test('rejects monero (not supported yet)', () => {
		expect(() => validateDeriveRequest({ chain: 'monero', phrase: phrase24 })).toThrow(/Zcash/);
	});

	test('rejects wrong word count', () => {
		expect(() => validateDeriveRequest({ chain: 'zcash', phrase: 'one two three' })).toThrow(/12- or 24-word/);
	});

	test('rejects missing phrase', () => {
		expect(() => validateDeriveRequest({ chain: 'zcash' })).toThrow(/phrase is required/);
	});

	test('rejects oversized phrase', () => {
		expect(() => validateDeriveRequest({ chain: 'zcash', phrase: 'a'.repeat(500) })).toThrow(/400 characters/);
	});

	test('normalises double-spaces', () => {
		const out = validateDeriveRequest({ chain: 'zcash', phrase: '  abandon   ' + Array(23).fill('abandon').join(' ') });
		expect(out.wordCount).toBe(24);
		expect(out.phrase).not.toMatch(/\s{2,}/);
	});
});
