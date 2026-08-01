// Private-watch business logic.
//
// The data-api now speaks NINE surfaces around watches:
//
//   POST   /v1/private/watch                 — $0.10, creates a watch with starter credit
//   GET    /v1/private/watch/:id             — owner-only, status + credit
//   DELETE /v1/private/watch/:id             — owner-only, cancels
//   POST   /v1/private/watch/:id/test        — owner-only, fires a synthetic webhook
//   POST   /v1/private/topup                 — $0.10, adds 100_000 atomic credit
//   POST   /v1/private/topup-1               — $1.00, adds 1_000_000 atomic credit
//   POST   /v1/private/topup-5               — $5.00, adds 5_000_000 atomic credit
//   POST   /v1/private/historical            — $0.50, one-off scan (notes returned, view key NOT stored)
//   POST   /v1/private/derive-viewkey        — FREE (rate-limited), Zcash UFVK from BIP-39 mnemonic
//   GET    /v1/private/info                  — free, lists prices + chains
//   GET    /v1/private/health                — free, counters only (no PII)
//
// Watches use a prepaid credit meter (`credit_atomic` in atomic USDC),
// debited per-day idle + per-webhook delivered. The receiver sees the
// remaining balance + projected expiry on every webhook body. When
// the meter crosses LOW_CREDIT_THRESHOLD_ATOMIC we fire one
// `low_credit` webhook so the receiver can top up before it runs dry.
//
// Everything in this module is pure: it validates inputs, builds
// records, and computes balance diffs. The side-effecty bits (DB
// writes, NFPT HTTP calls, webhook POSTs) live in the route handlers
// and the poller, so unit tests can exercise the contract without
// touching the network.
//
// SSRF rules: we accept user-supplied webhook URLs but defend against
// using them to probe our LAN. Three layers, in this file:
//   1. URL syntax + scheme allowlist (http/https only)
//   2. Hostname blocklist (loopback, metadata IPs, FORBIDDEN_HOSTNAMES)
//   3. IPv4 + IPv6 private-range checks on the literal hostname
// At creation time the rest-server.js handler additionally runs an
// async DNS lookup (see `resolveAndAssertWebhookSafe`) so a name like
// `evil.example.com` that resolves to 127.0.0.1 is also blocked.

import { URL } from 'node:url';
import { promises as dns } from 'node:dns';

// ── Tunables ─────────────────────────────────────────────────────

export const WATCH_CONSTANTS = Object.freeze({
	// Credit-based pricing. Watches hold a prepaid balance in atomic
	// USDC units (1 USDC = 10^6 atomic). The poller debits per-day
	// and per-call rates; when the balance dips below a threshold we
	// fire a one-shot `low_credit` webhook so the receiver can top
	// up before the meter hits zero. Round numbers chosen so the
	// "$X.XX per day" maths is obvious to anyone reading the docs.
	DAY_RATE_ATOMIC: 20_000,       // $0.02 / day idle
	CALL_RATE_ATOMIC: 5_000,       // $0.005 / webhook delivered
	// What a top-up tier buys, all in atomic USDC. The same constants
	// are referenced by x402.js so the marketing copy and the
	// settlement path can never drift.
	TOPUP_10C_ATOMIC: 100_000,     // $0.10  → 5 idle days
	TOPUP_1_ATOMIC: 1_000_000,     // $1.00  → 50 idle days
	TOPUP_5_ATOMIC: 5_000_000,     // $5.00  → 250 idle days
	// Starter credit attached to a fresh watch. Matches the $0.10
	// creation paywall so the user gets exactly what they paid for
	// the first time and can top up afterwards in any tier.
	STARTER_CREDIT_ATOMIC: 100_000,
	// Fire a `low_credit` webhook when remaining credit drops below
	// this many atomic units. 40_000 = $0.04 = 2 idle days at the
	// current DAY_RATE. Enough lead time for a top-up to land before
	// the meter actually expires.
	LOW_CREDIT_THRESHOLD_ATOMIC: 40_000,
	// Historical lookup price (one-off, doesn't persist anything).
	HISTORICAL_PRICE_ATOMIC: 500_000, // $0.50
	// Hard cap on how many notes we'll return from a historical
	// scan. Stops a huge wallet from returning a megabyte of JSON.
	HISTORICAL_MAX_NOTES: 5_000,
	// Poll cadence — NFPT detaches a scanner after 5 min idle, so we
	// stay comfortably under that ceiling.
	DEFAULT_POLL_INTERVAL_SEC: 180,
	// How many consecutive webhook failures before we give up.
	// 50 attempts × 3-min poll ≈ 2.5 h of failures, which is enough
	// for a brief outage but short enough that a wrongly-configured
	// receiver doesn't pin a poller slot forever.
	MAX_DELIVERY_ATTEMPTS: 50,
	// Maximum lifetime any single watch may hold credit for. Beyond
	// this (~1 year) we'd rather the user re-create than have a row
	// sit around for a decade. Tunable via env if anyone complains.
	MAX_WATCH_LIFETIME_MS: 365 * 86_400_000,
	// Schema bounds we sanity-check user input against.
	XMR_VIEWKEY_HEX_LEN: 64,
	XMR_ADDRESS_MIN_LEN: 90,
	XMR_ADDRESS_MAX_LEN: 110,
	ZEC_UFVK_PREFIX: 'uview1',
	ZEC_ADDRESS_PREFIXES: Object.freeze(['u1', 't1', 't3', 'zs1', 'u1q']),
	WEBHOOK_BODY_MAX_BYTES: 64 * 1024,
	WEBHOOK_URL_MAX_LEN: 2048,
	// Maximum bytes we'll buffer from a webhook response before
	// abandoning the read. Receivers should `200 OK` with a tiny
	// body; misbehaving ones can't tie up our poller with megabytes.
	WEBHOOK_RESPONSE_MAX_BYTES: 4 * 1024,
	// Bounds for the optional birthday/from-height (Monero scans back
	// to this height; Zcash starts scanning at NU6 if unspecified).
	// 50M comfortably covers Zcash mainnet (~3.5M) and Monero (~3.4M)
	// for the next decade without forcing a code change.
	MAX_BIRTHDAY_HEIGHT: 50_000_000,
	// Zcash NU6 mainnet activation height. We use this as a sane
	// default when a caller doesn't supply birthdayHeight so we
	// don't accidentally trigger an autoDetect or full re-scan.
	ZCASH_NU6_HEIGHT: 3_042_000,
	// BIP-39 mnemonic word count expected by the NFPT scanner's
	// `derive-ufvk` command. 24 words is Orchard-standard; 12-word
	// seeds are flagged to the user with a "may not match your
	// wallet" warning.
	MNEMONIC_WORDS_ORCHARD: 24
});

// Derived helper: how many days of idle credit `remaining` buys at
// the current rates. Returns a float so a UI can show "4.3 days".
export function daysRemainingFromCredit(remainingAtomic, dayRateAtomic = WATCH_CONSTANTS.DAY_RATE_ATOMIC) {
	if (remainingAtomic <= 0 || dayRateAtomic <= 0) return 0;
	return remainingAtomic / dayRateAtomic;
}

// Format atomic USDC as a dollar string. Used in webhook bodies +
// public summaries. 6 atomic units = 0.000006 USDC, so 4 decimal
// places of precision is plenty.
export function atomicToUsdString(atomic) {
	const sign = atomic < 0 ? '-' : '';
	const abs = Math.abs(Number(atomic));
	return `${sign}${(abs / 1_000_000).toFixed(4).replace(/\.?0+$/u, '')}`;
}

// Hosts/IPs we won't deliver webhooks to. SSRF protection: agents
// pass us their callback URL and we POST to it from inside our LAN.
// A malicious caller pointing it at `http://127.0.0.1:6379` would let
// them probe our internal services. Block private ranges + the usual
// loopback aliases.
const FORBIDDEN_HOSTNAMES = new Set([
	'localhost',
	'localhost.localdomain',
	'127.0.0.1',
	'0.0.0.0',
	'::1',
	'::',
	'metadata.google.internal',
	'169.254.169.254',
	'fd00::1',
	'fe80::1'
]);

const PRIVATE_IPV4_PREFIXES = [
	/^10\./u,
	/^192\.168\./u,
	/^172\.(1[6-9]|2\d|3[0-1])\./u,
	/^127\./u,
	/^169\.254\./u,
	/^0\./u,
	/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./u // RFC6598 CGNAT 100.64.0.0/10
];

// Private IPv6 ranges per RFC4193/4291/6890. We canonicalise the
// IP first (lowercase, strip brackets) so the check is robust against
// the many ways an attacker could spell loopback ("::1", "[::1]",
// "::ffff:7f00:1" etc.).
function ipv6IsPrivate(rawAddr) {
	const addr = canonicaliseIpv6(rawAddr);
	if (addr === null) return false;
	if (addr === '::1' || addr === '::') return true;
	// fc00::/7 (unique local): first hextet starts 0xfc or 0xfd.
	if (/^fc[0-9a-f]{2}:|^fd[0-9a-f]{2}:/u.test(addr)) return true;
	// fe80::/10 (link-local): fe80..febf.
	if (/^fe[89ab][0-9a-f]:/u.test(addr)) return true;
	// IPv4-mapped IPv6 (::ffff:0:0/96) — re-check against IPv4 ranges.
	// URL parsing normalises dotted-quad inside IPv6 to hex words, so
	// we handle both `::ffff:127.0.0.1` and `::ffff:7f00:1` forms.
	const v4 = ipv4FromMappedIpv6(addr);
	if (v4 && PRIVATE_IPV4_PREFIXES.some((re) => re.test(v4))) return true;
	return false;
}

function canonicaliseIpv6(addr) {
	if (typeof addr !== 'string') return null;
	const stripped = addr.replace(/^\[|\]$/gu, '').toLowerCase();
	if (!stripped.includes(':')) return null;
	return stripped;
}

function ipv4FromMappedIpv6(addr) {
	const mixed = addr.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/u);
	if (mixed) return mixed[1];
	const hex = addr.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/u);
	if (hex) {
		const high = Number.parseInt(hex[1], 16);
		const low = Number.parseInt(hex[2], 16);
		return [(high >> 8) & 0xff, high & 0xff, (low >> 8) & 0xff, low & 0xff].join('.');
	}
	return null;
}

// ── Public surface ───────────────────────────────────────────────

/**
 * Validate the chain + key + address half of an inbound private-API
 * request. Splitting this out lets the watch-creation, historical
 * lookup, and derive-viewkey paths share the validation rules without
 * accidentally drifting.
 */
export function validateChainCredentials(body) {
	if (!body || typeof body !== 'object') {
		throw new TypeError('request body must be an object');
	}
	const chain = String(body.chain ?? '').toLowerCase();
	if (!['monero', 'zcash'].includes(chain)) {
		throw new TypeError(`chain must be 'monero' or 'zcash' (got ${describe(body.chain)})`);
	}
	const address = String(body.address ?? '').trim();
	const viewKey = String(body.viewKey ?? '').trim();
	if (!address) throw new TypeError('address is required');
	if (!viewKey) throw new TypeError('viewKey is required');

	if (chain === 'monero') {
		if (address.length < WATCH_CONSTANTS.XMR_ADDRESS_MIN_LEN
			|| address.length > WATCH_CONSTANTS.XMR_ADDRESS_MAX_LEN
			|| !/^[1-9A-HJ-NP-Za-km-z]+$/u.test(address)) {
			throw new TypeError(`monero address looks malformed (length=${address.length})`);
		}
		if (!/^[0-9a-fA-F]+$/u.test(viewKey) || viewKey.length !== WATCH_CONSTANTS.XMR_VIEWKEY_HEX_LEN) {
			throw new TypeError(`monero viewKey must be ${WATCH_CONSTANTS.XMR_VIEWKEY_HEX_LEN} hex chars`);
		}
	}
	else {
		if (!WATCH_CONSTANTS.ZEC_ADDRESS_PREFIXES.some((p) => address.startsWith(p))) {
			throw new TypeError(`zcash address must start with one of ${WATCH_CONSTANTS.ZEC_ADDRESS_PREFIXES.join(', ')}`);
		}
		if (!viewKey.startsWith(WATCH_CONSTANTS.ZEC_UFVK_PREFIX) && !viewKey.startsWith('uview')) {
			throw new TypeError(`zcash viewKey must be a UFVK (starts with '${WATCH_CONSTANTS.ZEC_UFVK_PREFIX}')`);
		}
	}

	let birthdayHeight = null;
	if (body.birthdayHeight !== undefined && body.birthdayHeight !== null && body.birthdayHeight !== '') {
		const h = Number(body.birthdayHeight);
		if (!Number.isInteger(h) || h < 0 || h > WATCH_CONSTANTS.MAX_BIRTHDAY_HEIGHT) {
			throw new TypeError(`birthdayHeight must be an integer in [0, ${WATCH_CONSTANTS.MAX_BIRTHDAY_HEIGHT}] (got ${describe(body.birthdayHeight)})`);
		}
		birthdayHeight = h;
	}
	if (chain === 'zcash' && birthdayHeight === null) {
		// Default to NU6 — virtually all live wallets are post-April
		// 2024. Older wallets supply an explicit birthdayHeight. This
		// keeps us out of NFPT's multi-hour autoDetect path for a
		// $0.10 watch (autoDetect is fine for the explicit historical
		// route where the user expects to wait).
		birthdayHeight = WATCH_CONSTANTS.ZCASH_NU6_HEIGHT;
	}
	return { chain, address, viewKey, birthdayHeight };
}

/**
 * Validate an inbound POST /v1/private/watch body. Returns the
 * normalised input on success or throws a TypeError on failure (which
 * the rest-server error handler converts to 400).
 *
 * Inputs:
 *   { chain, address, viewKey, webhookUrl, birthdayHeight? }
 *
 * Watches now use a credit-meter (`credit_atomic` debited per-day +
 * per-call) rather than a fixed-duration tier. The caller pays the
 * x402 fee, which credits the watch with `STARTER_CREDIT_ATOMIC`;
 * subsequent top-ups go through the dedicated topup routes. We
 * deliberately ignore any `durationDays` field in the body so a
 * client that's read the old docs doesn't get confused.
 *
 * Output:
 *   { chain, address, viewKey, webhookUrl, birthdayHeight, now }
 */
export function validateWatchRequest(body, {
	now = Date.now(),
	allowPrivateWebhooks = false,
	requireHttps = false
} = {}) {
	const creds = validateChainCredentials(body);
	const webhookUrl = String(body.webhookUrl ?? '').trim();
	assertWebhookUrlSafe(webhookUrl, { allowPrivate: allowPrivateWebhooks, requireHttps });
	// We silently ignore any `durationDays` field — old clients may
	// send it. We refuse only if it's clearly nonsense (negative,
	// non-numeric) so a typo in a copy-pasted snippet doesn't appear
	// to be respected.
	if (body.durationDays !== undefined && body.durationDays !== null && body.durationDays !== '') {
		const n = Number(body.durationDays);
		if (!Number.isFinite(n) || n <= 0) {
			throw new TypeError('durationDays is deprecated; the watch runs on a credit meter — see /v1/private/info');
		}
	}
	return Object.freeze({
		...creds,
		webhookUrl,
		now
	});
}

/**
 * Validate a top-up body. Cheap structural check — the actual cost
 * is set by the x402 paywall (one paid path per tier), so the handler
 * passes us the resolved `creditAtomic` to apply.
 */
export function validateTopupRequest(body) {
	if (!body || typeof body !== 'object') {
		throw new TypeError('topup body must be an object');
	}
	const watchId = String(body.watchId ?? '').trim();
	if (!/^[0-9a-f-]{36}$/u.test(watchId)) {
		throw new TypeError('watchId must be a UUID');
	}
	const watchToken = String(body.watchToken ?? '').trim();
	if (!watchToken) {
		throw new TypeError('watchToken is required');
	}
	return Object.freeze({ watchId, watchToken });
}

/**
 * Validate a historical-lookup body. Same chain credentials as a
 * watch, plus optional `toHeight` and `includeNotes` flag (off by
 * default — the summary numbers alone are usually enough).
 */
export function validateHistoricalRequest(body) {
	const creds = validateChainCredentials(body);
	let toHeight = null;
	if (body.toHeight !== undefined && body.toHeight !== null && body.toHeight !== '') {
		const h = Number(body.toHeight);
		if (!Number.isInteger(h) || h < 0 || h > WATCH_CONSTANTS.MAX_BIRTHDAY_HEIGHT) {
			throw new TypeError(`toHeight must be an integer in [0, ${WATCH_CONSTANTS.MAX_BIRTHDAY_HEIGHT}]`);
		}
		toHeight = h;
	}
	const includeNotes = body.includeNotes === true;
	return Object.freeze({ ...creds, toHeight, includeNotes });
}

/**
 * Validate a derive-viewkey body. The phrase length is bounded so a
 * giant payload can't trip our backend, and we strip duplicate
 * whitespace before forwarding to NFPT.
 */
export function validateDeriveRequest(body) {
	if (!body || typeof body !== 'object') {
		throw new TypeError('derive body must be an object');
	}
	const chain = String(body.chain ?? '').toLowerCase();
	if (chain !== 'zcash') {
		throw new TypeError(`chain '${chain}' not supported; derive-viewkey is currently Zcash (Orchard) only`);
	}
	const phrase = String(body.phrase ?? '').trim().replace(/\s+/gu, ' ');
	if (!phrase) {
		throw new TypeError('phrase is required (24-word BIP-39 mnemonic)');
	}
	if (phrase.length > 400) {
		throw new TypeError('phrase exceeds 400 characters');
	}
	const words = phrase.split(' ');
	if (words.length !== WATCH_CONSTANTS.MNEMONIC_WORDS_ORCHARD && words.length !== 12) {
		throw new TypeError(`phrase must be a 12- or 24-word BIP-39 mnemonic (got ${words.length} words)`);
	}
	const network = String(body.network ?? 'mainnet').toLowerCase();
	if (!['mainnet', 'testnet', 'regtest'].includes(network)) {
		throw new TypeError(`network must be 'mainnet', 'testnet' or 'regtest'`);
	}
	return Object.freeze({ chain, phrase, network, wordCount: words.length });
}

/**
 * Async DNS-aware variant of the validator. Same input/output as
 * `validateWatchRequest` but ALSO resolves the webhook hostname via
 * the system resolver and checks each returned IP against private
 * ranges. Reject `evil.example.com` whose A record points at
 * 127.0.0.1 — the literal-IP check alone would miss this class of
 * SSRF.
 *
 * The DNS lookups (one A, one AAAA) add ~5–80 ms; perfectly fine on
 * a one-shot watch creation, and very much worth the protection.
 *
 * `lookup` is dependency-injected so tests can stub it without a
 * fake DNS server. Defaults to node:dns/promises.
 */
export async function resolveAndValidateWatchRequest(body, {
	now = Date.now(),
	allowPrivateWebhooks = false,
	requireHttps = false,
	resolver = dns
} = {}) {
	const validated = validateWatchRequest(body, { now, allowPrivateWebhooks, requireHttps });
	if (!allowPrivateWebhooks) {
		await assertWebhookHostResolvesPublic(validated.webhookUrl, { resolver });
	}
	return validated;
}

/**
 * Resolve the webhook host's A + AAAA records and throw a TypeError
 * if any returned address is in a private/loopback range. Skips the
 * lookup if the hostname is already a literal IP (the synchronous
 * `assertWebhookUrlSafe` already covered those).
 */
export async function assertWebhookHostResolvesPublic(webhookUrl, { resolver = dns } = {}) {
	let url;
	try { url = new URL(webhookUrl); }
	catch { return; }
	const host = url.hostname.toLowerCase();
	// Already an IP literal? Sync guard covered it.
	if (/^[0-9.]+$/u.test(host) || host.includes(':')) return;
	const seen = [];
	const tryResolve = async (fn, kind) => {
		try {
			const ips = await fn(host);
			for (const ip of ips) seen.push({ kind, ip });
		}
		catch (err) {
			// NXDOMAIN, NODATA, network blip — leave the gate open;
			// the eventual delivery will fail naturally and we'd
			// rather not punish a freshly-created DNS record. We
			// log the error name so an operator can see why.
			if (err?.code !== 'ENODATA' && err?.code !== 'ENOTFOUND') throw err;
		}
	};
	await Promise.all([
		tryResolve(resolver.resolve4.bind(resolver), 'A'),
		tryResolve(resolver.resolve6.bind(resolver), 'AAAA')
	]);
	for (const { kind, ip } of seen) {
		if (kind === 'A' && PRIVATE_IPV4_PREFIXES.some((re) => re.test(ip))) {
			throw new TypeError(`webhookUrl host '${host}' resolves to private IPv4 ${ip}`);
		}
		if (kind === 'AAAA' && ipv6IsPrivate(ip)) {
			throw new TypeError(`webhookUrl host '${host}' resolves to private IPv6 ${ip}`);
		}
	}
}

/**
 * Assert that `webhookUrl` is safe to POST to. Throws a TypeError on
 * any violation; returns nothing on success.
 *
 * Rules:
 *   - parseable URL, length cap WEBHOOK_URL_MAX_LEN
 *   - http or https only (with optional `requireHttps`)
 *   - hostname not in FORBIDDEN_HOSTNAMES
 *   - IPv4 dotted hostname not in private/loopback/RFC6598 ranges
 *   - IPv6 literal not in ::/128, ::1, fc00::/7, fe80::/10, etc.
 *
 * This is the synchronous "obvious" guard. For DNS-based SSRF (an
 * attacker-controlled name that resolves to 127.0.0.1) use
 * `assertWebhookHostResolvesPublic` afterwards.
 */
export function assertWebhookUrlSafe(webhookUrl, { allowPrivate = false, requireHttps = false } = {}) {
	if (typeof webhookUrl !== 'string' || webhookUrl.length === 0) {
		throw new TypeError('webhookUrl is required');
	}
	if (webhookUrl.length > WATCH_CONSTANTS.WEBHOOK_URL_MAX_LEN) {
		throw new TypeError(`webhookUrl exceeds ${WATCH_CONSTANTS.WEBHOOK_URL_MAX_LEN} chars`);
	}
	let url;
	try { url = new URL(webhookUrl); }
	catch (e) { throw new TypeError(`webhookUrl is not a valid URL: ${e?.message ?? e}`); }
	if (url.protocol !== 'http:' && url.protocol !== 'https:') {
		throw new TypeError(`webhookUrl protocol must be http or https (got ${url.protocol})`);
	}
	if (requireHttps && url.protocol !== 'https:') {
		throw new TypeError(`webhookUrl must use https:// in production (got ${url.protocol})`);
	}
	// Reject embedded credentials: keeps us from inadvertently
	// leaking basic-auth tokens that the receiver isn't expecting.
	if (url.username || url.password) {
		throw new TypeError('webhookUrl must not embed userinfo (https://user:pass@host…)');
	}
	const host = url.hostname.toLowerCase();
	if (allowPrivate) return;
	if (FORBIDDEN_HOSTNAMES.has(host)) {
		throw new TypeError(`webhookUrl host '${host}' is not allowed`);
	}
	// dotted-quad IPv4 — block private ranges.
	if (/^[0-9.]+$/u.test(host)) {
		if (PRIVATE_IPV4_PREFIXES.some((re) => re.test(host))) {
			throw new TypeError(`webhookUrl host '${host}' is in a private IPv4 range`);
		}
	}
	// IPv6 literal — block loopback/link-local/unique-local + v4-mapped.
	if (host.includes(':')) {
		if (ipv6IsPrivate(host)) {
			throw new TypeError(`webhookUrl host '${host}' is a private IPv6 address`);
		}
	}
}

/**
 * Build a synthetic webhook body for the /test endpoint. Same shape
 * as a real `balance_change` event but flagged via
 * `event: "synthetic_test"` so receivers can branch and avoid
 * processing it as a real payment.
 */
export function buildSyntheticTestBody({ watchId, chain, address, row = null, nowMs = Date.now() }) {
	return JSON.stringify({
		watchId,
		chain,
		address,
		event: 'synthetic_test',
		timestamp: new Date(nowMs).toISOString(),
		nonce: `test-${nowMs.toString(36)}`,
		previous: null,
		current: {
			chain,
			status: 'completed',
			balanceAtomic: '0',
			scannedHeight: 0,
			chainHeight: 0,
			percentComplete: 100,
			error: null,
			note: 'synthetic test event from /v1/private/watch/:id/test'
		},
		delta: { balance_atomic: '0', before_atomic: '0', after_atomic: '0' },
		credit: buildCreditBlock(row)
	});
}

/**
 * Scan states that mean "this job is finished and its numbers are
 * final". Mirrors TERMINAL_SUCCESS_STATES in private-watch-nfpt.js;
 * duplicated rather than imported to keep this module dependency-free
 * and pure.
 */
const SETTLED_SCAN_STATES = new Set(['succeeded', 'completed', 'success']);

/**
 * Is this snapshot too early to be believed?
 *
 * Upstream drops idle scan jobs, so a poller that ticks slower than that
 * TTL regularly finds its job gone, starts a fresh one, and polls it
 * immediately. That first poll necessarily answers `status: 'running'`
 * with no notes and `scannedHeight: 0` — the scan has not looked at the
 * chain yet. That is the *absence* of a balance, not a balance of zero.
 *
 * Diffing it against real prior knowledge invents a drain-to-zero,
 * followed by a refill when the scan completes, then another drain on
 * the next restart: an endless ±balance oscillation from one deposit.
 * That is not just noise — consumers crediting on a positive delta
 * re-credit forever, and because each delivery bills the watch per call,
 * a watch also burns its own credit on events that never happened.
 *
 * Two shapes are untrustworthy, both requiring a non-final status so a
 * genuinely completed scan is always believed:
 *   - it reports no progress at all (`scannedHeight` 0), or
 *   - it reports *less* progress than we already had (the job restarted).
 *
 * Deliberately NOT suppressed:
 *   - anything carrying an `error` — a failing scan is always news;
 *   - a real spend, which drops the balance while `scannedHeight` keeps
 *     advancing, so neither shape above matches.
 */
export function isPrematureSnapshot(before, after) {
	if (!after) return false;
	if (after.error) return false;
	if (SETTLED_SCAN_STATES.has(String(after.status ?? '').toLowerCase())) return false;
	const afterHeight = Number(after.scannedHeight ?? 0);
	if (!Number.isFinite(afterHeight)) return false;
	if (afterHeight === 0) return true;
	const beforeHeight = Number(before?.scannedHeight ?? 0);
	if (!Number.isFinite(beforeHeight)) return false;
	return afterHeight < beforeHeight;
}

/**
 * Compute the diff between two balance snapshots. Returns:
 *   - `null` if there's no semantic difference (used to skip webhook
 *     delivery on idle ticks)
 *   - `{ changed: true, delta, before, after, summary }` otherwise.
 *
 * Snapshots are the objects produced by private-watch-nfpt.js's
 * `normaliseMonero` / `normaliseOrchard`.
 *
 * Callers must not feed this a snapshot that `isPrematureSnapshot()`
 * rejects: this function compares the numbers it is given and cannot
 * tell "balance is zero" from "we have not looked yet".
 */
export function diffBalance(before, after) {
	if (!after) return null;
	const a = numericString(after.balanceAtomic);
	const b = before ? numericString(before.balanceAtomic) : null;
	const heightChanged = before
		&& Number(after.scannedHeight ?? 0) > Number(before.scannedHeight ?? 0);
	if (b === a && !before?.error !== !after?.error) {
		// status flag flipped (e.g. error → recovered) but no balance
		// change. We still want to emit on first-completion.
	}
	const balanceChanged = a !== null && a !== b;
	const errorChanged = (before?.error ?? null) !== (after?.error ?? null);
	const firstComplete = !before && (after?.status === 'completed' || after?.scanProgress >= 0.999);
	if (!balanceChanged && !errorChanged && !firstComplete) return null;
	const beforeAtomic = b ?? '0';
	const afterAtomic = a ?? '0';
	let delta = null;
	try { delta = (BigInt(afterAtomic) - BigInt(beforeAtomic)).toString(); }
	catch { delta = null; }
	return Object.freeze({
		changed: true,
		balance_changed: balanceChanged,
		error_changed: errorChanged,
		first_complete: firstComplete,
		height_changed: Boolean(heightChanged),
		before_atomic: beforeAtomic,
		after_atomic: afterAtomic,
		delta_atomic: delta
	});
}

/**
 * Build a `credit` block summarising the watch's remaining prepaid
 * balance and rates. We attach this to every webhook body so the
 * receiver always knows the state of the meter without having to
 * poll our REST API. Returns `null` if the input row is missing
 * (e.g. synthetic test bodies handle their own framing).
 */
export function buildCreditBlock(row, {
	dayRateAtomic = WATCH_CONSTANTS.DAY_RATE_ATOMIC,
	callRateAtomic = WATCH_CONSTANTS.CALL_RATE_ATOMIC,
	lowThresholdAtomic = WATCH_CONSTANTS.LOW_CREDIT_THRESHOLD_ATOMIC
} = {}) {
	if (!row) return null;
	const remaining = Number.isFinite(Number(row.credit_atomic)) ? Number(row.credit_atomic) : 0;
	const billed = Number.isFinite(Number(row.credit_billed_atomic)) ? Number(row.credit_billed_atomic) : 0;
	const topups = Number.isFinite(Number(row.credit_topups_atomic)) ? Number(row.credit_topups_atomic) : 0;
	const daysRemaining = daysRemainingFromCredit(remaining, dayRateAtomic);
	return {
		remaining_atomic: String(remaining),
		remaining_usd: atomicToUsdString(remaining),
		billed_atomic: String(billed),
		billed_usd: atomicToUsdString(billed),
		topups_atomic: String(topups),
		topups_usd: atomicToUsdString(topups),
		rate_per_day_atomic: String(dayRateAtomic),
		rate_per_day_usd: atomicToUsdString(dayRateAtomic),
		rate_per_call_atomic: String(callRateAtomic),
		rate_per_call_usd: atomicToUsdString(callRateAtomic),
		days_remaining_if_idle: Number(daysRemaining.toFixed(3)),
		low_credit: remaining <= lowThresholdAtomic,
		low_credit_threshold_atomic: String(lowThresholdAtomic),
		low_credit_threshold_usd: atomicToUsdString(lowThresholdAtomic)
	};
}

/**
 * Build the JSON body of a webhook delivery. The receiver verifies
 * the signature header (`<prefix>-signature: sha256=<hex>`, prefix
 * `x-viewkey` by default) against the exact body bytes,
 * so the caller must hand the returned string verbatim to fetch.
 *
 * The `row` argument is the post-debit watch row so the `credit`
 * block reflects what the receiver actually has left AFTER this
 * delivery has been billed.
 */
export function buildWebhookBody({ watchId, chain, address, before, after, diff, row = null, nowMs = Date.now() }) {
	const payload = {
		watchId,
		chain,
		address,
		event: diff.first_complete
			? 'scan_complete'
			: diff.balance_changed
				? 'balance_change'
				: 'status_change',
		timestamp: new Date(nowMs).toISOString(),
		nonce: `${nowMs.toString(36)}-${Math.floor(Math.random() * 1e9).toString(36)}`,
		previous: before ? scrubSnapshot(before) : null,
		current: scrubSnapshot(after),
		delta: {
			balance_atomic: diff.delta_atomic,
			before_atomic: diff.before_atomic,
			after_atomic: diff.after_atomic
		},
		credit: buildCreditBlock(row)
	};
	return JSON.stringify(payload);
}

/**
 * Build a low_credit warning webhook body. Fired exactly once per
 * threshold-crossing — see private-watch-poller.js where the
 * `low_credit_warned` row flag is set after delivery. The body
 * deliberately matches `buildWebhookBody`'s shape (same outer fields)
 * so a receiver can ignore the unknown event type and still parse it.
 */
export function buildLowCreditBody({ watchId, chain, address, row, nowMs = Date.now() }) {
	const payload = {
		watchId,
		chain,
		address,
		event: 'low_credit',
		timestamp: new Date(nowMs).toISOString(),
		nonce: `${nowMs.toString(36)}-low-${Math.floor(Math.random() * 1e9).toString(36)}`,
		previous: null,
		current: null,
		delta: null,
		credit: buildCreditBlock(row)
	};
	return JSON.stringify(payload);
}

/**
 * Public summary that GET /v1/private/watch/:id returns. We strip
 * everything sensitive — no view key, no webhook URL, no secret — so
 * the agent can poll for status without leaking back to the receiver.
 *
 * Derives `next_poll_eta_ms` from `last_polled_at_ms` + the poll
 * cadence so the caller knows roughly when the next scan tick will
 * fire (handy when integrating against a UI).
 */
export function buildWatchSummary(row, { nowMs = Date.now(), pollIntervalSec = WATCH_CONSTANTS.DEFAULT_POLL_INTERVAL_SEC } = {}) {
	if (!row) return null;
	const lastKnown = parseSnapshot(row.last_known_balance);
	const lastDelivered = parseSnapshot(row.last_delivered_balance);
	const lastPolled = row.last_polled_at_ms ?? null;
	const nextPollEta = lastPolled
		? Math.max(0, (lastPolled + pollIntervalSec * 1000) - nowMs)
		: null;
	const credit = buildCreditBlock(row);
	const cancelled = row.cancelled === 1;
	const dead = row.dead === 1;
	const outOfCredit = !cancelled && !dead && Number(row.credit_atomic ?? 0) <= 0;
	return {
		watchId: row.id,
		chain: row.chain,
		created_at_ms: row.created_at_ms,
		// `expires_at_ms` is now an upper bound: when the meter would
		// hit zero at the current idle rate. Top-ups push it later;
		// per-call billing nibbles at it. Clients still get a single
		// timestamp to plan around.
		expires_at_ms: row.expires_at_ms,
		expires_in_ms: Math.max(0, row.expires_at_ms - nowMs),
		state: cancelled ? 'cancelled' : dead ? 'dead' : outOfCredit ? 'out_of_credit' : 'active',
		cancelled,
		dead,
		out_of_credit: outOfCredit,
		credit,
		last_polled_at_ms: lastPolled,
		next_poll_eta_ms: nextPollEta,
		last_delivered_at_ms: row.last_delivered_at_ms ?? null,
		last_delivered_event: row.last_delivered_event ?? null,
		delivery_attempts: row.delivery_attempts ?? 0,
		delivery_count: row.delivery_count ?? 0,
		last_delivery_error: row.last_delivery_error ?? null,
		last_known_balance: lastKnown,
		last_delivered_balance: lastDelivered
	};
}

/**
 * Free metadata endpoint. Lists prices, chains, NFPT health summary.
 * Caller passes the upstream `nfptStatus` (true/false) so we don't
 * pull on the network from a pure function.
 */
export function buildPrivateInfo({
	x402Cfg,
	nfptHealth,
	requireHttps = false,
	serviceName = 'view-key payment watch',
	signatureHeader = 'X-Viewkey-Signature'
}) {
	const routes = x402Cfg?.routes ?? {};
	const priceOf = (route) => routes[route]?.accepts?.price ?? null;
	return {
		service: serviceName,
		spec: 'view-key based payment monitoring + on-demand historical lookups',
		chains: ['monero', 'zcash'],
		pricing: {
			model: 'prepaid credit meter (per-day idle rate + per-call delivery rate)',
			rate_per_day_atomic: String(WATCH_CONSTANTS.DAY_RATE_ATOMIC),
			rate_per_day_usd: atomicToUsdString(WATCH_CONSTANTS.DAY_RATE_ATOMIC),
			rate_per_call_atomic: String(WATCH_CONSTANTS.CALL_RATE_ATOMIC),
			rate_per_call_usd: atomicToUsdString(WATCH_CONSTANTS.CALL_RATE_ATOMIC),
			low_credit_threshold_atomic: String(WATCH_CONSTANTS.LOW_CREDIT_THRESHOLD_ATOMIC),
			low_credit_threshold_usd: atomicToUsdString(WATCH_CONSTANTS.LOW_CREDIT_THRESHOLD_ATOMIC),
			starter_credit_atomic: String(WATCH_CONSTANTS.STARTER_CREDIT_ATOMIC),
			starter_credit_usd: atomicToUsdString(WATCH_CONSTANTS.STARTER_CREDIT_ATOMIC),
			watch_creation: priceOf('POST /v1/private/watch'),
			topup_tiers: [
				{ path: 'POST /v1/private/topup', price: priceOf('POST /v1/private/topup'), credit_atomic: String(WATCH_CONSTANTS.TOPUP_10C_ATOMIC) },
				{ path: 'POST /v1/private/topup-1', price: priceOf('POST /v1/private/topup-1'), credit_atomic: String(WATCH_CONSTANTS.TOPUP_1_ATOMIC) },
				{ path: 'POST /v1/private/topup-5', price: priceOf('POST /v1/private/topup-5'), credit_atomic: String(WATCH_CONSTANTS.TOPUP_5_ATOMIC) }
			],
			topup_custom: {
				path: 'POST /v1/private/topup-custom',
				price: 'variable (your choice within bounds)',
				body: '{ watchId, watchToken, amountAtomic } where amountAtomic is between 100_000 and 25_000_000 (0.10 – 25.00 USDC)',
				note: 'lets a UI present a slider rather than three fixed tiers; same credit math, same webhook contract'
			},
			historical_lookup: {
				path: 'POST /v1/private/historical',
				price: priceOf('POST /v1/private/historical'),
				returns: 'spendable_atomic + spent_atomic + total_received_atomic + (optional) per-note breakdown',
				note: 'one-shot scan; view key NEVER persists in our DB'
			},
			derive_viewkey: {
				path: 'POST /v1/private/derive-viewkey',
				price: 'free (rate-limited)',
				supported_chains: ['zcash'],
				warning: 'transmits your seed phrase to our server in plaintext over TLS; we do not store it but a network-attacker between you and us would see it. For maximum safety derive offline using the orchard-scanner binary on a trusted machine.'
			}
		},
		poll_interval_sec: WATCH_CONSTANTS.DEFAULT_POLL_INTERVAL_SEC,
		max_delivery_attempts: WATCH_CONSTANTS.MAX_DELIVERY_ATTEMPTS,
		max_watch_lifetime_days: Math.round(WATCH_CONSTANTS.MAX_WATCH_LIFETIME_MS / 86_400_000),
		paywall_enabled: x402Cfg?.enabled === true,
		upstream: nfptHealth,
		security: {
			view_key_encryption: 'AES-256-GCM with operator-supplied master key (PRIVATE_WATCH_ENCRYPTION_KEY)',
			webhook_signature: `HMAC-SHA256 (per-watch secret in ${signatureHeader}: sha256=…)`,
			webhook_url_scheme: requireHttps ? 'https only' : 'http or https',
			webhook_ssrf_guard: 'private IPv4/IPv6 ranges, loopback, link-local, RFC6598 CGNAT and cloud-metadata IPs are rejected at creation; the hostname is then DNS-resolved and the result re-checked',
			view_key_permissions: 'view keys grant read-only visibility into incoming transactions; they CANNOT spend funds. Handing one to a third-party service does not put your balance at risk.',
			historical_view_key_handling: 'historical lookups stream the view key through to NFPT in-memory only — never written to our SQLite or logs.'
		}
	};
}

/**
 * Apply per-day billing to a watch row. Returns the patch to persist:
 *   { credit_atomic, credit_billed_atomic, credit_last_billed_ms, expires_at_ms }
 * `chargeAtomic` is the integer atomic amount we just deducted.
 *
 * The poller calls this whenever it polls (so partial-days are
 * pro-rated), but the math is split out so it can be unit-tested
 * without a database.
 */
export function applyDayCharge(row, nowMs, {
	dayRateAtomic = WATCH_CONSTANTS.DAY_RATE_ATOMIC
} = {}) {
	const lastBilled = Number(row.credit_last_billed_ms ?? row.created_at_ms ?? nowMs);
	const elapsedMs = Math.max(0, nowMs - lastBilled);
	const chargeAtomic = Math.floor((elapsedMs * dayRateAtomic) / 86_400_000);
	if (chargeAtomic <= 0) {
		// Less than one atomic unit of cost has accrued; don't even
		// bump the timestamp (so we keep accumulating precision until
		// the next tick).
		return { chargeAtomic: 0 };
	}
	const newCredit = Math.max(0, Number(row.credit_atomic ?? 0) - chargeAtomic);
	const newBilled = Number(row.credit_billed_atomic ?? 0) + chargeAtomic;
	const expiresAtMs = nowMs + Math.floor((newCredit * 86_400_000) / dayRateAtomic);
	return {
		chargeAtomic,
		credit_atomic: newCredit,
		credit_billed_atomic: newBilled,
		credit_last_billed_ms: nowMs,
		expires_at_ms: expiresAtMs
	};
}

/**
 * Apply a per-call charge after a webhook delivery. Returns the patch
 * to persist:
 *   { credit_atomic, credit_billed_atomic, expires_at_ms }
 *
 * Called by the poller right after a successful webhook fetch; we
 * always burn the call charge even if the meter then dips below
 * zero (the next tick will mark the watch out_of_credit).
 */
export function applyCallCharge(row, nowMs, {
	callRateAtomic = WATCH_CONSTANTS.CALL_RATE_ATOMIC,
	dayRateAtomic = WATCH_CONSTANTS.DAY_RATE_ATOMIC
} = {}) {
	const newCredit = Math.max(0, Number(row.credit_atomic ?? 0) - callRateAtomic);
	const newBilled = Number(row.credit_billed_atomic ?? 0) + callRateAtomic;
	const expiresAtMs = nowMs + Math.floor((newCredit * 86_400_000) / dayRateAtomic);
	return {
		chargeAtomic: callRateAtomic,
		credit_atomic: newCredit,
		credit_billed_atomic: newBilled,
		expires_at_ms: expiresAtMs
	};
}

/**
 * Apply a top-up to a watch row. Returns the patch:
 *   { credit_atomic, credit_topups_atomic, expires_at_ms, low_credit_warned }
 *
 * If the top-up pushes the meter back above the low-credit threshold
 * we reset `low_credit_warned` so the next drop fires a fresh
 * warning.
 */
export function applyTopup(row, creditAtomic, nowMs, {
	dayRateAtomic = WATCH_CONSTANTS.DAY_RATE_ATOMIC,
	lowThresholdAtomic = WATCH_CONSTANTS.LOW_CREDIT_THRESHOLD_ATOMIC,
	maxLifetimeMs = WATCH_CONSTANTS.MAX_WATCH_LIFETIME_MS
} = {}) {
	if (!Number.isInteger(creditAtomic) || creditAtomic <= 0) {
		throw new TypeError('creditAtomic must be a positive integer of atomic USDC units');
	}
	const newCredit = Number(row.credit_atomic ?? 0) + creditAtomic;
	const newTopups = Number(row.credit_topups_atomic ?? 0) + creditAtomic;
	const naiveExpires = nowMs + Math.floor((newCredit * 86_400_000) / dayRateAtomic);
	const cappedExpires = Math.min(naiveExpires, nowMs + maxLifetimeMs);
	const lowCreditReset = newCredit > lowThresholdAtomic ? 0 : (row.low_credit_warned ?? 0);
	return {
		credit_atomic: newCredit,
		credit_topups_atomic: newTopups,
		expires_at_ms: cappedExpires,
		low_credit_warned: lowCreditReset
	};
}

/**
 * Read the per-watch surge rates off a row, falling back to the
 * legacy `WATCH_CONSTANTS.*` defaults for rows that pre-date the
 * surge-pricing migration (where `day_rate_atomic` is NULL). The
 * meter math + the low-credit gate all flow through this so the
 * fallback policy lives in exactly one place.
 *
 * Returns `{ dayRateAtomic, callRateAtomic, lowCreditThresholdAtomic }`.
 */
export function effectiveRatesForRow(row) {
	const day = Number(row?.day_rate_atomic ?? 0);
	const call = Number(row?.call_rate_atomic ?? 0);
	const low = Number(row?.low_credit_threshold_atomic ?? 0);
	const dayRateAtomic = Number.isFinite(day) && day > 0 ? day : WATCH_CONSTANTS.DAY_RATE_ATOMIC;
	const callRateAtomic = Number.isFinite(call) && call > 0 ? call : WATCH_CONSTANTS.CALL_RATE_ATOMIC;
	// Threshold policy: trust whatever the surge engine stored
	// at creation time; for legacy rows (NULL column) fall back
	// to the long-standing global constant so existing watches
	// don't suddenly trip low-credit warnings on their starter
	// credit.
	const lowCreditThresholdAtomic = low > 0 ? low : WATCH_CONSTANTS.LOW_CREDIT_THRESHOLD_ATOMIC;
	return { dayRateAtomic, callRateAtomic, lowCreditThresholdAtomic };
}

// ── Internal helpers ─────────────────────────────────────────────

function numericString(v) {
	if (v === null || v === undefined) return null;
	const s = String(v);
	return /^-?\d+$/u.test(s) ? s : null;
}

function scrubSnapshot(snap) {
	if (!snap || typeof snap !== 'object') return null;
	// Whitelist only the public fields. Avoids accidentally leaking
	// future internal state if normalise* grows new keys.
	return {
		chain: snap.chain ?? null,
		status: snap.status ?? null,
		balanceAtomic: snap.balanceAtomic ?? null,
		spendableAtomic: snap.spendableAtomic ?? null,
		lockedAtomic: snap.lockedAtomic ?? null,
		pendingInAtomic: snap.pendingInAtomic ?? null,
		pendingOutAtomic: snap.pendingOutAtomic ?? null,
		receivedAtomic: snap.receivedAtomic ?? null,
		unspentNotes: snap.unspentNotes ?? null,
		notes: snap.notes ?? null,
		scannedHeight: snap.scannedHeight ?? null,
		chainHeight: snap.chainHeight ?? null,
		percentComplete: snap.percentComplete ?? null,
		error: snap.error ?? null
	};
}

function parseSnapshot(json) {
	if (!json) return null;
	try { return JSON.parse(json); }
	catch { return null; }
}

function describe(v) {
	const s = typeof v === 'string' ? v : JSON.stringify(v);
	return s.length > 80 ? `${s.slice(0, 80)}…` : s;
}
