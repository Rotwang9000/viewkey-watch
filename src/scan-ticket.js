/**
 * @fileoverview Scan tickets — minting side.
 *
 * NFPT is the single Orchard scanner behind zecmon, Seneschal and the
 * winbit32 MCP tools. Its free tier is accounted per END USER ("scan
 * subject") whichever front-end a request arrives through, and its queue
 * is shared. A scan ticket is how a caller that has taken payment buys a
 * place near the front of that queue for one scan.
 *
 * Deliberately a *place*, not capacity: the box scans no faster for a
 * paying customer, so a ticket cannot be oversold into a promise we
 * cannot keep.
 *
 * This module only MINTS. NFPT verifies and spends (see its
 * services/scanTicket.js) and is the sole authority on whether a ticket
 * is good. Both sides must agree on the wire format:
 *
 *     v1.<subject>.<expiryEpochSec>.<nonce>.<hmacSha256Base64Url>
 *
 * signed over `v1|<subject>|<expiry>|<nonce>` with the shared secret.
 *
 * Keep this in step with NFPT if either changes — the format is pinned by
 * a cross-implementation test on the NFPT side.
 */

import crypto from 'node:crypto';

// NFPT refuses anything longer, so minting beyond it just produces
// tickets that fail verification.
export const MAX_TICKET_TTL_SEC = 15 * 60;
export const DEFAULT_TICKET_TTL_SEC = 5 * 60;

/**
 * Subjects key the free-tier buckets on the scanner, so they must not be
 * forgeable into one another by case or padding, and must not contain the
 * '.' that delimits the token.
 */
export function normaliseSubject(raw) {
	if (typeof raw !== 'string') return null;
	const s = raw.trim().toLowerCase();
	if (!s) return null;
	if (!/^[a-z0-9_:@-]{1,128}$/u.test(s)) return null;
	return s;
}

/**
 * Mint a single-use scan ticket.
 *
 * @param {string} subject stable id of the end user the scan is for.
 *        NEVER a view key or raw address — hash those first.
 * @param {{ secret?: string, ttlSec?: number, now?: number }} [opts]
 * @returns {string}
 */
export function mintScanTicket(subject, opts = {}) {
	const secret = opts.secret ?? process.env.SCAN_TICKET_SECRET;
	if (typeof secret !== 'string' || secret.length < 16) {
		throw new Error('mintScanTicket: SCAN_TICKET_SECRET is not configured (needs >= 16 chars)');
	}
	const subj = normaliseSubject(subject);
	if (!subj) {
		throw new TypeError('mintScanTicket: subject is required and must match /^[a-z0-9_:@-]{1,128}$/');
	}

	const ttl = Math.min(
		MAX_TICKET_TTL_SEC,
		Math.max(30, Number(opts.ttlSec) || DEFAULT_TICKET_TTL_SEC)
	);
	const now = opts.now ?? Date.now();
	const exp = Math.floor(now / 1000) + ttl;
	const nonce = crypto.randomBytes(12).toString('base64url');
	const mac = crypto
		.createHmac('sha256', secret)
		.update(`v1|${subj}|${exp}|${nonce}`)
		.digest('base64url');
	return `v1.${subj}.${exp}.${nonce}.${mac}`;
}

/** Is a priority lane available at all? Lets callers skip minting quietly. */
export function isTicketingEnabled(secret = process.env.SCAN_TICKET_SECRET) {
	return typeof secret === 'string' && secret.length >= 16;
}
