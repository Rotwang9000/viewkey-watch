// Symmetric crypto helpers for the private-watch service.
//
// Three primitives, kept stupid-simple so they're easy to audit:
//
//   1. `encryptViewKey` / `decryptViewKey` — AES-256-GCM over a 32-byte
//      master key sourced from `PRIVATE_WATCH_ENCRYPTION_KEY`. Each
//      encryption uses a fresh 12-byte nonce. The wire format is
//      base64(nonce || ciphertext || tag) so a DB row dump never leaks
//      the view key directly; only the live process (which knows the
//      master key) can decrypt.
//
//   2. `generateWebhookSecret` — per-watch 32-byte random hex used as
//      the HMAC-SHA256 key for outbound webhooks. Stored alongside the
//      watch row (the operator already has filesystem access to the
//      DB; this isn't a defence against host compromise). Returning it
//      to the watch creator lets the receiver verify signatures.
//
//   3. `signWebhookBody` — HMAC-SHA256(secret, body). The body is the
//      exact JSON string that goes on the wire so receivers can
//      recompute without re-serialising. Returned as hex.
//
// Why one master key for view keys and one secret per watch:
//   - View keys MUST stay encrypted at rest. A single rotateable
//     master key keeps the surface tiny and the env var management
//     straightforward.
//   - Webhook secrets are public-by-policy (we hand them to the
//     watcher), so per-watch isolation is the right granularity —
//     leaking one watch's secret doesn't help an attacker forge
//     signatures for any other watch.

import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';

const ALGO = 'aes-256-gcm';
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;
const WEBHOOK_SECRET_BYTES = 32;

/**
 * Parse the operator-supplied master key. Accepts either:
 *   - 64-char hex string (preferred — copy/paste friendly), OR
 *   - base64 string decoding to 32 bytes.
 *
 * Throws a precise error so a misconfigured deployment fails at boot
 * rather than silently corrupting stored view keys.
 */
export function parseMasterKey(raw) {
	if (typeof raw !== 'string' || raw.length === 0) {
		throw new TypeError('parseMasterKey: PRIVATE_WATCH_ENCRYPTION_KEY must be a non-empty string');
	}
	const hexMatch = /^[0-9a-fA-F]+$/u.test(raw);
	if (hexMatch && raw.length === KEY_BYTES * 2) {
		return Buffer.from(raw, 'hex');
	}
	// Fallback: base64 (44 char canonical or 43 unpadded for 32 bytes).
	try {
		const buf = Buffer.from(raw, 'base64');
		if (buf.length === KEY_BYTES) return buf;
	}
	catch {
		// fall through to error
	}
	throw new TypeError(
		`parseMasterKey: expected a 64-char hex string or 32-byte base64 (got ${raw.length} chars)`
	);
}

/**
 * Encrypt a view key (or any short secret) under the master key.
 * Returns a single base64-url string suitable for storing in a TEXT
 * column. The 12-byte nonce is randomly chosen per call — collision
 * probability is negligible for any realistic number of watches.
 */
export function encryptViewKey(plaintext, masterKey) {
	if (typeof plaintext !== 'string' || plaintext.length === 0) {
		throw new TypeError('encryptViewKey: plaintext must be a non-empty string');
	}
	if (!Buffer.isBuffer(masterKey) || masterKey.length !== KEY_BYTES) {
		throw new TypeError('encryptViewKey: masterKey must be a 32-byte Buffer');
	}
	const nonce = randomBytes(NONCE_BYTES);
	const cipher = createCipheriv(ALGO, masterKey, nonce);
	const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
	const tag = cipher.getAuthTag();
	return Buffer.concat([nonce, ct, tag]).toString('base64');
}

/**
 * Inverse of `encryptViewKey`. Throws if the auth tag does not verify
 * — that means the ciphertext was tampered or the key changed.
 */
export function decryptViewKey(ciphertextB64, masterKey) {
	if (typeof ciphertextB64 !== 'string' || ciphertextB64.length === 0) {
		throw new TypeError('decryptViewKey: ciphertextB64 must be a non-empty string');
	}
	if (!Buffer.isBuffer(masterKey) || masterKey.length !== KEY_BYTES) {
		throw new TypeError('decryptViewKey: masterKey must be a 32-byte Buffer');
	}
	const buf = Buffer.from(ciphertextB64, 'base64');
	if (buf.length < NONCE_BYTES + TAG_BYTES + 1) {
		throw new Error('decryptViewKey: ciphertext too short to contain nonce|ct|tag');
	}
	const nonce = buf.subarray(0, NONCE_BYTES);
	const tag = buf.subarray(buf.length - TAG_BYTES);
	const ct = buf.subarray(NONCE_BYTES, buf.length - TAG_BYTES);
	const decipher = createDecipheriv(ALGO, masterKey, nonce);
	decipher.setAuthTag(tag);
	const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
	return pt.toString('utf8');
}

/**
 * Generate a fresh per-watch webhook signing secret.
 * Returns 64 hex chars (32 bytes of entropy).
 */
export function generateWebhookSecret() {
	return randomBytes(WEBHOOK_SECRET_BYTES).toString('hex');
}

/**
 * Sign a webhook body with the per-watch secret. The signature is
 * HMAC-SHA256 over the exact bytes the receiver will see in the HTTP
 * body, so verification is "recompute and compare" with no canonical
 * JSON tricks.
 *
 * Returns the bare hex digest. Callers should put `sha256=${hex}` in
 * the signature header (e.g. `x-viewkey-signature`) so the scheme is
 * self-describing.
 */
export function signWebhookBody(bodyString, secretHex) {
	if (typeof bodyString !== 'string') {
		throw new TypeError('signWebhookBody: bodyString must be a string');
	}
	if (typeof secretHex !== 'string' || secretHex.length === 0) {
		throw new TypeError('signWebhookBody: secretHex must be a non-empty string');
	}
	const secret = Buffer.from(secretHex, 'hex');
	return createHmac('sha256', secret).update(bodyString, 'utf8').digest('hex');
}

export const CRYPTO_CONSTANTS = Object.freeze({
	ALGO,
	NONCE_BYTES,
	TAG_BYTES,
	KEY_BYTES,
	WEBHOOK_SECRET_BYTES
});
