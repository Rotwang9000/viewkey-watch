// Tests for the symmetric crypto primitives backing the private-watch
// service. We keep these stupid-simple: round-trip view-key encryption
// under a known master key, reject malformed master keys early,
// confirm webhook signatures are stable and recoverable.

import { describe, test, expect } from '@jest/globals';
import { randomBytes } from 'node:crypto';

import {
	parseMasterKey,
	encryptViewKey,
	decryptViewKey,
	generateWebhookSecret,
	signWebhookBody,
	CRYPTO_CONSTANTS
} from '../src/private-watch-crypto.js';

const FIXED_KEY_HEX = 'a'.repeat(64);
const FIXED_KEY_BUF = Buffer.from(FIXED_KEY_HEX, 'hex');

describe('parseMasterKey', () => {
	test('accepts 64-char hex', () => {
		const k = parseMasterKey(FIXED_KEY_HEX);
		expect(k).toBeInstanceOf(Buffer);
		expect(k.length).toBe(CRYPTO_CONSTANTS.KEY_BYTES);
	});

	test('accepts 32-byte base64', () => {
		const k = parseMasterKey(randomBytes(32).toString('base64'));
		expect(k).toBeInstanceOf(Buffer);
		expect(k.length).toBe(CRYPTO_CONSTANTS.KEY_BYTES);
	});

	test('rejects empty string', () => {
		expect(() => parseMasterKey('')).toThrow(/non-empty string/);
	});

	test('rejects short hex', () => {
		expect(() => parseMasterKey('a'.repeat(20))).toThrow(/64-char hex/);
	});

	test('rejects bad base64', () => {
		expect(() => parseMasterKey('not-a-key!')).toThrow(/64-char hex/);
	});
});

describe('encryptViewKey / decryptViewKey', () => {
	test('round-trips a Monero view key', () => {
		const vk = '5'.repeat(64);
		const ct = encryptViewKey(vk, FIXED_KEY_BUF);
		expect(typeof ct).toBe('string');
		expect(ct.length).toBeGreaterThan(0);
		expect(ct).not.toContain(vk);
		expect(decryptViewKey(ct, FIXED_KEY_BUF)).toBe(vk);
	});

	test('round-trips a long Zcash UFVK', () => {
		const ufvk = 'uview1' + 'q'.repeat(800);
		const ct = encryptViewKey(ufvk, FIXED_KEY_BUF);
		expect(decryptViewKey(ct, FIXED_KEY_BUF)).toBe(ufvk);
	});

	test('different nonces produce different ciphertexts for the same plaintext', () => {
		const ct1 = encryptViewKey('abc', FIXED_KEY_BUF);
		const ct2 = encryptViewKey('abc', FIXED_KEY_BUF);
		expect(ct1).not.toBe(ct2);
		expect(decryptViewKey(ct1, FIXED_KEY_BUF)).toBe('abc');
		expect(decryptViewKey(ct2, FIXED_KEY_BUF)).toBe('abc');
	});

	test('rejects empty plaintext', () => {
		expect(() => encryptViewKey('', FIXED_KEY_BUF)).toThrow(/non-empty string/);
	});

	test('rejects wrong master key length', () => {
		expect(() => encryptViewKey('x', Buffer.alloc(31))).toThrow(/32-byte Buffer/);
	});

	test('decryption fails with tampered ciphertext', () => {
		const ct = encryptViewKey('hello', FIXED_KEY_BUF);
		// Tamper a middle byte (avoid base64 padding chars).
		const tampered = ct.slice(0, ct.length - 8) + 'AAAAAAAA';
		expect(() => decryptViewKey(tampered, FIXED_KEY_BUF)).toThrow();
	});

	test('decryption fails with wrong master key', () => {
		const ct = encryptViewKey('hello', FIXED_KEY_BUF);
		const otherKey = Buffer.from('b'.repeat(64), 'hex');
		expect(() => decryptViewKey(ct, otherKey)).toThrow();
	});
});

describe('generateWebhookSecret', () => {
	test('returns 64 hex chars (32 bytes)', () => {
		const s = generateWebhookSecret();
		expect(s).toMatch(/^[0-9a-f]{64}$/u);
	});

	test('produces fresh randomness per call', () => {
		const a = generateWebhookSecret();
		const b = generateWebhookSecret();
		expect(a).not.toBe(b);
	});
});

describe('signWebhookBody', () => {
	test('is deterministic for the same input', () => {
		const sig1 = signWebhookBody('{"x":1}', '00'.repeat(32));
		const sig2 = signWebhookBody('{"x":1}', '00'.repeat(32));
		expect(sig1).toBe(sig2);
		expect(sig1).toMatch(/^[0-9a-f]{64}$/u);
	});

	test('changes when body changes', () => {
		const a = signWebhookBody('{"x":1}', '00'.repeat(32));
		const b = signWebhookBody('{"x":2}', '00'.repeat(32));
		expect(a).not.toBe(b);
	});

	test('changes when secret changes', () => {
		const a = signWebhookBody('{"x":1}', '00'.repeat(32));
		const b = signWebhookBody('{"x":1}', '11'.repeat(32));
		expect(a).not.toBe(b);
	});

	test('rejects non-string body', () => {
		expect(() => signWebhookBody({}, '00'.repeat(32))).toThrow(/must be a string/);
	});
});
