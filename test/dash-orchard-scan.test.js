// Pins the dash receive-scan contract: page the note stream from a
// cursor, hand the WASM the hex wire fields it expects, map hits to the
// `{ chainHeight, incoming }` shape runCryptoRecvTick consumes, and
// report instant finality (blockHeight = chainHeight = 1).

import { jest } from '@jest/globals';
import { scanDashReceiving, DASH_NOTES_PAGE_SIZE } from '../src/dash-orchard-scan.js';

const FVK = 'ab'.repeat(96);

const bytes = (n, fill) => new Uint8Array(n).fill(fill);

function makeSdk(pages) {
	const encryptedNotes = jest.fn();
	for (const page of pages) encryptedNotes.mockResolvedValueOnce(page);
	encryptedNotes.mockResolvedValue([]);
	return { shielded: { encryptedNotes } };
}

describe('scanDashReceiving', () => {
	test('rejects a malformed fvk before touching the network', async () => {
		await expect(scanDashReceiving({ fvk: 'nope', sdk: {}, wasm: {} }))
			.rejects.toThrow(/full viewing key/u);
		await expect(scanDashReceiving({ sdk: {}, wasm: {} }))
			.rejects.toThrow(/full viewing key/u);
	});

	test('pages from the cursor and maps hits to incoming payments', async () => {
		const fullPage = Array.from({ length: DASH_NOTES_PAGE_SIZE }, () => ({
			nullifier: bytes(32, 1), cmx: bytes(32, 2), encryptedNote: bytes(216, 3)
		}));
		const shortPage = [
			{ nullifier: bytes(32, 4), cmx: bytes(32, 5), encryptedNote: bytes(216, 6) }
		];
		const sdk = makeSdk([fullPage, shortPage]);

		const wasm = {
			trial_decrypt: jest.fn()
				.mockReturnValueOnce([{
					index: 7, duffs: '123456789', scope: 'external',
					nullifier: 'c1'.repeat(32), memo_text: 'PG-3f4807e5', memo_hex: '00'.repeat(36),
					address: 'aa'.repeat(43)
				}])
				.mockReturnValueOnce([])
		};

		const result = await scanDashReceiving({ fvk: FVK, startIndex: 1000, sdk, wasm });

		expect(sdk.shielded.encryptedNotes).toHaveBeenNthCalledWith(1, 1000n, DASH_NOTES_PAGE_SIZE);
		expect(sdk.shielded.encryptedNotes).toHaveBeenNthCalledWith(2, 1200n, DASH_NOTES_PAGE_SIZE);
		expect(result.nextIndex).toBe(1201);
		expect(result.scanned).toBe(201);
		expect(result.chainHeight).toBe(1);

		// The WASM got the hex wire fields, indexed from the cursor.
		const [fvkArg, wireNotes] = wasm.trial_decrypt.mock.calls[0];
		expect(fvkArg).toBe(FVK);
		expect(wireNotes[0]).toEqual({
			index: 1000,
			rho: '01'.repeat(32),
			cmx: '02'.repeat(32),
			note: '03'.repeat(216)
		});

		expect(result.incoming).toEqual([{
			amountAtomic: '123456789',
			memo: 'PG-3f4807e5',
			txHash: 'c1'.repeat(32),
			blockHeight: 1,
			noteIndex: 7,
			scope: 'external'
		}]);
	});

	test('frees SDK wasm note handles after reading them', async () => {
		const free = jest.fn();
		const sdk = makeSdk([[
			{ nullifier: bytes(32, 1), cmx: bytes(32, 2), encryptedNote: bytes(216, 3), free }
		]]);
		const wasm = { trial_decrypt: jest.fn().mockReturnValue([]) };
		await scanDashReceiving({ fvk: FVK, sdk, wasm });
		expect(free).toHaveBeenCalledTimes(1);
	});

	test('an empty memo becomes an empty string (never undefined)', async () => {
		const sdk = makeSdk([[
			{ nullifier: bytes(32, 1), cmx: bytes(32, 2), encryptedNote: bytes(216, 3) }
		]]);
		const wasm = {
			trial_decrypt: jest.fn().mockReturnValue([{
				index: 0, duffs: '1', scope: 'internal',
				nullifier: 'c2'.repeat(32), memo_text: null, memo_hex: '00'.repeat(36),
				address: 'aa'.repeat(43)
			}])
		};
		const result = await scanDashReceiving({ fvk: FVK, sdk, wasm });
		expect(result.incoming[0].memo).toBe('');
	});

	test('maxNotes caps the walk mid-stream', async () => {
		const page = Array.from({ length: 100 }, () => ({
			nullifier: bytes(32, 1), cmx: bytes(32, 2), encryptedNote: bytes(216, 3)
		}));
		const sdk = makeSdk([page, page, page]);
		const wasm = { trial_decrypt: jest.fn().mockReturnValue([]) };
		const result = await scanDashReceiving({ fvk: FVK, sdk, wasm, pageSize: 100, maxNotes: 150 });
		expect(result.scanned).toBe(200); // stops after the page that crosses the cap
		expect(sdk.shielded.encryptedNotes).toHaveBeenCalledTimes(2);
	});
});
