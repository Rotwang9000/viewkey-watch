/* tslint:disable */
/* eslint-disable */

/**
 * Diversified payment address at `index` (external scope) for an FVK.
 * Returns the 43-byte raw Orchard address as hex.
 */
export function address_at(fvk_hex: string, index: number): string;

/**
 * Derive watch-only key material from a BIP-39 seed.
 *
 * Path is `m/32'/coin_type'/account'` with coin type 5 (mainnet) or
 * 1 (testnet). Only viewing material leaves this function — the
 * transiently derived spending key is dropped before returning.
 */
export function derive_watch_keys(seed: Uint8Array, mainnet: boolean, account: number): any;

/**
 * Trial-decrypt a batch of Platform encrypted notes with an FVK.
 *
 * `notes_js` is an array of `{ index, rho, cmx, note }` (hex fields;
 * `note` is the 216-byte ciphertext). Both external and internal
 * (change) scopes are tried. Returns the decrypted matches; notes that
 * don't belong to the FVK are simply skipped.
 */
export function trial_decrypt(fvk_hex: string, notes_js: any): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly derive_watch_keys: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly address_at: (a: number, b: number, c: number) => [number, number, number, number];
    readonly trial_decrypt: (a: number, b: number, c: any) => [number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
