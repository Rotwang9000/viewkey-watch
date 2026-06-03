// viewkey-watch — public API.
//
// Watch a Monero/Zcash *view key* (read-only; cannot spend) and get an
// HMAC-signed webhook whenever the balance changes, with an optional
// prepaid credit meter and XMR/ZEC top-up detection.
//
// The toolkit is a set of small, side-effect-free factories and pure
// helpers — nothing reads process.env or holds shared mutable state, so
// everything is injected through function parameters and is trivially
// testable. Two long-running loops (`runPollerTick`, `runCryptoRecvTick`)
// are designed to be driven by your own timer/cron/systemd unit.
//
// It talks to a wallet-scanner HTTP backend (the open-source NFPT API,
// or any service implementing the same contract — see README) for the
// actual chain scanning; you never run a full node in-process.

// ── Grouped namespaces (complete surface of each module) ─────────────
export * as scanner from './private-watch-nfpt.js';        // wallet-scanner client
export * as watch from './private-watch.js';               // validation, SSRF guard, meter math, payload builders
export * as store from './private-watch-store.js';         // watch persistence (SQLite)
export * as cryptoKeys from './private-watch-crypto.js';   // view-key encryption + webhook signing
export * as poller from './private-watch-poller.js';       // webhook delivery loop
export * as pricing from './private-watch-pricing.js';     // surge/credit pricing
export * as price from './crypto-price.js';                // USD↔coin conversion + price oracle
export * as receiveStore from './crypto-topup-store.js';   // inbound top-up quote persistence
export * as receivePoller from './crypto-recv-poller.js';  // inbound XMR/ZEC detection loop

// ── Flat convenience: the factories/entry points most callers wire ───
export { createNfptClient } from './private-watch-nfpt.js';
export { openWatchDb, createWatch, getWatch, cancelWatch } from './private-watch-store.js';
export { createPriceOracle } from './crypto-price.js';
export { runPollerTick, deliverWebhook } from './private-watch-poller.js';
export { runCryptoRecvTick, makeWatchCreditApplier } from './crypto-recv-poller.js';
export { ensureCryptoTopupSchema, createQuote } from './crypto-topup-store.js';
export {
	parseMasterKey,
	encryptViewKey,
	decryptViewKey,
	generateWebhookSecret,
	signWebhookBody
} from './private-watch-crypto.js';
export { WATCH_CONSTANTS } from './private-watch.js';
