# viewkey-watch

Watch a **Monero or Zcash view key** and get an **HMAC‑signed webhook** the moment funds
land — without running a full node and without ever touching a spend key.

A view key (Monero private view key, or a Zcash Unified Full Viewing Key) is **read‑only**:
it can *see* incoming transactions but can **never move funds**. That makes it safe to hand
to a watcher service. `viewkey-watch` turns that capability into a small, well‑tested toolkit:

- **Balance‑change webhooks** — register `{chain, address, viewKey, webhookUrl}`; receive a
  signed POST whenever the watched balance changes.
- **Prepaid credit meter** — optional per‑day + per‑delivery billing with surge pricing, so a
  hosted deployment can charge for the service. Ignore it entirely if you just want webhooks.
- **Accept XMR/ZEC payments** — a second loop watches *your own* receiving wallet's view key,
  matches inbound payments to quotes (unique‑amount for Monero, memo token for Zcash) and
  credits them. You dogfood the same mechanism you expose to customers.
- **Historical lookups & UFVK derivation** — one‑shot spendable/spent breakdowns, and (Zcash)
  derive a UFVK from a seed phrase.

Everything is plain ESM, dependency‑injected (nothing reads `process.env` or holds shared
mutable state), and ships with a full unit‑test suite.

> **Status:** powers the **Private Watch** product in production at
> [api.seneschal.space](https://api.seneschal.space/v1/private/info) — Monero/Zcash view‑key
> payment webhooks plus XMR/ZEC credit top‑ups. `0.x` while the public API settles.

## How it works

```
                 register watch                  ┌────────────────────────┐
   your app  ───────────────────────────────────▶│  viewkey-watch          │
   (HTTP API) ◀──── { id, watchToken, secret } ──│   • watch store (SQLite)│
                                                  │   • credit meter        │
   ┌──────────────┐   start/poll scan job         │   • poll loop           │
   │ wallet‑scanner│◀──── x-api-key ──────────────│   • receive loop        │
   │  backend      │────▶ balances / notes ───────▶│                        │
   │ (NFPT, nodes) │                               └───────────┬────────────┘
   └──────────────┘                                            │ on balance change
                                                               ▼
                                            POST webhookUrl  +  x-viewkey-signature
                                            (HMAC‑SHA256 of the body)
```

`viewkey-watch` does **not** scan chains itself — it talks to a **wallet‑scanner backend**
over HTTP (see [Backend](#backend)). The reference backend is the open‑source
[NFPT](https://github.com/FungeLLC/NFPT) API, which fronts `monerod`/`monero-lws` and a
Zcash `lightwalletd`/`zebra` node.

## Install

```bash
npm install viewkey-watch
```

Requires **Node ≥ 20** (uses the global `fetch`). The only runtime dependency is
`better-sqlite3`.

## Quickstart

A complete, runnable HTTP server lives in [`examples/basic-server.mjs`](examples/basic-server.mjs).
The essentials:

```js
import {
  createNfptClient, openWatchDb, createWatch,
  parseMasterKey, encryptViewKey, generateWebhookSecret,
  runPollerTick, WATCH_CONSTANTS
} from 'viewkey-watch';

const masterKey = parseMasterKey(process.env.PRIVATE_WATCH_ENCRYPTION_KEY); // 32 bytes (hex/base64)
const db = openWatchDb('./watches.db');
const nfpt = createNfptClient({ baseUrl: process.env.NFPT_BASE_URL, apiKey: process.env.NFPT_API_KEY });

// Register a watch (view key is encrypted at rest):
const secret = generateWebhookSecret();
const watch = createWatch(db, {
  chain: 'zcash',
  address: 'u1...',
  viewKeyCiphertext: encryptViewKey('uview1...', masterKey),
  webhookUrl: 'https://example.com/hook',
  webhookSecret: secret,
  creditAtomic: WATCH_CONSTANTS.STARTER_CREDIT_ATOMIC,
  dayRateAtomic: WATCH_CONSTANTS.DAY_RATE_ATOMIC,
  callRateAtomic: WATCH_CONSTANTS.CALL_RATE_ATOMIC
});
// → { id, token, expiresAt }  — return token+secret to the caller ONCE.

// Drive the poll loop from your own timer / cron / systemd unit:
setInterval(() => runPollerTick({ db, masterKey, nfptClient: nfpt }), 60_000);
```

## Verifying webhooks

Each delivery carries `x-viewkey-signature: sha256=<hex>` — an HMAC‑SHA256 over the **exact
body bytes**, keyed by the per‑watch `webhookSecret` (decoded from hex). Recompute and compare:

```js
import { createHmac, timingSafeEqual } from 'node:crypto';

function verify(rawBody, signatureHeader, webhookSecretHex) {
  const mac = createHmac('sha256', Buffer.from(webhookSecretHex, 'hex'));
  const expected = `sha256=${mac.update(rawBody).digest('hex')}`;
  const a = Buffer.from(signatureHeader ?? '');
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
```

Other headers: `x-viewkey-watch-id` and `x-viewkey-event` (`balance_change`, `scan_complete`,
`status_change`, or a low‑credit warning). The header prefix and user‑agent are configurable on
`deliverWebhook({ headerPrefix, userAgent })`.

## Backend

The scanner client (`createNfptClient`) speaks this HTTP contract. Any service implementing it
works; [NFPT](https://github.com/FungeLLC/NFPT) is the reference. All requests send
`x-api-key: <apiKey>`; job reads/cancels also send `x-job-token: <jobToken>`.

| Method & path | Body | Success → returns |
| --- | --- | --- |
| `POST /api/wallet-scanner/monero/scan/job` | `{ address, viewKey, fromHeight }` | `202` `{ data: { jobId, jobToken } }` |
| `GET  /api/wallet-scanner/monero/scan/job/:jobId` | — | `200` `{ data: { job } }` · `404` gone · `403` bad token |
| `DELETE /api/wallet-scanner/monero/scan/job/:jobId` | — | `200` |
| `POST /api/wallet-scanner/orchard/scan-ufvk/job` | `{ ufvk, birthdayHeight, endHeight, autoDetect }` | `202` `{ data: { jobId, jobToken } }` |
| `GET  /api/wallet-scanner/orchard/scan-ufvk/job/:jobId` | — | `200` `{ data: { job } }` |
| `DELETE /api/wallet-scanner/orchard/scan-ufvk/job/:jobId` | — | `200` |
| `GET  /api/wallet-scanner/lightwallet/status` | — | `200` `{ data: { lightwallet } }` (health) |
| `POST /api/wallet-scanner/orchard/export-ufvk` | `{ mnemonic, network }` | `200` `{ data: { ufvk } }` (optional) |

The returned `job` object is normalised into a chain‑agnostic snapshot (`status`,
`scannedHeight`, `chainHeight`, balances) by `scanner.normaliseMonero` / `scanner.normaliseOrchard`.

> Scanning is **asynchronous job‑based**: a watch starts a job, then each poll GETs it. Backends
> are expected to age idle jobs out (the poller transparently restarts a job on `404`).

## Accepting XMR/ZEC payments

`runCryptoRecvTick` watches a receiving wallet's view key and credits matched payments:

```js
import {
  createPriceOracle, ensureCryptoTopupSchema, createQuote,
  runCryptoRecvTick, makeWatchCreditApplier
} from 'viewkey-watch';

ensureCryptoTopupSchema(db);
const price = createPriceOracle();              // CoinGecko by default
// createQuote(...) locks a USD↔coin rate and an attribution token
//   (unique low‑digit amount for Monero, memo for Zcash).
await runCryptoRecvTick({ db, nfptClient: nfpt, /* receiving wallet view key + addr */ });
```

See `crypto-price.js`, `crypto-topup-store.js` and `crypto-recv-poller.js` for the full options.

## API surface

The package root re‑exports both grouped namespaces and the common factories flat:

| Namespace | Module | What it covers |
| --- | --- | --- |
| `scanner` | `private-watch-nfpt.js` | wallet‑scanner client: start/poll/cancel jobs, health, derive UFVK, historical + receive scans |
| `watch` | `private-watch.js` | request validation, SSRF guards, credit‑meter math, webhook payload builders |
| `store` | `private-watch-store.js` | watch persistence (SQLite), credit top‑ups, stats |
| `cryptoKeys` | `private-watch-crypto.js` | AES‑256‑GCM view‑key encryption, webhook HMAC signing |
| `poller` | `private-watch-poller.js` | `runPollerTick` + `deliverWebhook` |
| `pricing` | `private-watch-pricing.js` | active‑load surge pricing for the credit meter |
| `price` | `crypto-price.js` | USD↔coin conversion + price oracle |
| `receiveStore` | `crypto-topup-store.js` | inbound payment quote persistence |
| `receivePoller` | `crypto-recv-poller.js` | `runCryptoRecvTick` inbound detection loop |

```js
import { scanner, watch, store } from 'viewkey-watch'; // grouped
import { createNfptClient, openWatchDb } from 'viewkey-watch'; // flat
```

## Security model

- **View keys cannot spend.** A leaked view key exposes transaction *visibility*, not funds.
- **Encrypted at rest.** View keys are stored AES‑256‑GCM‑encrypted under an operator master
  key (`parseMasterKey`); the plaintext only exists in memory during a scan.
- **Signed webhooks.** Per‑watch HMAC‑SHA256 secret; verify before trusting a delivery.
- **SSRF‑guarded webhook URLs.** `watch.assertWebhookUrlSafe` / `resolveAndValidateWatchRequest`
  reject loopback, RFC1918/CGNAT, link‑local and cloud‑metadata targets, then re‑check after DNS.
- **UFVK derivation from a seed is a convenience, not a default.** Prefer deriving client‑side /
  offline; transmitting a mnemonic to any server means trusting that server and the transport.

## Testing

```bash
npm install
npm test        # jest, ESM (node --experimental-vm-modules)
```

## License

[MIT](LICENSE)
