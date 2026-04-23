# Security Review Package

This directory contains the **complete wallet-touching surface area** of the
TAO Subnet Bot, extracted into a self-contained review package so that
sceptical users and independent auditors can verify exactly what happens
to their TAO — without needing access to the rest of the codebase
(which contains proprietary scoring / ranking logic that is unrelated
to payments).

## TL;DR — Why you can trust this bot without a paid audit

1. **The bot never sees your private keys.** Every stake and unstake is
   signed locally inside Nova Wallet or Talisman on your own device via
   WalletConnect v2. The server only builds unsigned payloads and
   forwards signed extrinsics to the Bittensor RPC.
2. **Every transaction is independently verifiable.** The bot exposes
   `GET /api/tx/audit/{hash}` which returns the raw, SCALE-encoded
   extrinsic pulled directly from the chain — plus links to Taostats
   and Polkadot.js Apps so you can cross-check with third-party
   explorers.
3. **The operator fee wallet is public.** `GET /api/tx/transparency`
   discloses the SS58 address of the fee wallet, the fee percentage,
   and links directly to Taostats for that wallet. You can see in
   real time that the fee is exactly 1 % and goes only to the
   disclosed address.
4. **The code in this directory is everything.** Any code path not
   included here does not — and cannot — move user funds.

## Can public viewers change anything?

**No.** This directory is a read-only snapshot for review purposes.

- Viewers on GitHub see the code but cannot modify it. Only repository
  collaborators with explicit write access can push.
- Anyone can open a Pull Request, but the operator must manually review
  and merge it — a PR cannot reach production on its own.
- The live bot runs whatever code was deployed at deployment time. It
  does not pull the latest `main` at runtime. A malicious merge (even
  if one somehow happened) would only affect the next deploy.
- The self-verification script (`verify_security.py` at the repo root)
  runs entirely on the auditor's own machine. It cannot reach the
  server and has no write permissions anywhere.

So: maximum transparency, zero loss of operator control.

## Scope — what is in this package

| File in this directory | Source path in the live bot | Lines | What it does |
|---|---|---:|---|
| `tx_builder.py` | `bot/services/tx_builder.py` | 536 | Builds unsigned `utility.batch_all` extrinsics (fee + stake, or unstake + fee), submits signed extrinsics to the chain, runs the on-chain audit for any tx hash. |
| `wc_substrate.py` | `bot/services/wc_substrate.py` | 757 | WalletConnect / Substrate bridge. SCALE-encodes the signing payload, assembles the final signed extrinsic from the external wallet signature, queries staked positions. |
| `wallet_manager.py` | `wallet_manager.py` (root) | 92 | Read-only SS58 address validation and Taostats staking data lookup. No signing. |
| `api_tx_handlers.py` | `bot/api.py:166-180` and `bot/api.py:5307-6214` | ~900 | All HTTP endpoints under `/api/tx/*` and `/api/staked-positions/*`. This file includes the handler docstrings and security notes; the full executable source lives inline in `bot/api.py`, but every handler is reproduced here with a line-number reference so you can diff it against the original. |

**Total wallet-touching surface area: ~2 300 lines of Python.** This is
small enough for one engineer to review thoroughly in an afternoon.

### Out of scope — and why

Everything else in the repository is *analytics*, *UI*, or *scoring*:

- `bot/pump_engine/*` — proprietary XGBoost model, backtester, snapshots.
- `bot/services/score_engine.py`, `bot/services/score_scheduler.py` — ranking logic.
- `bot/handlers/*`, `Miniapp/*`, `bot/services/chaingpt*`, `bot/services/coingecko.py`, etc. — user-facing UI and third-party data sources.

None of these have wallet access. None can move user funds. They are
intentionally excluded from this review package to protect operator IP.
If you want to prove this independently, run the root-level
`verify_security.py` script — it greps the *entire* repository for
private-key handling, key storage, and outbound calls to anything
other than the disclosed endpoints. You will not find any key
material because there is none.

## Security properties — formal claims

The following properties hold for the code in this directory. They are
claims an auditor can attempt to break. If any fails, it is a critical
bug and the operator would like to know immediately (see
[`SECURITY.md`](../SECURITY.md) at the repo root for reporting).

### P1 — No key material

The bot never generates, derives, stores, imports, or transmits any of:
secret keys, private keys, mnemonics, seed phrases, keystores, or
signing entropy of any kind. The only cryptographic code present is
*public-key decoding* for SS58 address validation and *signature
verification* formatting for WalletConnect payload assembly — both
strictly read/format operations.

**How to verify:**
```
grep -RniE 'private[_ ]?key|mnemonic|seed[_ ]?phrase|keystore|secret[_ ]?key|sign_message' security-review/
```
Expected: zero matches referring to the bot's own keys. Matches like
`secret_key` in `bot/utils/telegram_auth.py` refer to Telegram's
`initData` HMAC validation, unrelated to wallets.

### P2 — Non-custodial signing

Every `stake` and `unstake` extrinsic is signed *outside* the server,
inside the user's wallet app, using the standard WalletConnect v2
`polkadot_signTransaction` method. The server receives only the
post-hoc signature. It cannot produce a valid signature without user
action, and cannot mutate the signed extrinsic without invalidating
the signature (the chain will reject it with
`Transaction has a bad signature (code 1010)`).

**How to verify:** read `wc_substrate.py::assemble_signed_extrinsic`
and confirm that the only signature handling is parsing the hex
string the wallet returned and concatenating it with the sender
pubkey and call data. No `Keypair.sign()` is ever called with a
non-empty private key (the `Keypair` object is constructed from the
sender's public key only, with `private_key=None`).

### P3 — Fee transparency

Every stake/unstake extrinsic is a `utility.batch_all` containing
exactly two calls:

- `Balances.transfer_keep_alive(dest=FEE_WALLET_ADDRESS, value=fee_rao)`
- `SubtensorModule.add_stake` (or `remove_stake`) with the remaining amount.

`FEE_WALLET_ADDRESS` and `FEE_PERCENT` are loaded from environment
variables at startup and returned as-is by `GET /api/tx/transparency`.
The fee is computed client-side in the payload builder
(`tx_builder.py::_fee_split`) and the user sees both calls listed in
their wallet app before approving.

**How to verify:** read `tx_builder.py::build_stake_payload` and
`build_unstake_payload`. The entire fee logic is 5 lines of
multiplication in `_fee_split`.

### P4 — On-chain auditability

For any `tx_hash` the bot has ever submitted, the user can retrieve:

- The raw SCALE-encoded extrinsic from the chain (`extrinsic_hex`).
- The block hash, block number, and index within the block.
- A best-effort decoded view of the calls and sender.
- Links to Taostats and Polkadot.js Apps that show the same data.

Served by `tx_builder.py::get_extrinsic_audit` via the
`GET /api/tx/audit/{hash}` endpoint. The endpoint requires no
authentication because the chain is public.

### P5 — Input bounds and rate limits

All stake/unstake endpoints validate:

- SS58 regex on sender and hotkey (`^5[1-9A-HJ-NP-Za-km-z]{47}$`).
- Amount bounds: `MIN_STAKE_TAO ≤ amount ≤ MAX_STAKE_TAO`.
- Rate limit: `TX_RATE_LIMIT_PER_MIN` submissions per user per minute
  (enforced via `count_recent_transactions` in the DB).
- Hex regex on signed extrinsic and signature (`^0x[0-9a-fA-F]+$`).

## How to reproduce this review package

1. Clone the live repo (or the subset your auditor received).
2. Run the self-verification script at the repo root:

   ```
   python verify_security.py
   ```

   It re-computes the SHA-256 of every file in this directory against
   `FINGERPRINTS.txt`, greps the full repo for forbidden patterns
   (private key handling, hardcoded secrets, outbound calls to
   undisclosed endpoints), and prints a PASS/FAIL report.

3. Compare `tx_builder.py` in this directory to
   `bot/services/tx_builder.py` — they must be byte-identical. Same
   for `wc_substrate.py` and `wallet_manager.py`. If they differ, the
   review package is stale and should not be trusted until
   regenerated.

4. Read the four files. The total is ~2 300 lines. Focus on the
   properties P1–P5 above.

## Bounty

If you can demonstrate any practical exploit against user funds in
the code in this directory — including (but not limited to) a
server-side signing vulnerability, a fee-diversion bug, a bypass of
the amount bounds, or a way to replay a signed extrinsic with a
modified call — contact the operator before disclosing. Bounty
details are in [`SECURITY.md`](../SECURITY.md).
