# Security Policy

This document is the single point of truth for how the TAO Subnet Bot
handles user funds and what you can do if you want to verify that for
yourself — or report a problem.

## Core promise

**The bot never sees your private keys, mnemonics, or seed phrases.**

Every stake and unstake is signed locally inside Nova Wallet or
Talisman on your own device via WalletConnect v2. The server only:

1. Builds an *unsigned* extrinsic payload.
2. Receives the *signed* extrinsic back from the wallet.
3. Forwards that signed extrinsic to the public Bittensor RPC.

If someone stole the bot's entire server — database, source code, env
vars, everything — they still could not move a single TAO from any
user's wallet. There is no key material to steal.

## Threat model

The bot is designed against the following realistic threats:

| Threat | Mitigation |
|---|---|
| Server is compromised (full RCE). | No private keys exist on the server. The attacker can read the DB (public wallet addresses + tx hashes) but cannot forge a signature. |
| Operator turns malicious. | Same as above. The operator cannot produce a valid signed extrinsic without the user approving it in their wallet app. Every extrinsic the bot submits is publicly auditable on-chain. |
| Fee is secretly inflated beyond 1 %. | The fee is encoded as an explicit `Balances.transfer_keep_alive(FEE_WALLET, fee_rao)` call in a `utility.batch_all`. Nova Wallet displays both calls before signing. The fee wallet is public (`GET /api/tx/transparency`); anyone can watch it on Taostats. |
| Bot substitutes a different hotkey or netuid after the user clicks. | The user sees the exact hotkey, netuid, and amount in Nova Wallet before approving. Any post-signature mutation invalidates the signature — the chain rejects it with code 1010. |
| Replay of an old signed extrinsic. | Every extrinsic uses a mortal era (64 blocks ≈ 6.4 minutes) plus a per-account nonce. After the era expires or the nonce is used, replay is impossible. |
| Rate-limited RPC lets the bot drop a user's tx silently. | `tx_submit` records the hash in the DB before returning; the user can poll `/api/tx/status/{hash}` or query the chain directly. |
| SQL injection / CSRF / standard web vulns. | All DB queries use parameterised statements; all write endpoints require JSON body with typed validation; SS58 and hex inputs are regex-validated before processing. |

## Out of scope — things this document does *not* promise

- **Wallet security.** If your phone is compromised and the attacker can
  approve transactions in your Nova Wallet, no server-side mitigation
  can help. Keep your device secure.
- **Bittensor chain correctness.** We rely on the public Bittensor
  runtime to execute extrinsics honestly. If there is a consensus bug
  in Bittensor itself, that is out of scope.
- **Third-party APIs** (Taostats, CoinGecko, ChainGPT). These are
  read-only data sources; they cannot move funds. If any of them is
  unavailable, the bot degrades gracefully.
- **AI-generated analysis** (scoring, pump engine, chat). These are
  opinions, not financial advice. They have no wallet access.

## Review package

The complete wallet-touching surface area of the bot — about 2 300
lines of Python — is extracted into [`security-review/`](./security-review/)
so that auditors can review it without needing access to the rest of
the codebase (which contains proprietary scoring / ranking logic
unrelated to payments).

See [`security-review/README.md`](./security-review/README.md) for the
file list, the formal security properties P1–P5, and step-by-step
reproduction instructions.

## Verify it yourself

### Quick check (30 seconds)

Run these commands at the repo root. Each should produce **zero**
matches related to the bot storing its own keys:

```bash
# No mnemonics, seed phrases, or private key material anywhere
grep -RniE 'mnemonic|seed[_ -]?phrase|private[_ -]?key' \
    --include='*.py' --include='*.html' --include='*.js' \
    bot/ wallet_manager.py Miniapp/

# No keystore, wallet creation, or signing libraries with our own keys
grep -RniE 'from_mnemonic|create_keypair|\.sign\(|keypair\.create' \
    --include='*.py' bot/ wallet_manager.py
```

You will find:
- Matches for `sign_message`, `signTransaction`, `signature` — these
  are all on the *verification* or *WalletConnect relay* side.
- `Keypair(public_key=…)` in `bot/services/wc_substrate.py` — this
  creates a keypair from the sender's *public* key only, for signature
  reconstruction; `private_key` is never passed.
- `secret_key = hmac.new(…)` in `bot/utils/telegram_auth.py` — this is
  Telegram's `initData` HMAC validation, unrelated to wallets.

No matches for user mnemonics or bot-owned private keys. There are
none.

### Full check (2 minutes)

```bash
python verify_security.py
```

The script:

1. Hashes `security-review/tx_builder.py`,
   `security-review/wc_substrate.py`, and
   `security-review/wallet_manager.py` with SHA-256 and compares to
   `security-review/FINGERPRINTS.txt`.
2. Hashes the live-source counterparts
   (`bot/services/tx_builder.py`, `bot/services/wc_substrate.py`,
   `wallet_manager.py`) and confirms they match the review copies
   byte-for-byte.
3. Greps the entire repository for forbidden patterns (mnemonic
   handling, unsafe signing, outbound calls to undisclosed hosts).
4. Prints a PASS / FAIL report.

If you run it and it fails, do not trust the deployment until it
passes again.

### On-chain check (any time)

For any transaction the bot has ever submitted, hit:

```
GET https://<your-bot-domain>/api/tx/audit/{tx_hash}
```

You get back the raw SCALE-encoded extrinsic pulled directly from the
Bittensor chain, plus links to Taostats and Polkadot.js Apps for
independent verification. What the bot claimed and what the chain
recorded should match exactly.

You can also hit:

```
GET https://<your-bot-domain>/api/tx/transparency
```

to see the operator fee wallet, the fee percentage, and direct links
to watch that wallet on Taostats in real time.

## Reporting a vulnerability

If you believe you have found a vulnerability that could affect user
funds, please **do not open a public issue**. Instead:

1. Email the operator (contact link in the bot's `/start` response) or
   message the operator's Telegram account.
2. Include: a description of the issue, a proof-of-concept if you have
   one, and the commit hash you were testing against.
3. Give the operator a reasonable window (7–14 days depending on
   severity) to ship a fix before public disclosure.

### Scope

Out of scope: social engineering, physical attacks, attacks requiring
a compromised user device, UI polish issues, issues already disclosed,
and issues in third-party dependencies (report those upstream).

## Supply chain

- Python dependencies are pinned in `requirements.txt` and installed
  via `pip`. No binary artifacts are committed.
- The bot is deployed on a standard platform (Render / Heroku) with
  environment variables for all secrets (bot token, API keys, fee
  wallet). No secrets are in the repo — `.env.example` contains only
  placeholders.
- No code is fetched at runtime. The bot runs what was on disk at
  deploy time.

## Version

This policy applies to commits on branch
`claude/improve-stake-security-LIASL` and subsequent merges to `main`.
The fingerprint file `security-review/FINGERPRINTS.txt` pins the exact
commit hash the most recent review snapshot was captured from.
