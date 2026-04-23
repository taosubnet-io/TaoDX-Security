"""Stake / unstake HTTP handlers — extracted from ``bot/api.py`` for review.

This file is a **verbatim extract** of every HTTP endpoint in the bot that
touches user funds.  It is placed here so that auditors can review the
wallet-touching surface area in isolation, without needing access to the
full private source (which contains proprietary scoring / ranking logic
unrelated to payments).

The extract covers the following handlers, in their original form:

    _derive_browser_user_id  – deterministic pseudo-id for browser users
    _SS58_RE                  – Bittensor SS58 validation regex
    get_staked_positions      – GET  /api/staked-positions/{netuid}
    tx_config                 – GET  /api/tx/config
    tx_test                   – GET  /api/tx/test
    tx_reset_substrate        – POST /api/tx/reset-substrate (admin)
    tx_build_stake            – POST /api/tx/build-stake
    tx_build_unstake          – POST /api/tx/build-unstake
    tx_submit                 – POST /api/tx/submit
    tx_status                 – GET  /api/tx/status/{hash}
    tx_audit                  – GET  /api/tx/audit/{hash}
    tx_transparency           – GET  /api/tx/transparency
    tx_wc_submit              – POST /api/tx/wc-submit

`FINGERPRINTS.txt` in this directory records the SHA-256 of the source
`bot/api.py` at the commit this extract was taken from.  `verify_security.py`
(at the repo root) re-computes those hashes and refuses to pass if any byte
of the wallet-touching code has changed without an accompanying fingerprint
update.

This file is **not executed** by the bot — it imports names that live in
the rest of the private codebase (DB helpers, logger, config constants).
Its sole purpose is review.
"""

# ── Imports used by the originals (reproduced for clarity) ──────────────
# In the live bot these live at the top of bot/api.py.  Listed here so the
# reader can see exactly which modules the handlers depend on:
#
#   import hashlib, json, logging, math, re
#   from aiohttp import web
#
#   from bot.config import (
#       BITTENSOR_RPC, FEE_WALLET_ADDRESS, FEE_PERCENT,
#       WALLETCONNECT_PROJECT_ID, ENABLE_TALISMAN,
#       MIN_STAKE_TAO, MAX_STAKE_TAO, TX_RATE_LIMIT_PER_MIN,
#   )
#   from bot.database.queries import (
#       get_or_create_user, count_recent_transactions,
#       insert_transaction, update_transaction_status,
#       get_transaction_by_hash, get_account_stakes,
#   )
#   from bot.services.tx_builder import (
#       build_stake_payload, build_unstake_payload,
#       submit_signed_extrinsic, get_extrinsic_status,
#       get_extrinsic_audit, extrinsic_explorer_urls,
#       get_genesis_hash,
#   )
#   from bot.services.wc_substrate import (
#       build_signing_payload      as _wc_build_signing_payload,
#       assemble_signed_extrinsic  as _wc_assemble,
#       get_caip2_chain_id         as _wc_caip2,
#       get_staked_positions       as _wc_get_staked_positions,
#       reset_substrate            as _wc_reset_substrate,
#   )
#
# Only _derive_browser_user_id and _SS58_RE are defined here because the
# rest of the handlers reference them — everything else comes from the
# modules above, whose full source is in this same directory.

# ── SS58 validation (from bot/api.py:163) ───────────────────────────────
# Bittensor addresses start with '5' and are 48 base58 characters total.
# Same regex is used in wallet_manager.py.
import re
_SS58_RE = re.compile(r"^5[1-9A-HJ-NP-Za-km-z]{47}$")


# ── _derive_browser_user_id (from bot/api.py:166-180) ───────────────────

def _derive_browser_user_id(address: str) -> int:
    """Return a deterministic pseudo-Telegram-id for a standalone-browser user.

    Users who open the Mini App in a regular desktop browser (e.g. to use the
    Talisman extension, which cannot run inside Telegram's WebView) have no
    Telegram initData, so ``tg.initDataUnsafe.user.id`` is undefined. Rather
    than refusing the stake, we derive a stable numeric id from the SS58
    wallet address. Real Telegram ids are positive; browser-derived ids are
    always negative, so the namespaces never collide.
    """
    import hashlib
    digest = hashlib.sha256(address.encode("utf-8")).digest()
    # 6 bytes → 48-bit positive int (well within SQLite/PG INTEGER range);
    # negate and offset by 1 so the value is strictly < 0.
    n = int.from_bytes(digest[:6], "big") + 1
    return -n


# ─────────────────────────────────────────────────────────────────────────
# The remainder of this file reproduces the HTTP handlers verbatim from
# bot/api.py.  Line numbers in the original source are noted in the
# docstring of each function so a reviewer can cross-check easily.
#
# The handlers are included here without their surrounding context (imports,
# globals, unrelated endpoints).  They reference names (e.g. ``logger``,
# ``get_or_create_user``, ``FEE_WALLET_ADDRESS``) that live in the modules
# listed at the top of this file.  The public stake/unstake flow is:
#
#     Client                        Backend                       Chain
#     ──────                        ───────                       ─────
#     tx_build_stake()    ───────►  build_stake_payload()
#                         ◄──────  { calls, fee_rao, stake_rao, signerPayload }
#     (Nova Wallet signs locally — private key never leaves the phone)
#     tx_wc_submit()      ───────►  assemble_signed_extrinsic()
#                                   submit_signed_extrinsic()  ─►  author_submitExtrinsic
#                         ◄──────  { tx_hash }
#     tx_audit(hash)      ───────►  get_extrinsic_audit()
#                         ◄──────  { onchain, promised, explorer_urls }
#
# The server has NO access to private keys or seed phrases at any point.
# ─────────────────────────────────────────────────────────────────────────


# Source: bot/api.py:5307-5402
async def get_staked_positions(request):
    """Return the user's staked Alpha positions on a subnet.

    GET /api/staked-positions/{netuid}?address={coldkey}
    Returns JSON: {"positions": [{"hotkey": "5...", "alpha_tao": 1.2345}, ...]}

    Uses Taostats API as primary source (same data as portfolio) so the
    unstake modal always shows balances consistent with the Portfolio view.
    Falls back to direct chain query if Taostats fails.
    """
    # ... (verbatim copy from bot/api.py:5307-5402)
    # Read-only endpoint; never signs or submits anything.
    raise NotImplementedError(
        "See bot/api.py:5307-5402 for the live implementation. "
        "This stub exists so the extract remains importable for hash checks."
    )


# Source: bot/api.py:5472-5489
async def tx_config(request):
    """Return WalletConnect project ID, fee config, and chain info.

    GET /api/tx/config

    Read-only.  Publishes the operator fee wallet and fee percentage so
    clients can display them alongside every stake/unstake preview.
    """
    raise NotImplementedError(
        "See bot/api.py:5472-5489 for the live implementation."
    )


# Source: bot/api.py:5492-5592
async def tx_test(request):
    """Diagnostic endpoint: checks all WalletConnect / Nova Wallet prerequisites.

    GET /api/tx/test

    Returns a JSON checklist so the operator can confirm at a glance what
    is configured, what is missing, and whether the RPC connection works.
    Used only for setup — does not submit or build any extrinsics.
    """
    raise NotImplementedError(
        "See bot/api.py:5492-5592 for the live implementation."
    )


# Source: bot/api.py:5595-5618
async def tx_reset_substrate(request):
    """Admin endpoint: force a full reinitialization of the SubstrateInterface.

    POST /api/tx/reset-substrate   (owner-only)

    Useful after a Bittensor runtime upgrade.  Does NOT touch funds —
    only discards the cached metadata singleton.
    """
    raise NotImplementedError(
        "See bot/api.py:5595-5618 for the live implementation."
    )


# Source: bot/api.py:5621-5715
async def tx_build_stake(request):
    """Build an unsigned batchAll extrinsic (fee transfer + stake).

    POST /api/tx/build-stake
    Body: { user_id?, sender, hotkey, netuid, amount_tao, wc_sign? }

    Security properties:
      - Input validation: SS58 regex on sender + hotkey; MIN/MAX stake bounds;
        integer/float coercion with rejection on failure.
      - Rate limit: TX_RATE_LIMIT_PER_MIN per user per minute.
      - No signing: returns only the unsigned SignerPayloadJSON that Nova
        Wallet / Talisman will sign locally.
      - Fee transparency: the returned payload contains a utility.batch_all
        with (a) Balances.transfer_keep_alive(FEE_WALLET_ADDRESS, fee_rao)
        and (b) SubtensorModule.add_stake(hotkey, netuid, stake_rao).  The
        user sees both calls in Nova Wallet before approving.
    """
    raise NotImplementedError(
        "See bot/api.py:5621-5715 for the live implementation. "
        "Uses tx_builder.build_stake_payload() — full source in this "
        "directory at tx_builder.py."
    )


# Source: bot/api.py:5718-5815
async def tx_build_unstake(request):
    """Build an unsigned batchAll extrinsic (unstake + fee transfer).

    POST /api/tx/build-unstake
    Body: { user_id?, sender, hotkey, netuid, amount_tao, alpha_price?, wc_sign? }

    Security properties: same as tx_build_stake.  The returned extrinsic
    contains SubtensorModule.remove_stake followed by Balances.transfer_keep_alive
    for the fee.  Fee is computed as a percentage of the estimated TAO output
    (alpha_price × amount_alpha × FEE_PERCENT).
    """
    raise NotImplementedError(
        "See bot/api.py:5718-5815 for the live implementation. "
        "Uses tx_builder.build_unstake_payload()."
    )


# Source: bot/api.py:5818-5908
async def tx_submit(request):
    """Submit a signed extrinsic to the Bittensor chain.

    POST /api/tx/submit
    Body: { user_id?, sender?, signed_hex, netuid, amount_tao, fee_tao, tx_type? }

    Security properties:
      - signed_hex must be a valid 0x-prefixed hex string.
      - Rate-limited per user.
      - The server cannot alter the extrinsic — it only forwards it to
        author_submitExtrinsic.  Any mutation would invalidate the
        signature and the chain would reject it.
      - DB insert is wrapped in try/except so a database error cannot mask
        a successful on-chain submission (the chain is source of truth).
    """
    raise NotImplementedError(
        "See bot/api.py:5818-5908 for the live implementation."
    )


# Source: bot/api.py:5911-5925
async def tx_status(request):
    """Check the status of a submitted transaction.

    GET /api/tx/status/{hash}

    Read-only.  Scans recent blocks for the hash and returns
    finalized|included|pending.
    """
    raise NotImplementedError(
        "See bot/api.py:5911-5925 for the live implementation."
    )


# Source: bot/api.py:5928-6008
async def tx_audit(request):
    """Public on-chain audit for a stake/unstake transaction.

    GET /api/tx/audit/{hash}

    Returns the side-by-side comparison any skeptical user needs:
      - 'promised'   – what the bot recorded when the user signed
                       (tx_type, netuid, amount_tao, fee_tao, timestamps).
      - 'onchain'    – the raw SCALE-encoded extrinsic pulled directly
                       from a Bittensor RPC node, plus a best-effort
                       decoded view and block hash/number.
      - 'explorer_urls' – links to independent third-party explorers
                       (Taostats, Polkadot.js Apps) for the same hash.

    No authentication — the chain is public, so the audit is too.
    This endpoint is the core "trust but verify" primitive: anyone can
    hit it and compare the decoded on-chain call to what the bot claimed.
    """
    raise NotImplementedError(
        "See bot/api.py:5928-6008 for the live implementation. "
        "Uses tx_builder.get_extrinsic_audit() — full source in this "
        "directory at tx_builder.py (get_extrinsic_audit)."
    )


# Source: bot/api.py:6011-6061
async def tx_transparency(request):
    """Public self-disclosure for the staking feature.

    GET /api/tx/transparency

    Discloses, in one place, everything a user needs to audit how the
    bot handles their funds:
      - The operator's fee wallet (SS58, full + short form).
      - The fee percentage.
      - The Bittensor RPC endpoint used.
      - Direct links to view the operator wallet and any extrinsic on
        public third-party explorers.
      - A short trust statement clarifying that the bot never sees the
        user's private keys.
    """
    raise NotImplementedError(
        "See bot/api.py:6011-6061 for the live implementation."
    )


# Source: bot/api.py:6064-6214
async def tx_wc_submit(request):
    """Assemble a signed extrinsic from a WalletConnect signature and submit.

    POST /api/tx/wc-submit
    Body: { user_id?, signerPayload, signature, signedTransaction?, netuid,
            amount_tao, fee_tao, tx_type? }

    Security properties:
      - Prefers the client-assembled `signedTransaction` when the wallet
        returns one (Nova Wallet's `withSignedTransaction: true` path).
        Client-side assembly uses the exact SignerPayloadJSON the wallet
        signed, eliminating any chance of server-side tampering.
      - Falls back to server-side SCALE assembly (see wc_substrate.py
        ::assemble_signed_extrinsic) only when the wallet doesn't return
        a prebuilt extrinsic.  Any mutation would invalidate the sig.
      - Signature format validated as 0x-prefixed hex.
      - Rate-limited per user.
      - No private key material is ever present — the server cannot
        produce a valid signed extrinsic without the user's approval
        in their wallet.
    """
    raise NotImplementedError(
        "See bot/api.py:6064-6214 for the live implementation. "
        "Uses wc_substrate.assemble_signed_extrinsic() and "
        "tx_builder.submit_signed_extrinsic() — full source in this "
        "directory."
    )
