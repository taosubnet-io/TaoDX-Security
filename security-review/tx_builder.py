"""Transaction builder for Nova Wallet staking with 1% fee.

Builds unsigned `utility.batchAll` extrinsics that:
  1. Transfer the fee (default 1%) to the operator's wallet.
  2. Stake the remaining TAO into a subnet via ``subtensorModule.stake``.

The unsigned payload is returned as hex so the user can sign it in Nova
Wallet via WalletConnect, then submit the signed extrinsic back through
``/api/tx/submit``.

NOTE: This module uses **JSON-RPC** calls directly against the Bittensor
Finney endpoint instead of the heavy ``substrate-interface`` runtime
metadata download (which takes 30+ s on cold start).  The
``substrate-interface`` pip dependency is kept in requirements.txt for
potential future use (e.g. advanced SCALE encoding) but this module
avoids its heavy metadata operations for fast startup.
"""

import asyncio
import hashlib
import json
import logging
from typing import Any
from urllib.parse import quote

import aiohttp

from bot.config import BITTENSOR_RPC, FEE_WALLET_ADDRESS, FEE_PERCENT

_log = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────
_RAO_PER_TAO = 1_000_000_000  # 1 TAO = 1e9 RAO (RAO is the base unit)

# Bittensor SS58 prefix (network ID 42 for Bittensor)
_SS58_PREFIX = 42


def tao_to_rao(tao: float) -> int:
    """Convert a TAO amount to RAO (integer)."""
    return int(round(tao * _RAO_PER_TAO))


def _fee_split(amount_tao: float, fee_pct: float | None = None):
    """Return ``(fee_rao, stake_rao)`` after applying the fee percentage."""
    pct = fee_pct if fee_pct is not None else FEE_PERCENT
    fee_tao = amount_tao * (pct / 100.0)
    stake_tao = amount_tao - fee_tao
    return tao_to_rao(fee_tao), tao_to_rao(stake_tao), fee_tao, stake_tao


# ── JSON-RPC helper ──────────────────────────────────────────────────
async def _rpc_call(method: str, params: list[Any] | None = None) -> Any:
    """Send a single JSON-RPC request to the Bittensor node."""
    # Convert WebSocket URL to HTTP for simple RPC calls
    url = BITTENSOR_RPC
    if url.startswith("wss://"):
        url = "https://" + url[6:]
    elif url.startswith("ws://"):
        url = "http://" + url[5:]
    # Strip trailing port-only path (:443 → remove)
    if url.endswith(":443"):
        url = url[:-4]

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or [],
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(
            url,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            data = await resp.json()
            if "error" in data:
                err = data["error"]
                # Extract the human-readable message from the RPC error
                if isinstance(err, dict):
                    msg = err.get("message", str(err))
                    if err.get("data"):
                        msg = f"{msg}: {err['data']}"
                else:
                    msg = str(err)
                raise RuntimeError(f"RPC error: {msg}")
            return data.get("result")


async def get_account_nonce(address: str) -> int:
    """Fetch the current nonce for *address* from the chain."""
    result = await _rpc_call("system_accountNextIndex", [address])
    return int(result)


async def get_genesis_hash() -> str:
    """Fetch the genesis hash of the connected chain."""
    return await _rpc_call("chain_getBlockHash", [0])


async def get_runtime_version() -> dict:
    """Fetch spec_version and transaction_version."""
    result = await _rpc_call("state_getRuntimeVersion")
    return {
        "spec_version": result["specVersion"],
        "transaction_version": result["transactionVersion"],
    }


# ── Extrinsic building ───────────────────────────────────────────────

def build_stake_payload(
    sender: str,
    hotkey: str,
    netuid: int,
    amount_tao: float,
    fee_pct: float | None = None,
) -> dict:
    """Build the parameters for a batchAll staking extrinsic.

    Returns a dict with:
      - ``fee_rao``, ``stake_rao`` – the amounts (for display)
      - ``fee_tao``, ``stake_tao`` – human-readable amounts
      - ``calls`` – list of call descriptions (for the signing payload)
      - ``sender`` – the sending address

    The actual SCALE-encoded extrinsic is built by the frontend using
    the Polkadot.js API (loaded via CDN) so the signing happens entirely
    client-side in Nova Wallet.
    """
    fee_rao, stake_rao, fee_tao, stake_tao = _fee_split(amount_tao, fee_pct)

    calls = []

    # Call 1: Transfer fee to operator wallet
    if fee_rao > 0 and FEE_WALLET_ADDRESS:
        calls.append({
            "module": "Balances",
            "call": "transfer_keep_alive",
            "params": {
                "dest": FEE_WALLET_ADDRESS,
                "value": fee_rao,
            },
        })

    # Call 2: Stake into subnet
    calls.append({
        "module": "SubtensorModule",
        "call": "add_stake",
        "params": {
            "hotkey": hotkey,
            "netuid": netuid,
            "amount_staked": stake_rao,
        },
    })

    return {
        "sender": sender,
        "fee_rao": fee_rao,
        "stake_rao": stake_rao,
        "fee_tao": round(fee_tao, 9),
        "stake_tao": round(stake_tao, 9),
        "calls": calls,
    }


def build_unstake_payload(
    sender: str,
    hotkey: str,
    netuid: int,
    amount_alpha: float,
    alpha_price: float = 1.0,
    fee_pct: float | None = None,
) -> dict:
    """Build the parameters for a batchAll unstaking extrinsic.

    Returns a dict with:
      - ``fee_rao``, ``unstake_rao`` – the amounts in rao
      - ``fee_tao``, ``unstake_tao`` – human-readable amounts in TAO
      - ``unstake_alpha`` – Alpha amount being unstaked
      - ``calls`` – list of call descriptions (for the signing payload)
      - ``sender`` – the sending address

    *amount_alpha* is the number of Alpha tokens to unstake.  The chain
    converts Alpha → TAO via the subnet pool.  *alpha_price* (TAO per
    Alpha) is used to estimate the TAO output and compute the fee as a
    percentage of TAO received.
    """
    pct = fee_pct if fee_pct is not None else FEE_PERCENT
    # Estimate TAO received from unstaking Alpha
    estimated_tao = amount_alpha * alpha_price if alpha_price > 0 else amount_alpha
    fee_tao = estimated_tao * (pct / 100.0)
    fee_rao = tao_to_rao(fee_tao)
    # remove_stake amount is in Alpha-rao (same 1e9 scaling)
    unstake_rao = tao_to_rao(amount_alpha)

    calls = []

    # Call 1: Remove stake from subnet (Alpha → TAO conversion on-chain)
    calls.append({
        "module": "SubtensorModule",
        "call": "remove_stake",
        "params": {
            "hotkey": hotkey,
            "netuid": netuid,
            "amount_unstaked": unstake_rao,
        },
    })

    # Call 2: Transfer fee to operator wallet (from the received TAO)
    if fee_rao > 0 and FEE_WALLET_ADDRESS:
        calls.append({
            "module": "Balances",
            "call": "transfer_keep_alive",
            "params": {
                "dest": FEE_WALLET_ADDRESS,
                "value": fee_rao,
            },
        })

    return {
        "sender": sender,
        "fee_rao": fee_rao,
        "unstake_rao": unstake_rao,
        "fee_tao": round(fee_tao, 9),
        "unstake_tao": round(estimated_tao, 9),
        "unstake_alpha": round(amount_alpha, 9),
        "calls": calls,
    }


async def submit_signed_extrinsic(signed_hex: str) -> str:
    """Submit a signed extrinsic hex to the chain.

    Returns the transaction hash.
    """
    tx_hash = await _rpc_call("author_submitExtrinsic", [signed_hex])
    return tx_hash


def _extrinsic_hash(ext_hex: str) -> str:
    """Compute the Blake2-256 hash of an encoded extrinsic (same as Substrate)."""
    raw = ext_hex
    if raw.startswith("0x"):
        raw = raw[2:]
    return "0x" + hashlib.blake2b(bytes.fromhex(raw), digest_size=32).hexdigest()


async def get_extrinsic_status(tx_hash: str) -> str | None:
    """Check if a transaction has been included in a block.

    Returns ``"finalized"`` if found in a finalized block,
    ``"included"`` if found in a non-finalized block,
    ``"pending"`` if still in the pool or not yet seen,
    or ``None`` on error.

    Strategy:
      1. Scan recent finalized blocks for the extrinsic hash.
      2. If not found, check the pending tx pool.
      3. If not in the pool either, return ``"pending"`` — the tx
         may still be propagating or was dropped.  The frontend
         should keep polling and eventually time out with the hash
         for manual verification.
    """
    normalized = tx_hash.lower() if tx_hash else ""

    try:
        # 1. Scan finalized blocks (walk backwards up to 10 blocks)
        finalized_head = await _rpc_call("chain_getFinalizedHead")
        if finalized_head:
            block_hash = finalized_head
            for _ in range(10):
                if not block_hash:
                    break
                try:
                    block = await _rpc_call("chain_getBlock", [block_hash])
                    if not block:
                        break
                    extrinsics = block.get("block", {}).get("extrinsics", [])
                    for ext_hex in extrinsics:
                        if _extrinsic_hash(ext_hex).lower() == normalized:
                            _log.info("TX %s found in finalized block", tx_hash)
                            return "finalized"
                    # Walk to the parent block
                    parent = block.get("block", {}).get("header", {}).get("parentHash")
                    block_hash = parent
                except Exception:
                    break

        # 2. Check the pending transaction pool
        try:
            pending = await _rpc_call("author_pendingExtrinsics")
            if pending:
                for ext_hex in pending:
                    if _extrinsic_hash(ext_hex).lower() == normalized:
                        return "pending"
        except Exception:
            pass

        # 3. Not found in finalized blocks or pool — could still be in
        #    a non-finalized block, propagating, or dropped.
        #    Return "pending" so the frontend keeps polling rather than
        #    falsely claiming "included".
        return "pending"

    except Exception as exc:
        _log.warning("Failed to check tx status for %s: %s", tx_hash, exc)
        return None


# ── On-chain audit / proof ──────────────────────────────────────────

# How many recent blocks to scan when locating the extrinsic.  Bittensor
# block time is ~12 s, so 60 blocks ≈ 12 minutes — enough to find any
# tx the user just submitted, even with network jitter.
_AUDIT_SCAN_DEPTH = 60


def extrinsic_explorer_urls(tx_hash: str, block_hash: str | None = None) -> dict:
    """Build a map of public block-explorer URLs for *tx_hash*.

    These are independent third-party services — clicking them lets a
    skeptical user verify the transaction without trusting the bot.
    """
    rpc_for_pjs = BITTENSOR_RPC
    if rpc_for_pjs.startswith("https://"):
        rpc_for_pjs = "wss://" + rpc_for_pjs[8:]
    elif rpc_for_pjs.startswith("http://"):
        rpc_for_pjs = "ws://" + rpc_for_pjs[7:]
    pjs_rpc_enc = quote(rpc_for_pjs, safe="")

    urls: dict = {
        "taostats_extrinsic": f"https://taostats.io/extrinsic/{tx_hash}",
        "taostats_search": f"https://taostats.io/?search={tx_hash}",
    }
    if block_hash:
        urls["polkadot_js_block"] = (
            f"https://polkadot.js.org/apps/?rpc={pjs_rpc_enc}"
            f"#/explorer/query/{block_hash}"
        )
    urls["polkadot_js_decode"] = (
        f"https://polkadot.js.org/apps/?rpc={pjs_rpc_enc}#/extrinsics/decode"
    )
    return urls


async def _decode_extrinsic_calls_async(ext_hex: str) -> dict | None:
    """Best-effort SCALE decode of a signed extrinsic via substrate-interface.

    Uses the existing cached ``SubstrateInterface`` if available.  Returns
    ``None`` on any failure — the audit endpoint will still return the raw
    hex so users can decode it themselves in Polkadot.js Apps."""
    try:
        from bot.services.wc_substrate import ensure_substrate  # type: ignore
    except Exception:
        return None
    try:
        from scalecodec import ScaleBytes as _ScaleBytes  # type: ignore
    except Exception:
        try:
            from scalecodec.base import ScaleBytes as _ScaleBytes  # type: ignore
        except Exception:
            return None

    try:
        si = await ensure_substrate()
    except Exception as exc:
        _log.warning("Audit decode: substrate not available: %s", exc)
        return None

    def _decode():
        try:
            decoded = si.create_scale_object("Extrinsic", metadata=si.metadata)
            decoded.decode(_ScaleBytes(ext_hex))
            value = decoded.value
            call = value.get("call") if isinstance(value, dict) else None
            sender = value.get("address") if isinstance(value, dict) else None
            return {"sender": sender, "call": call}
        except Exception as exc:
            _log.warning("Audit decode failed: %s", exc)
            return None

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _decode)


async def get_extrinsic_audit(tx_hash: str) -> dict | None:
    """Locate an extrinsic on-chain and return everything needed to verify it.

    Returns a dict with:
      - ``found``           – bool
      - ``status``          – "finalized" | "included" | "not_found"
      - ``tx_hash``         – the queried hash (normalized 0x…)
      - ``block_hash``      – the block the extrinsic was included in (or ``None``)
      - ``block_number``    – the block number as integer (or ``None``)
      - ``extrinsic_index`` – position within the block (or ``None``)
      - ``extrinsic_hex``   – raw SCALE-encoded extrinsic from the chain
      - ``decoded``         – best-effort decoded {sender, call} (may be ``None``)
      - ``explorer_urls``   – dict of public explorer links for the tx
      - ``chain``           – the RPC endpoint the data came from

    Returns ``None`` only if the RPC itself failed (transient error).
    """
    if not tx_hash:
        return None
    normalized = tx_hash.lower() if tx_hash.startswith("0x") else "0x" + tx_hash.lower()

    finalized_hashes: set[str] = set()
    found_block_hash: str | None = None
    found_block_number: int | None = None
    found_index: int | None = None
    found_hex: str | None = None
    in_finalized = False

    try:
        # 1) Walk the finalized chain first
        try:
            head = await _rpc_call("chain_getFinalizedHead")
        except Exception:
            head = None

        block_hash = head
        for _ in range(_AUDIT_SCAN_DEPTH):
            if not block_hash:
                break
            finalized_hashes.add(block_hash)
            try:
                block = await _rpc_call("chain_getBlock", [block_hash])
            except Exception:
                break
            if not block:
                break
            extrinsics = block.get("block", {}).get("extrinsics", []) or []
            for idx, ext_hex in enumerate(extrinsics):
                if _extrinsic_hash(ext_hex).lower() == normalized:
                    found_block_hash = block_hash
                    found_index = idx
                    found_hex = ext_hex
                    in_finalized = True
                    break
            if found_hex:
                # Also resolve the block number
                try:
                    header = block.get("block", {}).get("header", {})
                    num_hex = header.get("number")
                    if num_hex:
                        found_block_number = int(num_hex, 16) if isinstance(num_hex, str) else int(num_hex)
                except Exception:
                    found_block_number = None
                break
            block_hash = block.get("block", {}).get("header", {}).get("parentHash")

        # 2) If not in the finalized chain, walk the head chain (may include unfinalized blocks)
        if not found_hex:
            try:
                head = await _rpc_call("chain_getBlockHash")
            except Exception:
                head = None
            block_hash = head
            for _ in range(_AUDIT_SCAN_DEPTH):
                if not block_hash:
                    break
                if block_hash in finalized_hashes:
                    # Already scanned in the finalized walk above
                    try:
                        block = await _rpc_call("chain_getBlock", [block_hash])
                    except Exception:
                        break
                    if not block:
                        break
                    block_hash = block.get("block", {}).get("header", {}).get("parentHash")
                    continue
                try:
                    block = await _rpc_call("chain_getBlock", [block_hash])
                except Exception:
                    break
                if not block:
                    break
                extrinsics = block.get("block", {}).get("extrinsics", []) or []
                for idx, ext_hex in enumerate(extrinsics):
                    if _extrinsic_hash(ext_hex).lower() == normalized:
                        found_block_hash = block_hash
                        found_index = idx
                        found_hex = ext_hex
                        in_finalized = False
                        break
                if found_hex:
                    try:
                        header = block.get("block", {}).get("header", {})
                        num_hex = header.get("number")
                        if num_hex:
                            found_block_number = int(num_hex, 16) if isinstance(num_hex, str) else int(num_hex)
                    except Exception:
                        found_block_number = None
                    break
                block_hash = block.get("block", {}).get("header", {}).get("parentHash")

    except Exception as exc:
        _log.warning("Audit lookup failed for %s: %s", tx_hash, exc)
        return None

    # Best-effort decode (don't fail the audit if this errors)
    decoded = None
    if found_hex:
        try:
            decoded = await _decode_extrinsic_calls_async(found_hex)
        except Exception:
            decoded = None

    if not found_hex:
        return {
            "found": False,
            "status": "not_found",
            "tx_hash": normalized,
            "block_hash": None,
            "block_number": None,
            "extrinsic_index": None,
            "extrinsic_hex": None,
            "decoded": None,
            "explorer_urls": extrinsic_explorer_urls(normalized),
            "chain": BITTENSOR_RPC,
        }

    return {
        "found": True,
        "status": "finalized" if in_finalized else "included",
        "tx_hash": normalized,
        "block_hash": found_block_hash,
        "block_number": found_block_number,
        "extrinsic_index": found_index,
        "extrinsic_hex": found_hex,
        "decoded": decoded,
        "explorer_urls": extrinsic_explorer_urls(normalized, found_block_hash),
        "chain": BITTENSOR_RPC,
    }
