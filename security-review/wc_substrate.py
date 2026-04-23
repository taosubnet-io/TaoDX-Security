"""WalletConnect v2 ↔ Substrate helpers.

Builds WalletConnect-compatible ``SignerPayloadJSON`` objects and assembles
fully-signed extrinsics from an external (Nova Wallet) signature so the
frontend never needs heavy Polkadot.js libraries.

Uses ``substrate-interface`` (already in requirements.txt) for metadata and
SCALE encoding.  A **lazy singleton** avoids the 30 s cold-start of full
metadata download until the first actual WC signing request.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import struct
import threading
import time
from typing import Any

from substrateinterface import SubstrateInterface
from substrateinterface.utils.ss58 import ss58_decode

from bot.config import BITTENSOR_RPC

_log = logging.getLogger(__name__)

# Bittensor SS58 prefix (network ID 42 for Bittensor)
_SS58_PREFIX = 42

# Mortal era validity window (in blocks).  At 12 s per block this gives
# ~6.4 minutes for the user to review and sign in Nova Wallet.
_MORTAL_ERA_PERIOD = 64

# How long (seconds) to cache a failed init before retrying.
_INIT_ERROR_TTL = 120

# Force a fresh connection when the existing one is older than this (seconds).
# WebSocket connections can silently go stale, returning cached/outdated data.
_MAX_CONNECTION_AGE = 300  # 5 minutes

# ── Lazy singleton ───────────────────────────────────────────────────
_substrate: SubstrateInterface | None = None
_substrate_lock = threading.Lock()
_init_error: str | None = None
_init_error_ts: float = 0.0
_substrate_created_ts: float = 0.0


def _get_substrate() -> SubstrateInterface:
    """Return a cached ``SubstrateInterface`` instance (thread-safe lazy init).

    The first call downloads runtime metadata (~2-5 s); subsequent calls are
    instant.  A failed init is retried after ``_INIT_ERROR_TTL`` seconds so
    transient network problems don't permanently block staking.

    Connections older than ``_MAX_CONNECTION_AGE`` are automatically replaced
    to avoid returning stale chain data from a dormant WebSocket.
    """
    global _substrate, _init_error, _init_error_ts, _substrate_created_ts
    # Check for stale connection (older than _MAX_CONNECTION_AGE)
    if _substrate is not None:
        if (time.time() - _substrate_created_ts) > _MAX_CONNECTION_AGE:
            _log.info("[WC-Sub] Connection is %ds old, refreshing",
                      int(time.time() - _substrate_created_ts))
            with _substrate_lock:
                _substrate = None
        else:
            return _substrate
    with _substrate_lock:
        if _substrate is not None:          # double-checked locking
            return _substrate
        # Clear a stale init error so we can retry after transient failures.
        if _init_error and (time.time() - _init_error_ts) > _INIT_ERROR_TTL:
            _log.info("[WC-Sub] Clearing stale init error, retrying connection")
            _init_error = None
        if _init_error:
            raise RuntimeError(_init_error)
        try:
            url = BITTENSOR_RPC
            _log.info("[WC-Sub] Connecting to %s …", url)
            si = SubstrateInterface(url=url)
            _substrate = si
            _substrate_created_ts = time.time()
            _log.info("[WC-Sub] Connected.  Runtime: spec_version=%s", si.runtime_version)
            return si
        except Exception as exc:
            _init_error = str(exc)
            _init_error_ts = time.time()
            _log.error("[WC-Sub] Failed to connect to chain: %s", exc)
            raise


def reset_substrate() -> None:
    """Force reinitialization of the ``SubstrateInterface`` singleton.

    Call this when you detect a runtime upgrade or want to clear a cached
    init error immediately.
    """
    global _substrate, _init_error, _init_error_ts, _substrate_created_ts
    with _substrate_lock:
        _substrate = None
        _init_error = None
        _init_error_ts = 0.0
        _substrate_created_ts = 0.0
    _log.info("[WC-Sub] Substrate singleton reset; next call will reinitialize")


def _get_substrate_async() -> SubstrateInterface:
    """Non-blocking wrapper: runs the (possibly slow) init in a thread."""
    return _get_substrate()


async def ensure_substrate() -> SubstrateInterface:
    """Await-able accessor that runs blocking init in a thread pool."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _get_substrate_async)


# ── SCALE compact encoding ──────────────────────────────────────────

def _compact(value: int) -> bytes:
    """SCALE compact-encode an unsigned integer."""
    if value < 1 << 6:
        return bytes([value << 2])
    if value < 1 << 14:
        return struct.pack("<H", (value << 2) | 0b01)
    if value < 1 << 30:
        return struct.pack("<I", (value << 2) | 0b10)
    # big-integer mode
    raw = value.to_bytes((value.bit_length() + 7) // 8, "little")
    return bytes([((len(raw) - 4) << 2) | 0b11]) + raw


# ── Chain helpers ────────────────────────────────────────────────────

async def get_chain_props() -> dict[str, Any]:
    """Return genesis hash, runtime version, latest block info."""
    si = await ensure_substrate()

    def _fetch():
        genesis = si.get_block_hash(0)
        block_hash = si.get_chain_head()
        block_header = si.get_block_header(block_hash)
        block_number = block_header["header"]["number"]
        signed_extensions = [
            ext["identifier"]
            for ext in si.metadata.get_signed_extensions()
        ] if hasattr(si.metadata, "get_signed_extensions") else [
            "CheckNonZeroSender",
            "CheckSpecVersion",
            "CheckTxVersion",
            "CheckGenesis",
            "CheckMortality",
            "CheckNonce",
            "CheckWeight",
            "ChargeTransactionPayment",
            "SubtensorSignedExtension",
            "CommitmentsSignedExtension",
            "CheckMetadataHash",
        ]
        return {
            "genesis_hash": genesis,
            "block_hash": block_hash,
            "block_number": block_number,
            "spec_version": si.runtime_version,
            "transaction_version": si.transaction_version,
            "signed_extensions": signed_extensions,
        }

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _fetch)


async def get_nonce(address: str) -> int:
    si = await ensure_substrate()
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, si.get_account_nonce, address)


# ── Signing payload builder ─────────────────────────────────────────

async def build_signing_payload(
    sender: str,
    calls_desc: list[dict],
) -> dict[str, Any]:
    """Build a ``SignerPayloadJSON`` for WalletConnect ``polkadot_signTransaction``.

    *calls_desc* is the list returned by ``build_stake_payload()['calls']``,
    each dict having ``module``, ``call``, ``params``.

    Returns a dict with::

        {
            "address":    str,      # SS58
            "blockHash":  str,      # 0x…
            "blockNumber": str,     # 0x…
            "era":        str,      # 0x… (mortal era hex)
            "genesisHash": str,     # 0x…
            "method":     str,      # 0x… (SCALE-encoded call)
            "nonce":      str,      # 0x…
            "signedExtensions": [...],
            "specVersion": str,     # 0x…
            "tip":        str,      # 0x00000000000000000000000000000000
            "transactionVersion": str,  # 0x…
            "version":    4,
        }
    """
    si = await ensure_substrate()

    def _build():
        # Refresh metadata if the on-chain spec version has changed since we
        # initialised.  This prevents stale call indices / parameter types
        # causing WASM decode panics after a runtime upgrade.
        try:
            si.init_runtime()
        except Exception as exc:  # pragma: no cover
            _log.warning("[WC-Sub] init_runtime() failed; metadata may be stale: %s", exc)

        # Compose individual calls
        inner_calls = []
        for cd in calls_desc:
            c = si.compose_call(
                call_module=cd["module"],
                call_function=cd["call"],
                call_params=cd["params"],
            )
            inner_calls.append(c)

        # Wrap in utility.batch_all if more than one call
        if len(inner_calls) == 1:
            top_call = inner_calls[0]
        else:
            top_call = si.compose_call(
                call_module="Utility",
                call_function="batch_all",
                call_params={"calls": inner_calls},
            )

        # Chain state
        genesis = si.get_block_hash(0)
        head = si.get_chain_head()
        header = si.get_block_header(head)
        block_number = header["header"]["number"]
        nonce = si.get_account_nonce(sender)

        # Mortal era: period=64 blocks (~6.4 min validity at 12s/block).
        # Gives users enough time to review and sign in Nova Wallet while
        # preventing replay of old transactions after the window expires.
        period = _MORTAL_ERA_PERIOD
        phase = block_number % period
        # Substrate mortal era encoding: 2 bytes, little-endian.
        # lower 4 bits = period_log2 - 1,  upper 12 bits = quantized phase.
        period_log2 = int(math.log2(period))
        quantize_factor = max(period >> 3, 1)
        quantized_phase = phase // quantize_factor * quantize_factor
        encoded_era = ((period_log2 - 1) | ((quantized_phase // quantize_factor) << 4))
        era_bytes = struct.pack("<H", encoded_era)
        era_hex = "0x" + era_bytes.hex()

        # The blockHash in SignerPayloadJSON MUST be the hash of the
        # mortal era's checkpoint block — NOT the chain head.  The chain
        # verifier (CheckMortality) recalculates the checkpoint from the
        # era and fetches its hash.  If we use the chain-head hash
        # instead, the signing payload the wallet signed will contain a
        # different blockHash from what the verifier reconstructs,
        # causing "Transaction has a bad signature" (code 1010).
        #
        # Checkpoint = quantized_phase + floor(current / period) * period
        era_checkpoint = quantized_phase + (block_number // period) * period
        era_block_hash = si.get_block_hash(era_checkpoint)

        _log.info(
            "[WC-Sub] Era: period=%d phase=%d quantized=%d "
            "checkpoint_block=%d (head=%d)",
            period, phase, quantized_phase, era_checkpoint, block_number,
        )

        # method hex – the SCALE-encoded call data
        method_hex = top_call.data.to_hex()

        # signed extensions (best-effort list from live metadata)
        try:
            signed_exts = [
                ext["identifier"]
                for ext in si.metadata.get_signed_extensions()
            ]
        except (AttributeError, KeyError, TypeError):
            # Fallback covering current Bittensor runtime extensions.
            # Updated to match runtime spec 393+ which renamed/replaced
            # old extensions (SubtensorSignedExtension → SubtensorTransactionExtension,
            # removed CommitmentsSignedExtension, added SudoTransactionExtension,
            # CheckShieldedTxValidity, DrandPriority).
            # CheckMetadataHash adds a 1-byte mode field to extra.
            # The other Bittensor-specific extensions add zero extra bytes.
            signed_exts = [
                "CheckNonZeroSender",
                "CheckSpecVersion",
                "CheckTxVersion",
                "CheckGenesis",
                "CheckMortality",
                "CheckNonce",
                "CheckWeight",
                "ChargeTransactionPayment",
                "SudoTransactionExtension",
                "CheckShieldedTxValidity",
                "SubtensorTransactionExtension",
                "DrandPriority",
                "CheckMetadataHash",
            ]

        payload = {
            "address": sender,
            "blockHash": era_block_hash,
            "blockNumber": _hex_int(block_number),
            "era": era_hex,
            "genesisHash": genesis,
            "method": method_hex,
            "nonce": _hex_int(nonce),
            "signedExtensions": signed_exts,
            "specVersion": _hex_int(si.runtime_version),
            "tip": _hex_int(0),
            "transactionVersion": _hex_int(si.transaction_version),
            "version": 4,
        }

        # Explicitly set CheckMetadataHash mode so wallets (SubWallet,
        # Nova, Talisman, etc.) know metadata verification is disabled.
        # Without this field some wallets omit or miscalculate the mode
        # byte, producing a signature that doesn't match the assembled
        # extrinsic → "Transaction has a bad signature" (code 1010).
        #
        # NOTE: Do NOT include ``metadataHash: null`` — some wallet
        # implementations (notably Nova Wallet) choke on the JSON null
        # value and silently fail to sign, causing the confirm button to
        # appear unresponsive.  Omitting the key entirely while keeping
        # ``mode: 0`` is sufficient: the wallet treats absent metadataHash
        # as "no hash" when mode is disabled.
        if "CheckMetadataHash" in signed_exts:
            payload["mode"] = 0
            # metadataHash intentionally omitted (mode 0 = disabled)

        # Request the wallet to return the fully assembled signed
        # extrinsic alongside the raw signature.  This bypasses all
        # client-side and server-side extrinsic assembly — the #1
        # source of "bad signature" and pattern-mismatch errors.
        payload["withSignedTransaction"] = True

        # Include the sender's raw public key so the frontend can
        # assemble the extrinsic client-side without needing an SS58
        # decoder (used as last-resort fallback only).
        payload["senderPubkey"] = "0x" + ss58_decode(sender)

        _log.info(
            "[WC-Sub] Built signing payload: address=%s nonce=%s era=%s "
            "specVersion=%s txVersion=%s signedExtensions=%s",
            sender, payload["nonce"], payload["era"],
            payload["specVersion"], payload["transactionVersion"],
            signed_exts,
        )

        return payload

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _build)


# ── Extrinsic assembly ──────────────────────────────────────────────

def _parse_signature(signature_hex: str) -> tuple[int, bytes]:
    """Parse the wallet signature into (crypto_type, raw_64_bytes).

    Returns a tuple of (MultiSignature type, 64-byte raw signature).
    Type 0 = Ed25519, 1 = Sr25519, 2 = Ecdsa.
    """
    sig_bytes = bytes.fromhex(signature_hex.replace("0x", ""))
    if len(sig_bytes) == 65:
        return sig_bytes[0], sig_bytes[1:]
    if len(sig_bytes) == 64:
        return 0x01, sig_bytes  # Sr25519 default
    raise ValueError(
        f"unexpected signature length {len(sig_bytes)} (expected 64 or 65)"
    )


async def assemble_signed_extrinsic(
    payload: dict[str, Any],
    signature_hex: str,
) -> str:
    """Assemble a fully-signed extrinsic from a ``SignerPayloadJSON`` and
    the 0x-prefixed signature returned by Nova Wallet.

    Returns the hex-encoded signed extrinsic ready for
    ``author_submitExtrinsic``.

    Uses ``SubstrateInterface.create_signed_extrinsic()`` with the
    external signature so that the library handles all SCALE encoding
    details (address format, signed extensions, CheckMetadataHash mode
    byte) from the live chain metadata.  Falls back to manual byte-level
    assembly if the library call fails.
    """
    si = await ensure_substrate()

    def _assemble():
        sig_type, raw_sig = _parse_signature(signature_hex)

        _log.info(
            "[WC-Sub] Assembling extrinsic: sig_type=0x%02x sig_len=%d "
            "address=%s nonce=%s era=%s signedExtensions=%s",
            sig_type, len(raw_sig),
            payload.get("address", "?"),
            payload.get("nonce", "?"),
            payload.get("era", "?"),
            payload.get("signedExtensions", []),
        )

        nonce_val = (
            int(payload["nonce"], 16)
            if isinstance(payload["nonce"], str)
            else payload["nonce"]
        )
        tip_val = (
            int(payload["tip"], 16)
            if isinstance(payload["tip"], str)
            else payload["tip"]
        )

        # ── Primary path: use the substrate-interface library ──────
        # The library knows the chain's metadata and correctly encodes
        # the address format, signature type, signed extensions, and
        # CheckMetadataHash mode byte.  This avoids subtle manual
        # encoding bugs that cause "bad signature" errors.
        lib_hex = _assemble_via_library(si, payload, sig_type, raw_sig,
                                        nonce_val, tip_val)
        if lib_hex:
            return lib_hex

        # ── Fallback: manual byte-level assembly ───────────────────
        _log.info("[WC-Sub] Falling back to manual extrinsic assembly")
        return _assemble_manual(payload, sig_type, raw_sig,
                                nonce_val, tip_val)

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _assemble)


def _assemble_via_library(
    si: SubstrateInterface,
    payload: dict[str, Any],
    sig_type: int,
    raw_sig: bytes,
    nonce_val: int,
    tip_val: int,
) -> str | None:
    """Try to assemble the extrinsic using ``SubstrateInterface``.

    Returns the hex-encoded extrinsic, or ``None`` if the library-based
    approach is not available or fails.
    """
    try:
        from substrateinterface import Keypair

        # Refresh metadata so call indices and extension types are current.
        try:
            si.init_runtime()
        except Exception as exc:
            _log.warning("[WC-Sub] init_runtime() failed: %s", exc)

        # Reconstruct the GenericCall from the SCALE-encoded method hex.
        call = si.runtime_config.create_scale_object(
            "Call", metadata=si.metadata
        )
        call.decode(_scale_bytes(payload["method"]))

        # Create a Keypair from the sender's public key only (no private
        # key needed since we're injecting an external signature).
        sender_hex = ss58_decode(payload["address"])
        kp = Keypair(
            public_key=bytes.fromhex(sender_hex),
            ss58_format=_SS58_PREFIX,
            crypto_type=sig_type,
        )

        # Decode the mortal era from our hex encoding back to period/phase.
        era_hex = payload["era"].replace("0x", "")
        era_bytes_raw = bytes.fromhex(era_hex)
        if len(era_bytes_raw) == 2:
            encoded = int.from_bytes(era_bytes_raw, "little")
            period = 2 << (encoded & 0x0F)
            quantize_factor = max(period >> 3, 1)
            phase = (encoded >> 4) * quantize_factor
            era_param = {"period": period, "phase": phase}
        else:
            era_param = None  # immortal

        # Build the signed extrinsic via the library.  The `signature`
        # parameter injects the wallet's signature so no private key is
        # needed.
        raw_sig_hex = "0x" + raw_sig.hex()

        extrinsic = si.create_signed_extrinsic(
            call=call,
            keypair=kp,
            era=era_param,
            nonce=nonce_val,
            tip=tip_val,
            signature=raw_sig_hex,
        )

        # Extract the hex-encoded extrinsic.
        extrinsic_hex = str(extrinsic.data)
        if not extrinsic_hex.startswith("0x"):
            extrinsic_hex = "0x" + extrinsic_hex

        _log.info(
            "[WC-Sub] Library assembly succeeded (length=%d)",
            len(extrinsic_hex),
        )
        return extrinsic_hex

    except Exception as exc:
        _log.warning(
            "[WC-Sub] Library-based assembly failed, will use manual: %s", exc
        )
        return None


def _scale_bytes(hex_str: str):
    """Create a ScaleBytes-like object from a hex string.

    Works with different versions of ``scalecodec`` that may expose the
    helper in various locations.
    """
    try:
        from scalecodec import ScaleBytes
        return ScaleBytes(hex_str)
    except ImportError:
        pass
    try:
        from scalecodec.base import ScaleBytes
        return ScaleBytes(hex_str)
    except ImportError:
        pass
    # Last resort: the SubstrateInterface may expose it
    raise ImportError("Cannot import ScaleBytes from scalecodec")


def _assemble_manual(
    payload: dict[str, Any],
    sig_type: int,
    raw_sig: bytes,
    nonce_val: int,
    tip_val: int,
) -> str:
    """Manual byte-level extrinsic assembly (fallback).

    This is the original assembly logic kept as a fallback in case the
    library-based approach is unavailable.
    """
    sender_pub = bytes.fromhex(ss58_decode(payload["address"]))

    era_hex = payload["era"].replace("0x", "")
    era_bytes = bytes.fromhex(era_hex)

    nonce_enc = _compact(nonce_val)
    tip_enc = _compact(tip_val)

    method_hex = payload["method"].replace("0x", "")
    call_data = bytes.fromhex(method_hex)

    # "extra" = concatenation of each signed extension's encoded extra
    # data (the part that goes in the extrinsic body, not just signed):
    #   CheckMortality  → era bytes
    #   CheckNonce      → compact-encoded nonce
    #   ChargeTransactionPayment → compact-encoded tip
    #   CheckMetadataHash → 1 byte mode (0x00 = disabled)
    signed_exts = payload.get("signedExtensions", [])
    extra = era_bytes + nonce_enc + tip_enc
    if "CheckMetadataHash" in signed_exts:
        extra += bytes([0x00])

    body = (
        bytes([0x84])            # signed extrinsic version 4
        + bytes([0x00])          # MultiAddress::Id
        + sender_pub             # 32-byte account id
        + bytes([sig_type])      # MultiSignature type
        + raw_sig                # 64-byte signature
        + extra                  # extension extra data
        + call_data              # SCALE-encoded call
    )

    length_prefix = _compact(len(body))
    extrinsic_hex = "0x" + (length_prefix + body).hex()

    _log.info(
        "[WC-Sub] Manual assembly result (length=%d)", len(extrinsic_hex)
    )
    return extrinsic_hex


# ── CAIP-2 chain ID ─────────────────────────────────────────────────

async def get_caip2_chain_id() -> str:
    """Return the CAIP-2 chain identifier for the connected chain.

    Format: ``polkadot:<first_32_hex_chars_of_genesis_hash>``

    Tries the heavy ``SubstrateInterface`` first (it may already be
    cached), then falls back to a lightweight HTTP JSON-RPC call so the
    CAIP-2 chain ID can still be resolved when the WebSocket connection
    to the Bittensor node is flaky.
    """
    genesis: str | None = None
    try:
        si = await ensure_substrate()
        loop = asyncio.get_running_loop()
        genesis = await loop.run_in_executor(None, si.get_block_hash, 0)
    except Exception:
        # SubstrateInterface unavailable – fall back to simple HTTP RPC.
        try:
            from bot.services.tx_builder import get_genesis_hash
            genesis = await get_genesis_hash()
        except Exception as exc:
            raise RuntimeError(f"Cannot fetch genesis hash: {exc}") from exc

    if not genesis or not genesis.startswith("0x") or len(genesis) < 34:
        raise RuntimeError(f"Invalid genesis hash: {genesis!r}")
    # genesis is "0x..." – take first 32 hex chars after "0x"
    return "polkadot:" + genesis[2:34]


# ── Staked positions query ──────────────────────────────────────────

async def get_staked_positions(
    coldkey: str,
    netuid: int,
    candidate_hotkeys: list[str] | None = None,
) -> list[dict]:
    """Query the chain for this coldkey's staked Alpha on a specific subnet.

    Returns a list of ``{"hotkey": "5…", "alpha_tao": 1.2345}`` dicts,
    one per validator the user has staked with on this subnet.

    If *candidate_hotkeys* is provided and ``StakingHotkeys`` returns nothing,
    we fall back to probing each candidate for an ``Alpha`` balance.  This
    covers cases where the on-chain ``StakingHotkeys`` map hasn't been updated
    (observed after the dTAO migration) but the user does hold Alpha.
    """
    si = await ensure_substrate()

    def _query():
        # 1) Get all hotkeys this coldkey has staked with (across all subnets)
        hotkey_list: list[str] = []
        try:
            result = si.query(
                module="SubtensorModule",
                storage_function="StakingHotkeys",
                params=[coldkey],
            )
            hotkey_list = result.value if result else []
        except Exception as exc:
            _log.warning(
                "[WC-Sub] StakingHotkeys query failed for %s: %s",
                coldkey, exc,
            )

        _log.info(
            "[WC-Sub] StakingHotkeys[%s…] returned %d hotkeys for SN%d query",
            coldkey[:12], len(hotkey_list), netuid,
        )

        # 2) If StakingHotkeys returned nothing, fall back to candidate
        #    hotkeys (top validators for the subnet) so we can still detect
        #    the user's Alpha positions.
        if not hotkey_list and candidate_hotkeys:
            _log.info(
                "[WC-Sub] StakingHotkeys empty for %s on SN%d, "
                "probing %d candidate hotkeys",
                coldkey, netuid, len(candidate_hotkeys),
            )
            hotkey_list = list(candidate_hotkeys)

        if not hotkey_list:
            return []

        positions = []
        for hk in hotkey_list:
            try:
                alpha = si.query(
                    module="SubtensorModule",
                    storage_function="Alpha",
                    params=[hk, coldkey, netuid],
                )
                raw_val = alpha.value if alpha else 0
                # On some runtimes / netuids, alpha.value returns a
                # dict (e.g. {"bits": …}) instead of a plain int.
                # Extract the numeric value or skip this hotkey.
                if isinstance(raw_val, dict):
                    raw_val = raw_val.get("bits", raw_val.get("value", 0))
                # Force to plain Python int for reliable arithmetic
                # and JSON serialization (SCALE codec types can behave
                # unexpectedly with division / json.dumps).
                try:
                    raw_val = int(raw_val)
                except (TypeError, ValueError, OverflowError):
                    raw_val = 0
                if raw_val > 0:
                    # Standard Bittensor uses 9 decimal places (rao),
                    # but after the dTAO migration Alpha values may
                    # use 18 or even 27 decimal places.  Keep dividing
                    # by 1e9 until the value is in a human-reasonable
                    # range (no individual stake can exceed 1 billion).
                    alpha_tao = raw_val / 1e9
                    while alpha_tao > 1e9:
                        alpha_tao = alpha_tao / 1e9
                    _log.info(
                        "[WC-Sub] Alpha[%s…, %s…, SN%d] raw=%d → %.4f",
                        hk[:12], coldkey[:12], netuid, raw_val, alpha_tao,
                    )
                    positions.append({
                        "hotkey": hk,
                        "alpha_tao": alpha_tao,
                    })
            except Exception as exc:
                _log.warning(
                    "[WC-Sub] Alpha query failed for hotkey=%s netuid=%d: %s",
                    hk, netuid, exc,
                )

        _log.info(
            "[WC-Sub] get_staked_positions(%s…, SN%d): %d positions found",
            coldkey[:12], netuid, len(positions),
        )
        return positions

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _query)


# ── Helpers ──────────────────────────────────────────────────────────

def _hex_int(value: int) -> str:
    """Encode an integer as an even-length hex string (``0x...`` prefixed).

    Polkadot.js ``numberToHex`` always produces an even number of hex
    digits.  Wallets (Nova, SubWallet, Talisman) may silently fail to
    parse odd-length hex values like ``"0x189"`` when reconstructing the
    signing payload, so we pad to match the convention.
    """
    if value == 0:
        return "0x00"
    h = format(value, "x")
    if len(h) % 2:
        h = "0" + h
    return "0x" + h
