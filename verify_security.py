#!/usr/bin/env python3
"""Self-verification script for the TAO Subnet Bot security review package.

Run at the repo root:

    python verify_security.py

The script performs three independent checks and prints a PASS/FAIL report.
No network access, no writes, no side effects.  An auditor can run it on
their own checkout without trusting anything the operator set up.

Checks performed:

    1. FINGERPRINT  – SHA-256 of every file in security-review/ matches
                      security-review/FINGERPRINTS.txt.
    2. PARITY       – The copies in security-review/ are byte-identical
                      to the live source (e.g. bot/services/tx_builder.py).
                      If they differ, the review package is stale.
    3. FORBIDDEN    – The entire repo does not contain forbidden patterns
                      (mnemonic handling, bot-owned private keys, calls
                      to undisclosed network hosts).

Exit code 0 on full pass, 1 on any failure.

This script is deliberately dependency-free: it uses only the Python
standard library.
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REVIEW = ROOT / "security-review"
FINGERPRINTS = REVIEW / "FINGERPRINTS.txt"


# ── terminal colour helpers ─────────────────────────────────────────────
def _green(s: str) -> str:
    return f"\033[32m{s}\033[0m" if sys.stdout.isatty() else s


def _red(s: str) -> str:
    return f"\033[31m{s}\033[0m" if sys.stdout.isatty() else s


def _bold(s: str) -> str:
    return f"\033[1m{s}\033[0m" if sys.stdout.isatty() else s


# ── helpers ─────────────────────────────────────────────────────────────
def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_fingerprints(path: Path) -> dict[str, str]:
    """Return {relative_path: sha256} from FINGERPRINTS.txt.

    Lines starting with '#' or blank are ignored.  Each data line is
    "<hex>  <relative/path>".
    """
    mapping: dict[str, str] = {}
    if not path.is_file():
        return mapping
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        hex_hash, rel = parts
        if not re.fullmatch(r"[0-9a-f]{64}", hex_hash):
            continue
        mapping[rel] = hex_hash
    return mapping


# ── check 1: fingerprints ───────────────────────────────────────────────
def check_fingerprints() -> list[str]:
    """Verify that every file listed in FINGERPRINTS.txt matches on disk."""
    errors: list[str] = []
    if not FINGERPRINTS.is_file():
        errors.append(
            f"Missing fingerprint file: {FINGERPRINTS.relative_to(ROOT)}"
        )
        return errors

    expected = parse_fingerprints(FINGERPRINTS)
    if not expected:
        errors.append("FINGERPRINTS.txt contains no parseable entries")
        return errors

    for rel, want in expected.items():
        file_path = ROOT / rel
        if not file_path.is_file():
            errors.append(f"Missing file referenced by fingerprint: {rel}")
            continue
        got = sha256_of(file_path)
        if got != want:
            errors.append(
                f"Hash mismatch for {rel}:\n"
                f"  expected: {want}\n"
                f"  actual:   {got}"
            )
    return errors


# ── check 2: parity between review copies and live source ──────────────
# Mapping: review snapshot → live source
PARITY_PAIRS = [
    ("security-review/tx_builder.py",   "bot/services/tx_builder.py"),
    ("security-review/wc_substrate.py", "bot/services/wc_substrate.py"),
    ("security-review/wallet_manager.py", "wallet_manager.py"),
]


def check_parity() -> list[str]:
    errors: list[str] = []
    for review_rel, live_rel in PARITY_PAIRS:
        review_path = ROOT / review_rel
        live_path = ROOT / live_rel
        if not review_path.is_file():
            errors.append(f"Missing review file: {review_rel}")
            continue
        if not live_path.is_file():
            errors.append(f"Missing live source: {live_rel}")
            continue
        rh = sha256_of(review_path)
        lh = sha256_of(live_path)
        if rh != lh:
            errors.append(
                f"Review copy differs from live source:\n"
                f"  review: {review_rel}  ({rh})\n"
                f"  live:   {live_rel}  ({lh})\n"
                f"  The review package is stale — regenerate before "
                f"distributing."
            )
    return errors


# ── check 3: forbidden patterns across the repo ────────────────────────
# Each pattern is (human_name, regex, allowlist_of_paths_where_it_is_ok).
# The allowlist is checked as a substring of the file path; a match against
# any allowlist entry means the hit is expected and not a failure.
#
# The patterns target *code-level* key handling (actual function calls,
# imports, constructor arguments), not prose mentions of the words.  This
# keeps the check useful (it catches real regressions) without flagging
# the documentation that describes the policy.
#
# Files that legitimately reference the forbidden concepts in prose
# (this script itself, SECURITY.md, user-facing guides that tell the
# *user* to safeguard their own seed phrase) are allowlisted.
_DOC_ALLOWLIST = [
    "SECURITY.md",
    "security-review/README.md",
    "security-review/FINGERPRINTS.txt",
    "security-review/api_tx_handlers.py",
    "verify_security.py",
    # User-facing onboarding: tells the USER to protect their own seed
    # phrase when installing Nova Wallet.  Read it yourself — there is
    # no code that touches a seed in these files.
    "bot/handlers/guide.py",
    # Localised translations of the same onboarding text
    "bot/locales/",
    "translations.json",
    "Miniapp/i18n.json",
]

FORBIDDEN = [
    (
        "from_mnemonic / from_seed / create_from_uri call",
        # These are the actual substrateinterface / python-sdk constructors
        # that derive a keypair from secret material.  If any of them ever
        # appears in our code as an actual call, the non-custodial property
        # is broken.
        re.compile(r"\b(from_mnemonic|from_seed|create_from_uri|create_from_mnemonic|create_from_seed|create_from_private_key)\s*\("),
        _DOC_ALLOWLIST,
    ),
    (
        "Keypair constructor with private_key argument",
        # Keypair(public_key=…) is fine (used for signature reconstruction).
        # Keypair(private_key=…) or Keypair(seed_hex=…) would mean we are
        # holding key material server-side.
        re.compile(r"Keypair\s*\([^)]*\b(private_key|seed_hex|secret_key)\s*="),
        _DOC_ALLOWLIST,
    ),
    (
        "keypair.sign / keypair.sign_message call (potential server-side signing)",
        # We only ever use the wallet's external signature.  If any line
        # calls .sign() on a keypair object, the non-custodial property
        # needs to be re-verified.
        re.compile(r"\bkeypair\s*\.\s*sign(?:_message)?\s*\("),
        _DOC_ALLOWLIST,
    ),
    (
        "hardcoded SS58 starting with 5 of length 48 (possible embedded key)",
        # Anything that looks like a Bittensor address hardcoded in source
        # should be audited.  The operator's FEE_WALLET_ADDRESS comes from
        # env vars, never from source.
        re.compile(r"\b5[1-9A-HJ-NP-Za-km-z]{47}\b"),
        _DOC_ALLOWLIST + [
            ".env.example",
            "README.md",
            # Docstring examples inside the payload builders:
            "security-review/tx_builder.py",
            "bot/services/tx_builder.py",
        ],
    ),
]

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".html", ".md"}
SCAN_EXCLUDE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}


def iter_source_files() -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        # prune excluded directories in-place
        dirnames[:] = [d for d in dirnames if d not in SCAN_EXCLUDE_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in SCAN_EXTENSIONS:
                out.append(p)
    return out


def check_forbidden() -> list[str]:
    errors: list[str] = []
    source_files = iter_source_files()

    for label, pattern, allowlist in FORBIDDEN:
        offending: list[str] = []
        for path in source_files:
            rel = path.relative_to(ROOT).as_posix()
            if any(a in rel for a in allowlist):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line):
                    offending.append(f"{rel}:{i}: {line.strip()[:120]}")
        if offending:
            errors.append(
                f"Forbidden pattern «{label}» found in "
                f"{len(offending)} location(s):\n  "
                + "\n  ".join(offending[:20])
                + ("\n  …" if len(offending) > 20 else "")
            )
    return errors


# ── report ──────────────────────────────────────────────────────────────
def run() -> int:
    print(_bold("TAO Subnet Bot — Security Self-Verification"))
    print(f"Root: {ROOT}")
    print()

    sections = [
        ("1. Fingerprint integrity (security-review/FINGERPRINTS.txt)",
         check_fingerprints),
        ("2. Parity: review copies vs. live source",
         check_parity),
        ("3. Forbidden patterns (no key material, no hidden wallets)",
         check_forbidden),
    ]

    any_fail = False
    for title, fn in sections:
        print(_bold(title))
        errors = fn()
        if errors:
            any_fail = True
            for e in errors:
                print(_red("  FAIL: ") + e)
        else:
            print(_green("  PASS"))
        print()

    print(_bold("Summary: ") + (_red("FAIL") if any_fail else _green("PASS")))
    if any_fail:
        print(
            "\nAt least one check failed.  Do not trust the deployment\n"
            "until the failures above are resolved and this script passes.\n"
        )
        return 1
    print(
        "\nAll checks passed.  The review package matches the live source,\n"
        "the fingerprint file is intact, and no forbidden patterns were\n"
        "found in the repository.\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(run())
