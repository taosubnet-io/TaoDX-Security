# TaoDX — Public Security Review

This repository is an **automated read-only mirror** of the
wallet-touching code from the TaoDX Telegram bot.

It contains everything needed to independently verify that the bot
cannot access user funds:

- **[SECURITY.md](./SECURITY.md)** — Core promise, threat model,
  and responsible-disclosure contact.
- **[security-review/](./security-review/)** — Byte-identical
  copies of the ~2 300 lines of wallet-touching Python code,
  with formal security properties P1–P5.
- **[verify_security.py](./verify_security.py)** — Run
  `python verify_security.py` for a PASS/FAIL report.

## Quick answer: can the bot steal my TAO?

**No.** Every stake and unstake is signed locally inside Nova
Wallet or Talisman on your own device via WalletConnect v2. The
server only relays signed extrinsics — it never sees private
keys or seed phrases.

If the entire server was compromised right now (source code,
database, all env vars), an attacker still could not move a
single TAO from any user's wallet, because there is no key
material to steal.

## How this mirror stays in sync

A GitHub Actions workflow in the private source repository syncs
this mirror on every merge to `main`. Each commit message
references the source commit hash, so you can match any snapshot
here to the exact state of the live bot at that moment.

This mirror's most recent sync was from
[`taosubnet-io/tao-subnet-bot@f6ce620`](https://github.com/taosubnet-io/tao-subnet-bot/commit/f6ce6207ba0ed65d4afbaf9b674abc50d53d2d6e).

## Reporting a vulnerability

This mirror is read-only. Pull requests are accepted as feedback
but do not affect the live bot. To report a vulnerability
responsibly, see the contact section in [SECURITY.md](./SECURITY.md).

---

*Generated automatically by the source repo's CI. Do not edit
this file directly — edits will be overwritten on the next sync.*
