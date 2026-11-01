# Flip all — DeFi Security Copilot for Discord

> **Flip the Switch Hackathon** — WeMakeDevs × DevTools Academy × Switch AI (Nov 4–7, 2026)

**Flip all** is an autonomous EVM smart contract and DeFi security analyst that lives **inside your Discord server** as a native teammate. Drop an EVM/Solidity contract into any channel, tag `@Flip all`, and get an instant, cryptographically-signed audit report with actionable risk scoring.

## What Flip all Does

| Command | Action |
|---|---|
| `@Flip all audit <code>` | Full static security audit of Solidity / EVM code |
| `@Flip all scan <code>` | Quick vulnerability scan (alias for audit) |
| `@Flip all status` | Show status, platform support, and cryptographic DID |
| `@Flip all help` | Show all available commands |

### Vulnerability Checks

| Severity | Attack Vectors & Patterns |
|---|---|
| 🔴 **CRITICAL** | Reentrancy (`.call{value:}`), `selfdestruct` exploitation, dangerous `delegatecall` |
| 🟠 **HIGH** | `tx.origin` phishing, Flash loan spot price & oracle manipulation (`slot0`, `getReserves`) |
| 🟡 **MEDIUM** | `ecrecover` signature malleability, `block.timestamp` miner manipulation, inline `assembly` |
| 🟢 **LOW** | Raw ERC-20 transfers (missing `SafeERC20`), gas stipend issues, arithmetic safety |

Every report is cryptographically signed using an **Ed25519 DID identity** (`did:key:z6Mk...`), providing immutable verification for team reviews.

## Architecture

```
Discord Channel
      ↓ user mentions @Flip all audit <code>
Switch Console  ←→  Bridge (Discord ↔ SSE)
      ↓ HTTP POST /message
Flip all agent server (agent.py, port 8080)
      ↓ static analysis engine
      ↓ Ed25519 sign
      → SSE stream back → Discord message
```

## Quickstart

### 1. Requirements
```bash
pip install -r requirements.txt
```

### 2. Run Flip all
```bash
# Windows
python discord_bot.py

# Switch Protocol Server
python agent.py
```

## License
MIT
