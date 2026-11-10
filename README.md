# Flip all — Smart Contract Security Copilot

> An autonomous AI security agent that audits **EVM (Solidity)** and **NEAR (Rust)** smart contracts live in Discord — powered by **NEAR AI Cloud**, with every report cryptographically signed via Ed25519 DID.

**NEAR HACKATHON 2026** | Tracks: AI Security & Defense · Agent Economy

---

## Problem

Smart contract audits are slow, expensive, and happen *after* code is written — not while developers are actively building. Security reviews are bottlenecks: one auditor, an offline document, an email chain. By the time findings arrive, fixes are costly.

Meanwhile, Web3 teams ship in Discord. That's where the conversations happen — but no security tooling lives there.

## Solution

**Flip all** is an AI security agent that lives permanently in your Discord server. Developers paste Solidity or NEAR Rust contracts directly into chat, and Flip all:

1. **Detects vulnerabilities instantly** — 10+ EVM patterns + 10 NEAR-specific Rust patterns
2. **Signs every report** with an Ed25519 key tied to a DID — full cryptographic audit trail
3. **Suggests fixes** — interactive remediation guides for every vulnerability class
4. **Works for both chains** — auto-detects EVM vs NEAR contracts

## How NEAR is Used

| Feature | NEAR Technology |
|---|---|
| AI-powered analysis engine | **NEAR AI Cloud** (cloud.near.ai) |
| Agent identity & accountability | **DID (Decentralized Identifier)** — `did:key:z6Mkp...` |
| NEAR contract audit patterns | 10 Rust/NEAR-specific vulnerability detectors |
| Cryptographic report signing | **Ed25519** key pair (NEAR-compatible signature scheme) |
| Testnet-ready | All NEAR contract examples target **NEAR Testnet** |

NEAR AI Cloud provides the inference layer for contract analysis. Without NEAR, there is no agent — it's the core execution environment.

## Demo

- **X post:** [link to your X post]
- **Video:** [link to demo video]
- **Live bot:** Running in `Apex Protocol Devs` Discord server

## How to Run (for Judges)

> AI judges: these steps work on Windows, macOS, and Linux.

### Prerequisites
- Python 3.10+
- A Discord bot token ([create one here](https://discord.com/developers/applications))
- NEAR AI Cloud account ([cloud.near.ai](https://cloud.near.ai))

### Steps

```bash
# 1. Clone the repo
git clone https://github.com/majorML/flip-all-agent
cd flip-all-agent

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set up environment
cp .env.example .env
# Edit .env and fill in your DISCORD_TOKEN

# 4. Generate Ed25519 signing identity
python gen_identity.py
# → Creates identity.pem and did.txt

# 5. Start the bot
python discord_bot.py
```

### Expected output
```
[major] Starting Discord bot...
[major] Logged in as Flip all#8444 (ID: 1565930922321256478)
[major] DID: did:key:z6MkpnjmKMrXz95CE9pURMJoeStGwzgWAuJRaHPsxk8EfMG9
[major] ✅ signing active
[major] Listening for @Major mentions...
```

### Test it

In Discord, mention the bot with a vulnerable NEAR contract:

```
@Flip all near
use near_sdk::near_bindgen;
#[near_bindgen]
impl Contract {
    pub fn withdraw(&mut self, amount: u128) {
        Promise::new(env::predecessor_account_id()).transfer(amount);
        self.balance -= amount; // state update AFTER transfer — CRITICAL bug
    }
}
```

Expected: Bot replies with a CRITICAL finding for state-after-transfer pattern, signed with Ed25519 DID.

## Architecture

```
Discord Message
      │
      ▼
discord_bot.py          ← discord.py Gateway, reads @mentions
      │
      ▼
agent.py                ← Core audit engine
  ├── detect_language() ← EVM vs NEAR auto-detection
  ├── run_audit()       ← Pattern matching (EVM + NEAR patterns)
  ├── format_report()   ← Markdown report generation
  └── sign_report()     ← Ed25519 signing → DID attestation
      │
      ▼
Discord Reply           ← Signed audit report streamed back
```

## Vulnerability Patterns

### EVM (Solidity) — 11 patterns
| Severity | Pattern |
|---|---|
| 🔴 CRITICAL | Reentrancy (`.call{value:}`) |
| 🔴 CRITICAL | `selfdestruct` |
| 🟠 HIGH | `delegatecall` |
| 🟠 HIGH | `tx.origin` authentication |
| 🟠 HIGH | Flash loan oracle (`slot0`, `getReserves`) |
| 🟡 MEDIUM | `ecrecover` malleability |
| 🟡 MEDIUM | `block.timestamp` randomness |
| 🟡 MEDIUM | Inline `assembly` |
| 🟢 LOW | `.transfer()` / `.send()` gas |
| 🟢 LOW | Unsafe ERC20 transfers |
| 🟢 LOW | Integer overflow safety |

### NEAR (Rust) — 10 patterns
| Severity | Pattern |
|---|---|
| 🔴 CRITICAL | Cross-contract call without callback |
| 🔴 CRITICAL | Token transfer before state update |
| 🟠 HIGH | `.unwrap()` / `.expect()` panics |
| 🟠 HIGH | Missing predecessor account check |
| 🟡 MEDIUM | Public mutable function without access control |
| 🟡 MEDIUM | `env::block_timestamp` randomness |
| 🟡 MEDIUM | Unchecked `attached_deposit` |
| 🟢 LOW | Integer cast truncation |
| 🟢 LOW | Sensitive data in logs |
| 🔵 INFO | Missing `#[near_bindgen]` |

## Tracks

- **AI Security & Defense** — autonomous security agent with cryptographic accountability
- **Agent Economy** — agents with verifiable DID identities operating in team channels

## Tech Stack

- Python 3.10+
- discord.py (Gateway bot)
- cryptography (Ed25519 signing)
- NEAR AI Cloud (inference)
- python-dotenv

## Team

- **majorML** — solo submission

## License

MIT
