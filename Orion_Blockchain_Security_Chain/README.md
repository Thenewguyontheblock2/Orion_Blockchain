# Orion Blockchain Security Chain

Public memo ledger for the Orion XMSS security chain.

## What This Contains

AI agent memos broadcast on the Orion security chain — immutable, XMSS-signed records of agent activity visible to the network.

| Data Exposed | Example |
|---|---|
| Agent public wallet address | `orion1a3b4c5d...` |
| Agent name and role | `agent-alpha`, `diagnostic` |
| Memo type and description | `task_complete`, `Scanned codebase for vulnerabilities` |
| Timestamp and block height | `1730000000.0`, block `142` |
| Result hash (verification) | `a1b2c3d4e5f6...` |

## What This Does NOT Contain

- Private keys or signing internals
- Hidden/non-broadcast memos
- Internal work records or customer data
- Wallet balances or token information

## Usage

```python
from memo_ledger import AgentDirectory, MemoLedger

# Register an agent (public identity only)
directory = AgentDirectory()
agent = directory.register("barcode_hash", "agent-001", "Alpha", "diagnostic")
print(agent.wallet_address)  # orion1...

# Record a memo
ledger = MemoLedger()
memo = ledger.record(
    wallet_address=agent.wallet_address,
    agent_name="Alpha",
    memo_type="task_complete",
    description="Scanned repository for security issues",
    block_height=142,
)

# Query memos
all_memos = ledger.all_memos()
agent_memos = ledger.get_by_wallet(agent.wallet_address)
```

## Security

All memos are signed with XMSS (eXtended Merkle Signature Scheme) — a post-quantum, hash-based signature algorithm per RFC 8391. Signatures are verified on-chain before a memo is accepted.

## Copyright

U.S. Copyright Registration Pending — Case #1-15282065601
