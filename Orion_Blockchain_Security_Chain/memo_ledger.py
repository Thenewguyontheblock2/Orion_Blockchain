"""
memo_ledger.py — Public memo ledger for the Orion Blockchain Security Chain.
=============================================================================
AI agent memos broadcast on the XMSS security chain. Each memo is an
immutable, signed record of agent activity visible to the network.

Only public data is exposed here:
  - Agent public wallet addresses (orion1...)
  - Agent names and roles
  - Memo type, description, timestamps
  - Block height at time of recording
  - Result hashes (content verification, not content itself)

Private data (private keys, internal work details, hidden memos) is NOT
included in this module.
"""

from dataclasses import dataclass, field
from collections import deque
from typing import Dict, List, Optional
import hashlib
import time
import threading


# ---------------------------------------------------------------------------
# Agent Public Identity (wallet address only — no private keys)
# ---------------------------------------------------------------------------

@dataclass
class AgentPublicIdentity:
    """Public-facing agent identity on the security chain.
    Contains ONLY the public wallet address and metadata visible to the network."""
    barcode: str
    agent_id: str
    agent_name: str
    role: str
    registered_at: float = field(default_factory=time.time)

    @property
    def wallet_address(self) -> str:
        """Deterministic public wallet address derived from the agent's barcode."""
        return "orion1" + hashlib.sha256(self.barcode.encode()).hexdigest()[:38]

    def to_public_dict(self) -> dict:
        return {
            "wallet_address": self.wallet_address,
            "agent_name": self.agent_name,
            "role": self.role,
            "registered_at": self.registered_at,
        }


class AgentDirectory:
    """Read-only public directory of agent wallet addresses."""

    def __init__(self):
        self._agents: Dict[str, AgentPublicIdentity] = {}
        self._lock = threading.Lock()

    def register(self, barcode: str, agent_id: str, agent_name: str,
                 role: str) -> AgentPublicIdentity:
        identity = AgentPublicIdentity(
            barcode=barcode, agent_id=agent_id,
            agent_name=agent_name, role=role,
        )
        with self._lock:
            self._agents[barcode] = identity
        return identity

    def lookup_by_wallet(self, wallet_address: str) -> Optional[AgentPublicIdentity]:
        for agent in self._agents.values():
            if agent.wallet_address == wallet_address:
                return agent
        return None

    def lookup_by_name(self, agent_name: str) -> Optional[AgentPublicIdentity]:
        for agent in self._agents.values():
            if agent.agent_name == agent_name:
                return agent
        return None

    def all_public(self) -> List[dict]:
        return [a.to_public_dict() for a in self._agents.values()]


# ---------------------------------------------------------------------------
# Memo Entries — XMSS-signed agent memos on the security chain
# ---------------------------------------------------------------------------

@dataclass
class MemoEntry:
    """Immutable memo recorded on the XMSS security chain.
    Each memo is signed by an agent's XMSS key and broadcast to the network."""
    memo_id: str
    wallet_address: str
    agent_name: str
    memo_type: str
    description: str
    task_id: str = ""
    timestamp: float = field(default_factory=time.time)
    result_hash: str = ""
    block_height: int = 0

    def to_dict(self) -> dict:
        return {
            "memo_id": self.memo_id,
            "wallet_address": self.wallet_address,
            "agent_name": self.agent_name,
            "memo_type": self.memo_type,
            "description": self.description,
            "task_id": self.task_id,
            "timestamp": self.timestamp,
            "result_hash": self.result_hash,
            "block_height": self.block_height,
        }


class MemoLedger:
    """Append-only public ledger of agent memos on the XMSS security chain.

    All broadcast memos are visible to the network. Non-broadcast memos
    are stored internally but NOT exposed through this public interface.
    """

    def __init__(self):
        self._entries: deque = deque(maxlen=5000)
        self._by_wallet: Dict[str, deque] = {}
        self._by_agent: Dict[str, deque] = {}
        self._counter = 0
        self._lock = threading.Lock()

    def record(self, wallet_address: str, agent_name: str, memo_type: str,
               description: str, task_id: str = "",
               block_height: int = 0) -> MemoEntry:
        with self._lock:
            self._counter += 1
            now = time.time()
            memo_id = hashlib.sha256(
                f"MEMO:{wallet_address}:{self._counter}:{now}".encode()
            ).hexdigest()[:16]
            result_hash = hashlib.sha256(
                f"{wallet_address}:{memo_type}:{description}:{now}".encode()
            ).hexdigest()[:16]
            entry = MemoEntry(
                memo_id=memo_id, wallet_address=wallet_address,
                agent_name=agent_name, memo_type=memo_type,
                description=description, task_id=task_id,
                timestamp=now, result_hash=result_hash,
                block_height=block_height,
            )
            self._entries.append(entry)
            if wallet_address not in self._by_wallet:
                self._by_wallet[wallet_address] = deque(maxlen=1000)
            self._by_wallet[wallet_address].append(entry)
            if agent_name not in self._by_agent:
                self._by_agent[agent_name] = deque(maxlen=1000)
            self._by_agent[agent_name].append(entry)
            return entry

    def get_by_wallet(self, wallet_address: str) -> List[MemoEntry]:
        """Get all public memos for a wallet address."""
        return list(self._by_wallet.get(wallet_address, []))

    def get_by_agent(self, agent_name: str) -> List[MemoEntry]:
        """Get all public memos for an agent name."""
        return list(self._by_agent.get(agent_name, []))

    def all_memos(self) -> List[dict]:
        """Get all public broadcast memos."""
        return [e.to_dict() for e in self._entries]

    def search_memos(self, memo_type: str = "", agent_name: str = "",
                     since: float = 0.0) -> List[dict]:
        """Search memos by type, agent, or time range."""
        results = []
        for entry in self._entries:
            if memo_type and entry.memo_type != memo_type:
                continue
            if agent_name and entry.agent_name != agent_name:
                continue
            if since and entry.timestamp < since:
                continue
            results.append(entry.to_dict())
        return results

    @property
    def memo_count(self) -> int:
        return len(self._entries)

    @property
    def latest_block_height(self) -> int:
        if not self._entries:
            return 0
        return self._entries[-1].block_height
