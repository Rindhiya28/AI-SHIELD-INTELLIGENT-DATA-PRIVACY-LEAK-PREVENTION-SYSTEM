"""Tamper-evident SHA-256 hash-chained audit ledger (report-service / governance)."""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

GENESIS = "0" * 64


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass
class Block:
    index: int
    timestamp: float
    stage: str
    job_id: str
    status: str
    pre_hash: Optional[str]
    post_hash: Optional[str]
    meta: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS
    hash: str = ""


def _digest(b: Block) -> str:
    payload = {k: v for k, v in asdict(b).items() if k != "hash"}
    return sha256_hex(json.dumps(payload, sort_keys=True))


class AuditLedger:
    """Append-only chain: H_i = SHA-256(H_{i-1} || index || time || stage || job || status || hashes || meta)."""

    def __init__(self) -> None:
        self.chain: List[Block] = []

    def record(self, stage: str, job_id: str, status: str, pre_hash: Optional[str] = None,
               post_hash: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> Block:
        prev = self.chain[-1].hash if self.chain else GENESIS
        b = Block(len(self.chain), time.time(), stage, job_id, status, pre_hash, post_hash, meta or {}, prev)
        b.hash = _digest(b)
        self.chain.append(b)
        return b

    def verify(self) -> bool:
        for i, b in enumerate(self.chain):
            expected_prev = GENESIS if i == 0 else self.chain[i - 1].hash
            if b.index != i or b.prev_hash != expected_prev or b.hash != _digest(b):
                return False
        return True
