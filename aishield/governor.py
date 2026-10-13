"""Privacy governor: the decision engine that orchestrates scan, review, redact and validate."""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from .detector import Detector, Entity
from .ledger import AuditLedger, sha256_hex
from .normalize import normalize
from .redactor import redact
from .risk import HIGH_TYPES, rubric_label
from .validator import strict_scan

log = logging.getLogger("aishield")


class Decision(str, Enum):
    ALLOW = "ALLOW"                      # nothing sensitive found; release unchanged
    REDACT = "REDACT"                    # sensitive data found and removed; release sanitised text
    BLOCK = "BLOCK"                      # residual sensitive data after the redaction rounds; release nothing
    REQUEST_APPROVAL = "REQUEST_APPROVAL"  # user kept a high-risk entity; needs explicit override


@dataclass
class Result:
    decision: Decision
    sanitized: Optional[str]
    entities: List[Entity]
    residual: int
    rounds: int
    risk_rule: str
    timings: Dict[str, float] = field(default_factory=dict)


class Governor:
    def __init__(self, detector: Optional[Detector] = None, *, normalize_text: bool = True, validate: bool = True,
                 max_rounds: int = 2, ledger: Optional[AuditLedger] = None) -> None:
        self.detector = detector or Detector()
        self.normalize_text, self.validate, self.max_rounds = normalize_text, validate, max_rounds
        self.ledger = ledger if ledger is not None else AuditLedger()

    def process(self, text: str, job_id: str = "job", approved_types: Optional[Set[str]] = None,
                override_high: bool = False) -> Result:
        t: Dict[str, float] = {}
        c0 = time.perf_counter()
        work = normalize(text) if self.normalize_text else text
        t["normalize"] = time.perf_counter() - c0
        pre = sha256_hex(work)
        c0 = time.perf_counter()
        entities = self.detector.detect(work)
        t["detect"] = time.perf_counter() - c0
        risk = rubric_label([e.type for e in entities])
        self.ledger.record("SCAN", job_id, "OK", pre_hash=pre, meta={"entities": len(entities), "risk": risk})
        log.info("job=%s scan entities=%d risk=%s", job_id, len(entities), risk)

        if not entities and not self.validate:
            self.ledger.record("DECISION", job_id, Decision.ALLOW.value, pre_hash=pre, post_hash=pre)
            return Result(Decision.ALLOW, work, entities, 0, 0, risk, t)

        kept = [e for e in entities if approved_types is not None and e.type not in approved_types]
        if kept and any(e.type in HIGH_TYPES for e in kept) and not override_high:
            self.ledger.record("DECISION", job_id, Decision.REQUEST_APPROVAL.value, pre_hash=pre,
                               meta={"kept_types": sorted({e.type for e in kept})})
            return Result(Decision.REQUEST_APPROVAL, None, entities, 0, 0, risk, t)

        c0 = time.perf_counter()
        out = redact(work, entities, approved_types)
        t["redact"] = time.perf_counter() - c0
        rounds, residual = 1, 0
        c0 = time.perf_counter()
        if self.validate:
            while True:
                leftover = [x for x in strict_scan(out)
                            if not any(k.value in x.value or x.value in k.value for k in kept)]  # consent: kept entities stay
                residual = len(leftover)
                self.ledger.record("RESCAN", job_id, "CLEAN" if not residual else "RESIDUAL",
                                   post_hash=sha256_hex(out), meta={"residual": residual, "round": rounds})
                if not residual or rounds >= self.max_rounds + 1:
                    break
                out = redact(out, leftover)
                rounds += 1
        t["rescan"] = time.perf_counter() - c0

        if residual:
            decision, released = Decision.BLOCK, None
        elif entities or rounds > 1:
            decision, released = Decision.REDACT, out
        else:
            decision, released = Decision.ALLOW, out
        self.ledger.record("DECISION", job_id, decision.value, pre_hash=pre, post_hash=sha256_hex(out),
                           meta={"rounds": rounds, "residual": residual})
        log.info("job=%s decision=%s rounds=%d residual=%d", job_id, decision.value, rounds, residual)
        return Result(decision, released, entities, residual, rounds, risk, t)
