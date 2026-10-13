"""Redaction (redact-service): replace approved spans with type tags, right to left."""
from __future__ import annotations

from typing import Iterable, Optional, Set

from .detector import Entity


def redact(text: str, entities: Iterable[Entity], approved_types: Optional[Set[str]] = None) -> str:
    out = text
    for e in sorted(entities, key=lambda x: x.start, reverse=True):
        if approved_types is not None and e.type not in approved_types:
            continue
        tag = "[REDACTED]" if e.type == "RESIDUAL" else f"[{e.type}]"
        out = out[:e.start] + tag + out[e.end:]
    return out
