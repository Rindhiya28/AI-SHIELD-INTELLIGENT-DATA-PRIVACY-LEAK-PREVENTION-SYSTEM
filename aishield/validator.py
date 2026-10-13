"""Strict rescan validator (rescan-service): broad, high-recall patterns run on sanitised text."""
from __future__ import annotations

import re
from typing import List

from .detector import Entity, _resolve

EMAIL_OBF = re.compile(
    r"[A-Za-z0-9._%+-]+\s*(?:@|%40|\[at\]|\(at\))\s*[A-Za-z0-9-]+(?:\s*(?:\.|\[dot\]|\(dot\))\s*[A-Za-z]{2,})+"
    r"|[A-Za-z0-9._%+-]+\s+at\s+[A-Za-z0-9-]+\s+dot\s+[A-Za-z]{2,}", re.I)
DIGIT_RUN = re.compile(r"(?<!\d)\d(?:[\s.\-]?\d){9,13}(?!\d)")
STUDENT_LOOSE = re.compile(r"(?<![A-Za-z0-9])\d{2}\s?[A-Za-z]{3}\s?\d{3}(?![A-Za-z0-9])")
PAN_LOOSE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{5}\s?\d{4}\s?[A-Za-z](?![A-Za-z0-9])")
NAME_CUE_ANYCASE = re.compile(r"(?:my name is|name\s*[:\-])\s*\n?\s*([A-Za-z][A-Za-z .]{2,40}?)(?=[,;\n]|\.\s|$)", re.I)


def strict_scan(text: str) -> List[Entity]:
    found: List[Entity] = []
    for rx in (EMAIL_OBF, DIGIT_RUN, STUDENT_LOOSE, PAN_LOOSE):
        for m in rx.finditer(text):
            found.append(Entity("RESIDUAL", m.start(), m.end(), m.group(), 0.8, "validator"))
    for m in NAME_CUE_ANYCASE.finditer(text):
        value = m.group(1).strip()
        if value and not value.startswith("["):
            found.append(Entity("RESIDUAL", m.start(1), m.start(1) + len(value), value, 0.7, "validator"))
    return _resolve(found)
