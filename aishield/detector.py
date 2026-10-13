"""Entity detector: regular expressions, checksums and context rules (detect-service)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Set

# Verhoeff checksum tables (used by 12-digit national ID numbers).
_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
      [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
      [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
      [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]


def verhoeff_valid(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


@dataclass(frozen=True)
class Entity:
    type: str
    start: int
    end: int
    value: str
    confidence: float
    detector: str  # "regex" | "context" | "gazetteer" | "validator"


EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE = re.compile(r"(?<![\d])(?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
STUDENT_ID = re.compile(r"(?<![A-Za-z0-9])\d{2}[A-Z]{3}\d{3}(?![A-Za-z0-9])")
AADHAAR = re.compile(r"(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)")
PAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])")
PIN = re.compile(r"(?<!\d)[1-9]\d{2}\s?\d{3}(?!\d)")
DOB_CUE = re.compile(r"(?:date of birth|d\.?o\.?b\.?|born on|birth date)\s*[:\-]?\s*", re.I)
DATE = re.compile(r"\d{1,2}[/\-.]\d{1,2}[/\-.]\d{4}|\d{1,2}\s+[A-Z][a-z]{2,8}\s+\d{4}")
ADDR_CUE = re.compile(r"\b(?:Street|St\.|Road|Rd\.?|Nagar|Colony|Lane|Avenue|Cross|Main|Door No\.?|Flat|Apartment|Village)\b")
NAME_TOKEN = r"[A-Z][a-z]{1,15}"
NAME_BODY = rf"{NAME_TOKEN}(?:\s{NAME_TOKEN}){{0,2}}(?:\s[A-Z]\b\.?)?|[A-Z]\.\s?{NAME_TOKEN}"
CUE = re.compile(
    rf"(?:[Mm]y name is|[Nn]ame\s*[:\-]|[Ss]ubmitted by|[Pp]repared by|[Aa]uthored by|[Rr]egards,|[Dd]ear|"
    rf"\bMr\.|\bMs\.|\bMrs\.|\bDr\.)\s*({NAME_BODY})")
SID_CUE = re.compile(r"(?:register|reg\.?|roll|student|enrol\w*|admission)", re.I)
DEPT_CODES = {"UAI", "UCC", "UEC", "UME", "UCS", "UIT", "UCE", "UEE"}
ORG_SUFFIX = {"Textiles", "Bakery", "Traders", "Stores", "Jewellers", "Nagar", "Enterprises", "Hospital", "Foods", "Mart", "Agency"}
VERB_NAME = re.compile(rf"\b({NAME_TOKEN}\s{NAME_TOKEN})\s+(?:presented|reviewed|approved|confirmed|joined|wrote|said|reported|attended|signed)\b")
GAZ_NAME = re.compile(rf"\b({NAME_TOKEN}(?:\s{NAME_TOKEN})?(?:\s[A-Z]\b\.?)?)")

# Partial first-name gazetteer: the benchmark generator uses a larger list, so some names are unseen.
FIRST_NAMES = {
    "Rindhiya", "Anushree", "Hemachandran", "Arun", "Priya", "Karthik", "Divya", "Suresh", "Meena", "Vignesh",
    "Lakshmi", "Ravi", "Kavya", "Ganesh", "Deepa", "Manoj", "Nandini", "Prakash", "Revathi", "Sathish",
    "Bharathi", "Dinesh", "Eswari", "Gokul", "Harini", "Jayanth", "Keerthana", "Lokesh", "Mythili", "Naveen",
}
TITLE_STOP = {"Dear", "Name", "Mr", "Ms", "Mrs", "Dr", "Regards"}


class Detector:
    """Configurable detector. The flags allow the baseline configurations to be built from it."""

    def __init__(self, *, ids: bool = True, aadhaar_checksum: bool = True, dob: bool = True, address: bool = True,
                 person_cue: bool = True, person_gazetteer: bool = True, pan: bool = True) -> None:
        self.ids, self.aadhaar_checksum, self.dob = ids, aadhaar_checksum, dob
        self.address, self.person_cue, self.person_gazetteer, self.pan = address, person_cue, person_gazetteer, pan

    def detect(self, text: str) -> List[Entity]:
        found: List[Entity] = []
        for m in EMAIL.finditer(text):
            found.append(Entity("EMAIL", m.start(), m.end(), m.group(), 1.0, "regex"))
        for m in PHONE.finditer(text):
            found.append(Entity("PHONE", m.start(), m.end(), m.group(), 0.97, "regex"))
        if self.ids:
            for m in STUDENT_ID.finditer(text):
                window = text[max(0, m.start() - 45):m.start()]
                if SID_CUE.search(window) or m.group()[2:5] in DEPT_CODES:
                    found.append(Entity("STUDENT_ID", m.start(), m.end(), m.group(), 0.95, "regex"))
            for m in AADHAAR.finditer(text):
                digits = re.sub(r"\s", "", m.group())
                if (not self.aadhaar_checksum) or verhoeff_valid(digits):
                    found.append(Entity("ID_NUMBER", m.start(), m.end(), m.group(), 0.98, "regex"))
            if self.pan:
                for m in PAN.finditer(text):
                    found.append(Entity("ID_NUMBER", m.start(), m.end(), m.group(), 0.95, "regex"))
        if self.dob:
            for cue in DOB_CUE.finditer(text):
                m = DATE.match(text, cue.end())
                if m:
                    found.append(Entity("DATE_OF_BIRTH", m.start(), m.end(), m.group(), 0.9, "context"))
        if self.address:
            found.extend(self._addresses(text))
        if self.person_cue:
            for m in CUE.finditer(text):
                s, e = m.start(1), m.end(1)
                value = text[s:e].rstrip(".")
                if value.split()[0] not in TITLE_STOP:
                    found.append(Entity("PERSON", s, s + len(value), value, 0.9, "context"))
        if self.person_gazetteer:
            for m in GAZ_NAME.finditer(text):
                first = m.group(1).split()[0]
                nxt = text[m.end(1):m.end(1) + 20].split()
                if first in FIRST_NAMES and not (nxt and nxt[0].strip(".,") in ORG_SUFFIX) \
                        and m.group(1).split()[-1] not in ORG_SUFFIX:
                    value = m.group(1).rstrip(".")
                    found.append(Entity("PERSON", m.start(1), m.start(1) + len(value), value, 0.75, "gazetteer"))
        if self.person_cue:
            for m in VERB_NAME.finditer(text):
                found.append(Entity("PERSON", m.start(1), m.end(1), m.group(1), 0.7, "context"))
        return _resolve(found)

    def _addresses(self, text: str) -> List[Entity]:
        out: List[Entity] = []
        for pin in PIN.finditer(text):
            window_start = max(0, pin.start() - 90)
            window = text[window_start:pin.start()]
            cue = None
            for cue in ADDR_CUE.finditer(window):
                pass
            if cue is None:
                continue
            seg = re.split(r"(?:\. |\n|: | at | to )", window[:cue.start()])
            start = pin.start() - len(window) + (len(window[:cue.start()]) - len(seg[-1]))
            out.append(Entity("ADDRESS", start, pin.end(), text[start:pin.end()].strip(), 0.85, "context"))
        return out


def _resolve(entities: Iterable[Entity]) -> List[Entity]:
    """Keep the longest, highest-confidence entity wherever spans overlap."""
    ordered = sorted(entities, key=lambda e: (-(e.end - e.start), -e.confidence, e.start))
    kept: List[Entity] = []
    for e in ordered:
        if all(e.end <= k.start or e.start >= k.end for k in kept):
            kept.append(e)
    return sorted(kept, key=lambda e: e.start)


def baseline_regex_detector() -> Detector:
    """Naive DLP-style baseline: email, phone and plain digit patterns only (no checksum, context or names)."""
    return Detector(ids=True, aadhaar_checksum=False, dob=False, address=False, person_cue=False,
                    person_gazetteer=False, pan=True)
