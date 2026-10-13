"""Synthetic benchmark generator for AI Shield-Bench. All people and numbers are fictional."""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import List, Tuple

import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from aishield.detector import _D, _P  # Verhoeff tables, used to generate valid ID numbers

FIRST = ["Rindhiya", "Anushree", "Hemachandran", "Arun", "Priya", "Karthik", "Divya", "Suresh", "Meena", "Vignesh",
         "Lakshmi", "Ravi", "Kavya", "Ganesh", "Deepa", "Manoj", "Nandini", "Prakash", "Revathi", "Sathish",
         "Bharathi", "Dinesh", "Eswari", "Gokul", "Harini", "Jayanth", "Keerthana", "Lokesh", "Mythili", "Naveen",
         "Oviya", "Pradeep", "Qasim", "Ramya", "Santhosh", "Tamilarasi", "Udhay", "Vimala", "Yogesh", "Zainab",
         "Abinaya", "Balaji", "Chitra", "Dharani", "Elango", "Fathima", "Gayathri", "Hari", "Indira", "Jeeva",
         "Kamala", "Logesh", "Madhan", "Nithya", "Omkar", "Parvathi", "Rajesh", "Selvi", "Thiru", "Uma"]
LAST = ["Kumar", "Sharma", "Raj", "Devi", "Nair", "Iyer", "Pillai", "Reddy", "Menon", "Das", "Babu", "Gupta",
        "Krishnan", "Murthy", "Rao", "Singh", "Verma", "Joseph", "Mohan", "Selvam"]
STREETS = ["Anna", "Gandhi", "Nehru", "Bharathi", "Kamaraj", "Patel", "Rajaji"]
CITIES = ["Puducherry", "Chennai", "Villupuram", "Cuddalore", "Vellore", "Salem"]
DEPTS = ["UAI", "UCC", "UEC", "UME", "UCS", "UIT"]
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
SHOPS = ["Kavya Textiles", "Meena Salon", "Lakshmi Nagar bus stop", "Arun Cycles", "Divya Jewellers", "Ganesh Mess"]
FILLER = [
    "The project uses a serverless architecture on AWS with Lambda and API Gateway.",
    "Results show that the system reduces manual review time for documents.",
    "The dataset was split into training and testing sets for evaluation.",
    "Please summarize the main findings and list the open issues.",
    "The quarterly review covered revenue, churn and support tickets.",
    "We compared three approaches and selected the one with the best recall.",
    "The report describes the methodology, results and future work.",
    "Section 3 explains how the pipeline handles retries and failures.",
]


def verhoeff_check_digit(num: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]
    return str(inv[c])


def valid_id12(r: random.Random) -> str:
    base = str(r.randint(2, 9)) + "".join(str(r.randint(0, 9)) for _ in range(10))
    return base + verhoeff_check_digit(base)


@dataclass
class Doc:
    text: str
    pii: List[Tuple[str, str]] = field(default_factory=list)       # (type, value) that must not survive
    negatives: List[str] = field(default_factory=list)             # strings that must be preserved
    kind: str = "typical"


def _name(r):
    return r.choice(FIRST), r.choice(LAST)


def make_doc(r: random.Random, kind: str) -> Doc:
    parts: List[str] = []
    pii: List[Tuple[str, str]] = []
    neg: List[str] = []
    first, last = _name(r)

    def add_person(sentence_fmt: str, value: str):
        parts.append(sentence_fmt.format(P=value)); pii.append(("PERSON", value))

    n_ent = {"clean": 0, "hardneg": 0, "light": r.randint(1, 3), "typical": r.randint(3, 6), "heavy": r.randint(6, 9)}[kind]
    pool = ["person", "email", "phone", "sid", "id", "pan", "dob", "addr", "person2"]
    chosen = r.sample(pool, min(n_ent, len(pool))) if n_ent else []
    for item in chosen:
        if item == "person":
            v = f"{first} {last}" if r.random() < 0.7 else f"{first} {last[0]}"
            add_person(r.choice(["My name is {P}.", "Submitted by {P}.", "Name: {P}", "Prepared by {P}."]), v)
        elif item == "person2":
            f2, l2 = _name(r)
            verb = r.choice(["presented the results to the committee", "reviewed the draft yesterday", "approved the budget",
                             "confirmed the schedule", "joined the project in March", "wrote the final section",
                             "mentioned the issue in the meeting", "supervised the experiment"])
            parts.append(f"{f2} {l2} {verb}."); pii.append(("PERSON", f"{f2} {l2}"))
        elif item == "email":
            v = r.choice([f"{first.lower()}.{last.lower()}", f"{first.lower()}{r.randint(1, 99)}", f"{first.lower()}_{last[0].lower()}"]) \
                + "@" + r.choice(["example.com", "mail.org", "college.edu.in", "corp.co.in"])
            parts.append(r.choice(["Email: {}", "You can write to me at {}.", "My email is {}."]).format(v)); pii.append(("EMAIL", v))
        elif item == "phone":
            d = str(r.randint(6, 9)) + "".join(str(r.randint(0, 9)) for _ in range(9))
            v = r.choice([d, d[:5] + " " + d[5:], "+91 " + d[:5] + " " + d[5:], "+91-" + d])
            parts.append(r.choice(["Phone: {}", "Call me on {}.", "Contact number {}."]).format(v)); pii.append(("PHONE", v))
        elif item == "sid":
            v = f"{r.randint(21, 25)}{r.choice(DEPTS)}{r.randint(1, 199):03d}"
            parts.append(r.choice(["My register number is {}.", "Register No: {}", "Roll number {}."]).format(v)); pii.append(("STUDENT_ID", v))
        elif item == "id":
            d = valid_id12(r)
            v = d if r.random() < 0.5 else f"{d[:4]} {d[4:8]} {d[8:]}"
            parts.append(r.choice(["Aadhaar number {}.", "National ID: {}", "ID number {} is attached."]).format(v)); pii.append(("ID_NUMBER", v))
        elif item == "pan":
            v = "".join(r.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(5)) + f"{r.randint(1000, 9999)}" + r.choice("ABCDEFGHJKLMNPQRSTUVWXYZ")
            parts.append(f"PAN {v} is on file."); pii.append(("ID_NUMBER", v))
        elif item == "dob":
            dd, mm, yy = r.randint(1, 28), r.randint(1, 12), r.randint(1995, 2006)
            v = r.choice([f"{dd:02d}/{mm:02d}/{yy}", f"{dd:02d}-{mm:02d}-{yy}", f"{dd} {MONTHS[mm - 1]} {yy}"])
            parts.append(r.choice(["Date of birth: {}", "DOB: {}", "Born on {}."]).format(v)); pii.append(("DATE_OF_BIRTH", v))
        elif item == "addr":
            v = f"{r.randint(1, 99)}, {r.choice(STREETS)} Street, {r.choice(CITIES)} {r.randint(600, 636)}{r.randint(0, 999):03d}"
            parts.append(r.choice(["Address: {}", "I live at {}."]).format(v)); pii.append(("ADDRESS", v))
    # hard negatives and filler
    for _ in range(r.randint(2, 4)):
        parts.append(r.choice(FILLER))
    n_neg = r.randint(3, 6) if kind == "hardneg" else r.randint(0, 2)
    for _ in range(n_neg):
        t = r.choice(["order", "version", "date", "shop", "code", "money", "invoice"])
        if t == "order":
            v = "".join(str(r.randint(0, 9)) for _ in range(12)); parts.append(f"Order ID {v} was delivered."); neg.append(v)
        elif t == "version":
            v = f"v{r.randint(1, 4)}.{r.randint(0, 9)}.{r.randint(0, 9)}"; parts.append(f"The release {v} fixes two bugs."); neg.append(v)
        elif t == "date":
            v = f"{r.randint(1, 28):02d}/{r.randint(1, 12):02d}/2026"; parts.append(f"The deadline is {v} for all submissions."); neg.append(v)
        elif t == "shop":
            v = r.choice(SHOPS); parts.append(f"We ordered supplies from {v} last week."); neg.append(v)
        elif t == "code":
            letters = r.choice(DEPTS) if r.random() < 0.3 else "".join(r.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(3))
            v = f"{r.randint(21, 25)}{letters}{r.randint(100, 999)}"; parts.append(f"Reference code {v} identifies the shipment."); neg.append(v)
        elif t == "money":
            v = f"Rs {r.randint(10, 99)},{r.randint(100, 999)}"; parts.append(f"The budget approved was {v}."); neg.append(v)
        else:
            v = f"INV-2026{r.randint(1000, 9999)}"; parts.append(f"Invoice {v} is pending."); neg.append(v)
    parts = [p if p.endswith('.') else p + '.' for p in parts]
    r.shuffle(parts)
    return Doc(" ".join(parts), pii, neg, kind)


def make_corpus(n: int, seed: int) -> List[Doc]:
    r = random.Random(seed)
    kinds = ["clean"] * 15 + ["hardneg"] * 15 + ["light"] * 20 + ["typical"] * 35 + ["heavy"] * 15
    return [make_doc(r, r.choice(kinds)) for _ in range(n)]


# ---------------------------------------------------------------- adversarial suite (12 classes x 2 scenarios)
@dataclass
class Adv:
    cls: str
    text: str
    markers: List[str]   # canonical strings that must not appear in released output


def _canon(s: str) -> str:
    import re, unicodedata
    s = unicodedata.normalize("NFKC", s)
    return re.sub(r"[\s.\-\u200b\u200c\u200d\u2060\ufeff]", "", s.lower())


def adversarial() -> List[Adv]:
    S: List[Adv] = []
    def add(c, t, m): S.append(Adv(c, t, [_canon(x) for x in m]))
    add("Spaced email", "Contact: rindhiya @ example . com for details.", ["rindhiya", "example"])
    add("Spaced email", "Write to arun.kumar @ mail . org today.", ["arun.kumar", "mail"])
    add("[at]/[dot] email", "Reach me at priya[at]college[dot]edu[dot]in please.", ["priya", "college"])
    add("[at]/[dot] email", "Email karthik(at)corp(dot)com is monitored.", ["karthik", "corp"])
    add("Full-width digits phone", "Call \uff19\uff18\uff17\uff16\uff15\uff14\uff13\uff12\uff11\uff10 now.", ["9876543210"])
    add("Full-width digits phone", "Phone: \uff17\uff18\uff19\uff10\uff11\uff12\uff13\uff14\uff15\uff16 (mobile).", ["7890123456"])
    add("Zero-width in ID", "My register number is 23UAI\u200b091 as listed.", ["23uai091"])
    add("Zero-width in ID", "Roll number 24UC\u200cC014 is attached.", ["24ucc014"])
    add("Spaced digit phone", "Phone: 9 8 7 6 5 4 3 2 1 0 any time.", ["9876543210"])
    add("Spaced digit phone", "Call 8 7 6 5 4 3 2 1 0 9 after noon.", ["8765432109"])
    add("Phone in words", "Call nine eight seven six five four three two one zero.", ["nineeightsevensixfivefourthreetwoonezero"])
    add("Phone in words", "My number is eight seven six five four three two one zero nine.", ["eightsevensixfivefourthreetwoonezeronine"])
    d1, d2 = "234567890124", "345678901236"
    d1 = d1[:-1] + verhoeff_check_digit(d1[:-1]); d2 = d2[:-1] + verhoeff_check_digit(d2[:-1])
    add("Dotted ID number", f"National ID {d1[:4]}.{d1[4:8]}.{d1[8:]} is on file.", [d1])
    add("Dotted ID number", f"ID: {d2[:4]}.{d2[4:8]}.{d2[8:]} attached.", [d2])
    add("Uppercase name", "NAME: ARUN KUMAR\nDEPARTMENT: AI&DS", ["arunkumar"])
    add("Uppercase name", "NAME: PRIYA SHARMA\nCLASS: FINAL YEAR", ["priyasharma"])
    add("Name after line break", "Submitted by\n\nKarthik Raj\nfor review.", ["karthikraj"])
    add("Name after line break", "Prepared by\nDivya Nair\non Monday.", ["divyanair"])
    add("URL-encoded email", "Link: mailto:rindhiya%40example.com sent.", ["rindhiya", "example"])
    add("URL-encoded email", "Use arun%40mail.org for replies.", ["arun", "mail"])
    add("Non-Latin name", "என் பெயர் அருண் குமார்.", ["அருண்"])
    add("Non-Latin name", "பெயர்: பிரியா சர்மா", ["பிரியா"])
    add("Lowercase name", "my name is arun kumar and I study AI.", ["arunkumar"])
    add("Lowercase name", "hello, my name is priya sharma.", ["priyasharma"])
    return S
