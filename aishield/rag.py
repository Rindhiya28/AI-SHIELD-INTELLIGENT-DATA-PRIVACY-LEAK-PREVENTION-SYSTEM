"""RAG layer (explain-service): guideline retrieval, prompt builder, safety gate and agent tool executor."""
from __future__ import annotations

from collections import Counter
from typing import Dict, List, Sequence

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .detector import Detector
from .validator import strict_scan

GUIDELINES: List[Dict[str, str]] = [
    {"id": "G01", "topic": "PERSON", "text": "A person's name on its own is low risk, but combined with any other identifier it can identify one individual. Remove names before a document is shared outside the organisation."},
    {"id": "G02", "topic": "EMAIL", "text": "Email addresses are direct contact identifiers. Remove them from documents sent to external services because they enable tracking, phishing and unsolicited contact."},
    {"id": "G03", "topic": "PHONE", "text": "Phone numbers identify and locate a person. Redact mobile and landline numbers, including numbers written with spaces, country codes or dashes, before sharing a document."},
    {"id": "G04", "topic": "STUDENT_ID", "text": "Student register numbers and roll numbers link a document to a specific student record. Treat them as high risk and redact them whenever a document leaves the institution."},
    {"id": "G05", "topic": "ID_NUMBER", "text": "Government identification numbers such as national ID and tax numbers are high risk. Never send them to external tools, because misuse can lead to identity fraud."},
    {"id": "G06", "topic": "ADDRESS", "text": "A postal address with a PIN code reveals where a person lives. Treat addresses as high risk and remove street, locality and PIN code together."},
    {"id": "G07", "topic": "DATE_OF_BIRTH", "text": "A date of birth is a strong quasi-identifier. Combined with a name or location it can single out a person, so redact it before sharing."},
    {"id": "G08", "topic": "MINIMISATION", "text": "Data minimisation means sharing only the personal data that a task really needs. A summary request never needs the author's personal details."},
    {"id": "G09", "topic": "PURPOSE", "text": "Purpose limitation means personal data collected for one purpose should not be reused for another. Uploading a report to a chatbot is a new purpose that needs review."},
    {"id": "G10", "topic": "RETENTION", "text": "Storage limitation means documents and derived data are deleted when no longer needed. Set an expiry on uploads and sanitised files and delete them automatically."},
    {"id": "G11", "topic": "THIRD_PARTY_AI", "text": "Text sent to an external AI service may be logged or retained by the provider. Treat everything pasted into a chatbot as disclosed to a third party."},
    {"id": "G12", "topic": "REIDENTIFICATION", "text": "Removing a name does not make a document anonymous if a combination of details such as role, place and date can still identify the person."},
    {"id": "G13", "topic": "CONSENT", "text": "Personal data should be changed or released only with the informed choice of the person it belongs to. Show findings to the user and record which entities they approved."},
    {"id": "G14", "topic": "LOGGING", "text": "Application logs must not contain raw personal data. Log entity types, counts and hashes so that audits are possible without creating another copy of the data."},
    {"id": "G15", "topic": "BREACH", "text": "If sensitive data is sent to an unintended recipient, record the incident, identify what was disclosed and notify the data owner without delay."},
    {"id": "G16", "topic": "ENCRYPTION", "text": "Encrypt personal data at rest with managed keys and in transit with TLS, and restrict key use to the services that need it."},
    {"id": "G17", "topic": "ACCESS_CONTROL", "text": "Apply least privilege so each service and user can reach only the documents needed for their role, and require multi-factor authentication for administrators."},
    {"id": "G18", "topic": "AUDIT", "text": "Keep an append-only audit trail of scans, redactions and releases so that every decision can be reviewed and tampering can be detected."},
    {"id": "G19", "topic": "VALIDATION", "text": "After redaction, rescan the output with a broad detector, because obfuscated or reformatted identifiers can survive the first pass."},
    {"id": "G20", "topic": "HIGH_RISK_COMBINATION", "text": "A name together with an identification number, contact detail or address is the highest-risk combination and must be redacted before external sharing."},
]


class GuidelineRetriever:
    def __init__(self, guidelines: Sequence[Dict[str, str]] = GUIDELINES) -> None:
        self.guidelines = list(guidelines)
        self.vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), sublinear_tf=True)
        self.matrix = self.vec.fit_transform([g["text"] for g in self.guidelines])

    def top_k(self, query: str, k: int = 3) -> List[Dict[str, str]]:
        sims = cosine_similarity(self.vec.transform([query]), self.matrix)[0]
        order = sims.argsort()[::-1][:k]
        return [self.guidelines[i] for i in order]


def findings_summary(entity_types: Sequence[str], risk: str) -> str:
    counts = Counter(entity_types)
    parts = ", ".join(f"{n} {t}" for t, n in sorted(counts.items())) or "none"
    return f"Risk level: {risk}. Entities found and removed: {parts}."


def build_prompt(summary: str, sanitized: str, chunks: Sequence[Dict[str, str]]) -> str:
    context = "\n".join(f"[{c['id']}] {c['text']}" for c in chunks)
    return (
        "SYSTEM: You are a data privacy assistant. Explain the findings using only the guidelines below. "
        "If the guidelines do not cover a point, say so.\n"
        f"GUIDELINES:\n{context}\n"
        f"FINDINGS: {summary}\n"
        f"SANITISED_TEXT: {sanitized}\n"
        "OUTPUT: JSON with keys found, why_risky, recommended_action, supporting_guideline."
    )


class SafetyGate:
    """Blocks any LLM call when the text still contains detectable sensitive data."""

    def __init__(self) -> None:
        self.detector = Detector()

    def is_clean(self, text: str) -> bool:
        return not self.detector.detect(text) and not strict_scan(text)


class ToolExecutor:
    """Agent tool layer: state-changing tools need explicit user confirmation, whatever the model asks for."""

    STATE_CHANGING = {"redact_entities"}

    def __init__(self) -> None:
        self.calls: List[str] = []
        self.refused: List[str] = []

    def call(self, tool: str, confirmed: bool = False, **kwargs):
        if tool in self.STATE_CHANGING and not confirmed:
            self.refused.append(tool)
            return {"status": "REFUSED", "reason": "user confirmation required"}
        self.calls.append(tool)
        return {"status": "OK", "tool": tool}
