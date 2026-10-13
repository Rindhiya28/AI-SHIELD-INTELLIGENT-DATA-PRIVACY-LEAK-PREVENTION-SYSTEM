import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from aishield.detector import Detector, verhoeff_valid
from aishield.governor import Governor, Decision
from aishield.normalize import normalize
from aishield.redactor import redact
from aishield.ledger import AuditLedger
from aishield.risk import rubric_label
from aishield.validator import strict_scan
from aishield.rag import SafetyGate, ToolExecutor, GuidelineRetriever, build_prompt
from aishield import handlers as H

SAMPLE = "My name is Rindhiya A. My email is rindhiya@example.com, and my register number is 23UAI091. Please summarize my project report."


def types(t): return [e.type for e in Detector().detect(t)]


def test_sample_entities(): assert types(SAMPLE) == ["PERSON", "EMAIL", "STUDENT_ID"]
def test_sample_redaction():
    r = Governor().process(SAMPLE); assert r.sanitized.startswith("My name is [PERSON]. My email is [EMAIL]")
def test_phone_formats():
    for p in ["9876543210", "98765 43210", "+91 98765 43210", "+91-9876543210"]: assert "PHONE" in types(f"Call {p}.")
def test_lookalike_code_not_flagged(): assert types("Reference code 24QWE123 identifies the shipment.") == []
def test_dept_code_flagged(): assert "STUDENT_ID" in types("Item 23UAI091 listed.")
def test_dob_needs_cue(): assert types("Deadline is 12/05/2026.") == [] and "DATE_OF_BIRTH" in types("DOB: 12/05/2004.")
def test_address(): assert "ADDRESS" in types("Address: 12, Anna Street, Puducherry 605107.")
def test_verhoeff():
    sys.path.insert(0, os.path.join(ROOT, "bench"))
    from gen import verhoeff_check_digit
    base = "23456789012"; ok = base + verhoeff_check_digit(base)
    bad = base + str((int(ok[-1]) + 1) % 10)
    assert verhoeff_valid(ok) and not verhoeff_valid(bad)
def test_org_not_person(): assert types("We ordered from Kavya Textiles last week.") == []
def test_normalize_fullwidth(): assert normalize("\uff19\uff18") == "98"
def test_normalize_zero_width(): assert normalize("23UAI\u200b091") == "23UAI091"
def test_redact_tags(): assert redact("a@b.com", Detector().detect("a@b.com")) == "[EMAIL]"
def test_strict_scan_obfuscated_email(): assert strict_scan("x [at] y [dot] com")
def test_rescan_catches_spaced_phone():
    r = Governor().process("Phone: 9 8 7 6 5 4 3 2 1 0 any time."); assert "9 8 7" not in (r.sanitized or "")
def test_allow_clean(): assert Governor().process("The report describes the methodology.").decision == Decision.ALLOW
def test_request_approval_for_high_kept():
    r = Governor().process(SAMPLE, approved_types={"EMAIL"}); assert r.decision == Decision.REQUEST_APPROVAL and r.sanitized is None
def test_consent_subset():
    r = Governor().process("My name is Arun Kumar. Email arun@x.com", approved_types={"EMAIL"})
    assert "Arun Kumar" in r.sanitized and "arun@x.com" not in r.sanitized
def test_rubric(): assert rubric_label([]) == "LOW" and rubric_label(["PERSON", "EMAIL", "PHONE"]) == "HIGH" and rubric_label(["STUDENT_ID"]) == "HIGH"
def test_ledger_valid_and_tamper():
    L = AuditLedger()
    for i in range(10): L.record("SCAN", f"j{i}", "OK")
    assert L.verify(); L.chain[4].status = "X"; assert not L.verify()
def test_ledger_delete():
    L = AuditLedger()
    for i in range(10): L.record("SCAN", f"j{i}", "OK")
    del L.chain[3]; assert not L.verify()
def test_gate(): g = SafetyGate(); assert not g.is_clean(SAMPLE) and g.is_clean("My name is [PERSON].")
def test_tool_guard():
    e = ToolExecutor(); assert e.call("redact_entities")["status"] == "REFUSED" and e.call("redact_entities", confirmed=True)["status"] == "OK"
def test_prompt_has_no_values():
    r = Governor().process(SAMPLE); p = build_prompt("s", r.sanitized, GuidelineRetriever().top_k("student register number", 3))
    assert "23UAI091" not in p and "rindhiya@example.com" not in p
def test_retriever_student(): assert "G04" in [c["id"] for c in GuidelineRetriever().top_k("student register number handling", 3)]
def _ev(b=None, p=None): return {"body": b, "pathParameters": p}
def test_handler_400(): assert H.scan_handler(_ev(None))["statusCode"] == 400 and H.scan_handler(_ev("{x"))["statusCode"] == 400
def test_handler_413(): assert H.scan_handler(_ev(json.dumps({"text": "a" * 200001})))["statusCode"] == 413
def test_handler_flow():
    s = H.scan_handler(_ev(json.dumps({"text": SAMPLE, "job_id": "t1"}))); assert s["statusCode"] == 200 and "rindhiya@example.com" not in s["body"]
    r = H.redact_handler(_ev(json.dumps({"job_id": "t1"}))); assert json.loads(r["body"])["decision"] == "REDACT"
    assert H.report_handler(_ev(None, {"jobId": "t1"}))["statusCode"] == 200
def test_handler_404(): assert H.redact_handler(_ev(json.dumps({"job_id": "none"})))["statusCode"] == 404
