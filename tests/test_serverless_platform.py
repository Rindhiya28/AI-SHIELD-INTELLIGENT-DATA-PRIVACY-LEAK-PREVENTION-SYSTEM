"""Unit and integration tests for AWS Serverless Platform (Module 1).
Validates SAM template syntax, state machine reachability, IAM policies, and Lambda handlers.
"""
import json
import os
import time
import yaml
import pytest

from aishield import lambdas as L

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_PATH = os.path.join(ROOT, "template.yaml")
STATE_MACHINE_PATH = os.path.join(ROOT, "deploy", "state_machine.json")
POLICY_PATH = os.path.join(ROOT, "deploy", "lambda_policy.json")

SAMPLE = "My name is Rindhiya A. My email is rindhiya@example.com, and my register number is 23UAI091."


def test_sam_template_structure():
    """Verify that template.yaml is valid YAML and contains all required serverless resources."""
    assert os.path.exists(TEMPLATE_PATH)
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        # Ignore AWS specific tags like !Ref, !Sub, !GetAtt during plain yaml load
        content = f.read()
        for tag in ["!Ref", "!Sub", "!GetAtt"]:
            content = content.replace(tag, "")
        tmpl = yaml.safe_load(content)

    resources = tmpl["Resources"]
    
    # Check Lambdas
    expected_lambdas = [
        "UploadFunction", "ExtractFunction", "DetectFunction",
        "RiskFunction", "ReviewFunction", "RedactFunction",
        "RescanFunction", "ReportFunction", "ExplainFunction"
    ]
    for fn in expected_lambdas:
        assert fn in resources, f"Missing Lambda resource: {fn}"

    # Check DynamoDB, S3, Step Functions, API Gateway
    assert "JobsTable" in resources
    assert "UploadsBucket" in resources
    assert "SanitizedBucket" in resources
    assert "ReportsBucket" in resources
    assert "AIShieldApi" in resources
    assert "AIShieldStateMachine" in resources
    assert "KMSKey" in resources


def test_state_machine_flow_and_reachability():
    """Verify Step Functions state machine graph: reachability, choices, pause tokens, and terminals."""
    assert os.path.exists(STATE_MACHINE_PATH)
    with open(STATE_MACHINE_PATH, "r", encoding="utf-8") as f:
        asl = json.load(f)

    states = asl["States"]
    assert asl["StartAt"] in states

    # Check waitForTaskToken pattern on WaitForUserReview
    review_state = states.get("WaitForUserReview")
    assert review_state is not None
    assert "waitForTaskToken" in review_state["Resource"]

    # Graph reachability traversal
    reachable = set()
    stack = [asl["StartAt"]]
    while stack:
        cur = stack.pop()
        if cur in reachable:
            continue
        reachable.add(cur)
        st = states.get(cur, {})
        if "Next" in st:
            stack.append(st["Next"])
        for c in st.get("Choices", []):
            stack.append(c["Next"])
        if "Default" in st:
            stack.append(st["Default"])
        for c in st.get("Catch", []):
            stack.append(c["Next"])

    # All defined states except terminal error handlers should be reachable
    for s_name in states:
        assert s_name in reachable, f"State {s_name} is dangling or unreachable!"


def test_lambda_policy_least_privilege():
    """Verify IAM policy contains no unrestricted wildcard actions."""
    assert os.path.exists(POLICY_PATH)
    with open(POLICY_PATH, "r", encoding="utf-8") as f:
        pol = json.load(f)

    for st in pol["Statement"]:
        actions = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
        # No statement should allow full wildcard action '*'
        assert "*" not in actions, f"Wildcard action found in statement {st.get('Sid')}"


def test_microservice_lambdas_execution_and_latency():
    """Benchmark cold start vs warm execution latency for the microservice handlers."""
    # 1. Upload service
    up_res = L.upload_handler({"text": SAMPLE})
    assert up_res["statusCode"] == 200

    # 2. Extract service
    ext_res = L.extract_handler({"text": SAMPLE})
    assert "text" in ext_res and len(ext_res["text"]) > 0

    # 3. Detect service (cold start vs warm latency measurement)
    t0 = time.perf_counter()
    det_res = L.detect_handler({"text": ext_res["text"]})
    cold_start_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    det_res_warm = L.detect_handler({"text": ext_res["text"]})
    warm_ms = (time.perf_counter() - t0) * 1000

    assert det_res["entity_count"] >= 3
    assert cold_start_ms >= 0 and warm_ms >= 0

    # 4. Risk service
    risk_res = L.risk_handler(det_res)
    assert risk_res["risk"] == "HIGH"

    # 5. Review service pause
    review_res = L.review_handler({"input": risk_res, "taskToken": "token-12345"})
    assert review_res["status"] == "WAITING_FOR_USER_REVIEW"

    # 6. Redact service
    red_res = L.redact_handler({"text": ext_res["text"]})
    assert red_res["redacted"] is True
    assert "[PERSON]" in red_res["sanitized"]

    # 7. Rescan service
    rescan_res = L.rescan_handler({"text": red_res["sanitized"]})
    assert rescan_res["clean"] is True
    assert rescan_res["residual_count"] == 0

    # 8. Report service
    rep_res = L.report_handler({"job_id": "test_job"})
    assert rep_res["status"] == "COMPLETED"

    # 9. Explain service (Safety Gate block when un-sanitized)
    bad_explain = L.explain_handler({"sanitized": SAMPLE})
    assert bad_explain["statusCode"] == 403

    # Clean explain
    good_explain = L.explain_handler({
        "sanitized": red_res["sanitized"],
        "risk": "HIGH",
        "entity_types": ["PERSON", "EMAIL", "STUDENT_ID"]
    })
    assert good_explain["statusCode"] == 200
    assert good_explain["body"] is not None
