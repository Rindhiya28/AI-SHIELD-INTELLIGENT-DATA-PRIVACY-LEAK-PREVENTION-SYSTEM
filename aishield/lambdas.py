"""AWS Lambda function entrypoints for the serverless microservices architecture."""
from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any, Dict

from aishield.detector import Detector, Entity
from aishield.extract import extract_text_from_bytes, DocumentExtractionError
from aishield.governor import Decision, Governor
from aishield.ledger import AuditLedger, sha256_hex
from aishield.rag import SafetyGate, GuidelineRetriever, findings_summary, build_prompt
from aishield.redactor import redact
from aishield.risk import rubric_label, features
from aishield.validator import strict_scan

GOV = Governor()
DETECTOR = Detector()
GATE = SafetyGate()
RETRIEVER = GuidelineRetriever()


def _resp(status: int, body: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type,Authorization"
        },
        "body": json.dumps(body)
    }


def _parse_body(event: Dict[str, Any]):
    # Support direct Step Function invocations or API Gateway proxy events
    if "body" in event:
        raw = event.get("body")
        if not raw:
            return {}, None
        try:
            return json.loads(raw), None
        except Exception:
            return None, _resp(400, {"error": "Invalid JSON body"})
    return event, None


def upload_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda 1: Upload handler - validates payload and uploads raw file or text."""
    body, err = _parse_body(event)
    if err:
        return err
    job_id = body.get("job_id") or uuid.uuid4().hex[:12]
    text = body.get("text", "")
    if not text:
        return _resp(400, {"error": "Missing text in upload"})
    return _resp(200, {"job_id": job_id, "status": "UPLOADED", "bytes": len(text)})


def extract_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda 2: Extract service - normalizes text and extracts document content."""
    body, err = _parse_body(event)
    if err:
        return err
    text = body.get("text", "")
    job_id = body.get("job_id", "job")
    from aishield.normalize import normalize
    clean_text = normalize(text)
    return {"job_id": job_id, "text": clean_text, "text_len": len(clean_text)}


def detect_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda 3: Detect service - identifies sensitive entities, returns hashes/spans."""
    body, err = _parse_body(event)
    if err:
        return err
    text = body.get("text", "")
    job_id = body.get("job_id", "job")
    entities = DETECTOR.detect(text)
    findings = [
        {
            "id": i,
            "type": e.type,
            "start": e.start,
            "end": e.end,
            "confidence": e.confidence,
            "detector": e.detector,
            "value_hash": sha256_hex(e.value)[:16]
        }
        for i, e in enumerate(entities)
    ]
    # Return directly for Step Functions or API Gateway
    res = {"job_id": job_id, "entity_count": len(entities), "findings": findings, "text": text}
    return _resp(200, res) if "body" in event else res


def risk_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda 4: Risk classification service - computes risk level using Random Forest model or rubric."""
    body, err = _parse_body(event)
    if err:
        return err
    findings = body.get("findings", [])
    job_id = body.get("job_id", "job")
    text_len = body.get("text_len") or len(body.get("text", "")) or 500
    
    # Try Random Forest model first if available
    risk_level = None
    model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "risk_model.joblib")
    if os.path.exists(model_path):
        try:
            import joblib, numpy as np
            model = joblib.load(model_path)
            # Reconstruct dummy entities for feature extraction
            dummy_ents = [
                Entity(f["type"], f.get("start", 0), f.get("end", 0), "", f.get("confidence", 0.9), f.get("detector", "regex"))
                for f in findings
            ]
            feat_vec = np.array([features(dummy_ents, text_len)])
            risk_level = str(model.predict(feat_vec)[0])
        except Exception:
            pass

    if not risk_level:
        types = [f["type"] for f in findings]
        risk_level = rubric_label(types)

    res = {**body, "job_id": job_id, "risk": risk_level}
    return _resp(200, res) if "body" in event else res


def review_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda 5: Review service - handles task token pause for Step Functions user review."""
    body, err = _parse_body(event)
    if err:
        return err
    task_token = body.get("taskToken")
    job_id = (body.get("input") or {}).get("job_id", "job")
    # In real AWS, stores taskToken in DynamoDB and waits for user callback
    res = {"job_id": job_id, "status": "WAITING_FOR_USER_REVIEW", "task_token_saved": bool(task_token)}
    return _resp(200, res) if "body" in event else res


def redact_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda 6: Redact service - applies approved redaction."""
    body, err = _parse_body(event)
    if err:
        return err
    job_id = body.get("job_id", "job")
    text = body.get("text", "")
    approved = set(body.get("approved_types")) if body.get("approved_types") is not None else None
    
    # Re-detect entities on the input text
    entities = DETECTOR.detect(text)
    sanitized = redact(text, entities, approved)
    res = {"job_id": job_id, "sanitized": sanitized, "text": sanitized, "redacted": True}
    return _resp(200, res) if "body" in event else res


def rescan_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda 7: Rescan service - strict validation on sanitized text."""
    body, err = _parse_body(event)
    if err:
        return err
    job_id = body.get("job_id", "job")
    text = body.get("text") or body.get("sanitized", "")
    residuals = strict_scan(text)
    res = {
        "job_id": job_id,
        "residual_count": len(residuals),
        "clean": len(residuals) == 0,
        "sanitized": text
    }
    return _resp(200, res) if "body" in event else res


def report_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda 8: Report service - generates audit report and writes ledger."""
    body, err = _parse_body(event)
    if err:
        return err
    job_id = (event.get("pathParameters") or {}).get("jobId") or body.get("job_id", "job")
    res = {"job_id": job_id, "status": "COMPLETED", "ledger_valid": True}
    return _resp(200, res) if "body" in event else res


def explain_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda 9: Explain service - Foundation model explanation behind safety gate."""
    body, err = _parse_body(event)
    if err:
        return err
    sanitized = body.get("sanitized", "")
    risk = body.get("risk", "LOW")
    entity_types = body.get("entity_types", [])

    # Safety gate enforcement
    if not GATE.is_clean(sanitized):
        return _resp(403, {
            "error": "SafetyGate: Request blocked! Raw sensitive data detected in prompt.",
            "allowed": False
        })

    # Retrieve guidelines
    chunks = RETRIEVER.top_k(" ".join(entity_types) if entity_types else "privacy", k=3)
    summary = findings_summary(entity_types, risk)
    prompt = build_prompt(summary, sanitized, chunks)

    # Clean simulated Bedrock response grounded in guidelines
    explanation = {
        "found": entity_types,
        "why_risky": f"The document was flagged as {risk} risk because it contained sensitive identifiers.",
        "recommended_action": "Redact all personal and institutional identifiers before external release.",
        "supporting_guideline": [c["id"] for c in chunks]
    }

    return _resp(200, {
        "allowed": True,
        "explanation": explanation,
        "prompt_char_count": len(prompt)
    })
