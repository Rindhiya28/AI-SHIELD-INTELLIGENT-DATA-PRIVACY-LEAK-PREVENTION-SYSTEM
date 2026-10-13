"""AWS Lambda handlers behind API Gateway (proxy integration). The job store stands in for DynamoDB."""
from __future__ import annotations

import json
import uuid
from typing import Any, Dict

from .governor import Decision, Governor
from .ledger import sha256_hex
from .risk import rubric_label

JOBS: Dict[str, Dict[str, Any]] = {}
MAX_CHARS = 200_000
GOV = Governor()


def _resp(code: int, body: Dict[str, Any]) -> Dict[str, Any]:
    return {"statusCode": code, "headers": {"Content-Type": "application/json"}, "body": json.dumps(body)}


def _body(event: Dict[str, Any]):
    raw = event.get("body")
    if not raw:
        return None, _resp(400, {"error": "missing body"})
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return None, _resp(400, {"error": "invalid JSON"})
    if not isinstance(data, dict):
        return None, _resp(400, {"error": "body must be an object"})
    return data, None


def scan_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """POST /scan: detect entities and return findings without raw values."""
    data, err = _body(event)
    if err:
        return err
    text = data.get("text")
    if not isinstance(text, str) or not text.strip():
        return _resp(400, {"error": "text must be a non-empty string"})
    if len(text) > MAX_CHARS:
        return _resp(413, {"error": "document too large"})
    job_id = data.get("job_id") or uuid.uuid4().hex[:12]
    entities = GOV.detector.detect(text)
    JOBS[job_id] = {"text": text, "entities": entities, "status": "REVIEW"}
    return _resp(200, {"job_id": job_id, "risk": rubric_label([e.type for e in entities]),
                       "entities": [{"id": i, "type": e.type, "start": e.start, "end": e.end,
                                     "confidence": e.confidence, "value_hash": sha256_hex(e.value)[:16]}
                                    for i, e in enumerate(entities)]})


def redact_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """POST /redact: apply the user's approved entity types, rescan and return the decision."""
    data, err = _body(event)
    if err:
        return err
    job = JOBS.get(data.get("job_id", ""))
    if job is None:
        return _resp(404, {"error": "unknown job"})
    approved = data.get("approved_types")
    if approved is not None and not isinstance(approved, list):
        return _resp(400, {"error": "approved_types must be a list"})
    res = GOV.process(job["text"], data["job_id"], set(approved) if approved is not None else None)
    job.update(status=res.decision.value, sanitized=res.sanitized)
    return _resp(200, {"job_id": data["job_id"], "decision": res.decision.value, "residual": res.residual,
                       "sanitized": res.sanitized})


def report_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """GET /report/{jobId}: summary of the job without raw values."""
    job_id = (event.get("pathParameters") or {}).get("jobId", "")
    job = JOBS.get(job_id)
    if job is None:
        return _resp(404, {"error": "unknown job"})
    types: Dict[str, int] = {}
    for e in job["entities"]:
        types[e.type] = types.get(e.type, 0) + 1
    return _resp(200, {"job_id": job_id, "status": job["status"], "entity_counts": types,
                       "ledger_valid": GOV.ledger.verify()})
