"""FastAPI application for AI Shield: Intelligent Data Privacy & Leak Prevention System."""
from __future__ import annotations

import os
import uuid
from typing import Any, Dict, List, Optional, Set
from fastapi import FastAPI, File, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from aishield.detector import Entity
from aishield.extract import extract_text_from_bytes, DocumentExtractionError
from aishield.governor import Decision, Governor
from aishield.ledger import sha256_hex
from aishield.risk import rubric_label

app = FastAPI(
    title="AI Shield: Intelligent Data Privacy & Leak Prevention System",
    description="Privacy checkpoint sitting between users and external AI tools.",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for session jobs (emulating DynamoDB job table)
JOBS: Dict[str, Dict[str, Any]] = {}
GOV = Governor()
MAX_CHARS = 200_000


# Pydantic Schemas
class ScanRequest(BaseModel):
    text: str = Field(..., description="Plain text to scan")
    job_id: Optional[str] = Field(None, description="Optional custom job identifier")


class RedactRequest(BaseModel):
    job_id: str = Field(..., description="Job identifier")
    approved_types: Optional[List[str]] = Field(None, description="Entity types approved for redaction")
    override_high: bool = Field(False, description="Explicit approval override for high-risk entities")


class EntityFinding(BaseModel):
    id: int
    type: str
    start: int
    end: int
    confidence: float
    value_hash: str
    detector: str


class ScanResponse(BaseModel):
    job_id: str
    risk: str
    entity_count: int
    entities: List[EntityFinding]


class RedactResponse(BaseModel):
    job_id: str
    decision: str
    residual: int
    rounds: int
    sanitized: Optional[str]


class ReportResponse(BaseModel):
    job_id: str
    status: str
    risk: str
    entity_counts: Dict[str, int]
    ledger_valid: bool
    chain_length: int


class LedgerBlockResponse(BaseModel):
    index: int
    timestamp: float
    stage: str
    job_id: str
    status: str
    pre_hash: Optional[str]
    post_hash: Optional[str]
    meta: Dict[str, Any]
    prev_hash: str
    hash: str


class LedgerResponse(BaseModel):
    is_valid: bool
    blocks: List[LedgerBlockResponse]


@app.post("/api/scan", response_model=ScanResponse)
def api_scan(req: ScanRequest):
    """Scan raw text, detect sensitive entities, and return findings without raw sensitive values."""
    text = req.text
    if not text or not text.strip():
        raise HTTPException(status_code=400, detail="Text must be a non-empty string")
    if len(text) > MAX_CHARS:
        raise HTTPException(status_code=413, detail="Document exceeds maximum character limit")

    job_id = req.job_id or uuid.uuid4().hex[:12]
    # Use governor's detector
    work = text
    entities = GOV.detector.detect(work)
    risk = rubric_label([e.type for e in entities])

    # Record scan step in the audit ledger without exposing sensitive raw values
    pre = sha256_hex(work)
    GOV.ledger.record("SCAN", job_id, "OK", pre_hash=pre, meta={"entities": len(entities), "risk": risk})

    JOBS[job_id] = {
        "text": work,
        "entities": entities,
        "status": "REVIEW",
        "risk": risk
    }

    # Return sanitized entity descriptors only (spans, types, confidence, truncated value hash)
    findings = [
        EntityFinding(
            id=i,
            type=e.type,
            start=e.start,
            end=e.end,
            confidence=round(e.confidence, 3),
            value_hash=sha256_hex(e.value)[:16],
            detector=e.detector
        )
        for i, e in enumerate(entities)
    ]

    return ScanResponse(
        job_id=job_id,
        risk=risk,
        entity_count=len(entities),
        entities=findings
    )


@app.post("/api/upload", response_model=ScanResponse)
async def api_upload(file: UploadFile = File(...), job_id: Optional[str] = None):
    """Extract text from TXT, PDF, or DOCX and run scan."""
    filename = file.filename or "upload.txt"
    contents = await file.read()
    try:
        text = extract_text_from_bytes(contents, filename)
    except DocumentExtractionError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to process document: {str(e)}")

    req = ScanRequest(text=text, job_id=job_id)
    return api_scan(req)


@app.post("/api/redact", response_model=RedactResponse)
def api_redact(req: RedactRequest):
    """Apply approved redactions, rescan with strict validator, and output the governor decision."""
    job = JOBS.get(req.job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Unknown job ID")

    approved_set = set(req.approved_types) if req.approved_types is not None else None
    res = GOV.process(
        job["text"],
        req.job_id,
        approved_types=approved_set,
        override_high=req.override_high
    )

    job["status"] = res.decision.value
    job["sanitized"] = res.sanitized

    return RedactResponse(
        job_id=req.job_id,
        decision=res.decision.value,
        residual=res.residual,
        rounds=res.rounds,
        sanitized=res.sanitized
    )


@app.get("/api/report/{job_id}", response_model=ReportResponse)
def api_report(job_id: str):
    """Fetch privacy report for a specific job."""
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Unknown job ID")

    counts: Dict[str, int] = {}
    for e in job.get("entities", []):
        counts[e.type] = counts.get(e.type, 0) + 1

    return ReportResponse(
        job_id=job_id,
        status=job.get("status", "UNKNOWN"),
        risk=job.get("risk", "LOW"),
        entity_counts=counts,
        ledger_valid=GOV.ledger.verify(),
        chain_length=len(GOV.ledger.chain)
    )


@app.get("/api/ledger", response_model=LedgerResponse)
def api_ledger():
    """Retrieve full audit ledger blocks and verify chain integrity."""
    is_valid = GOV.ledger.verify()
    blocks = [
        LedgerBlockResponse(
            index=b.index,
            timestamp=b.timestamp,
            stage=b.stage,
            job_id=b.job_id,
            status=b.status,
            pre_hash=b.pre_hash,
            post_hash=b.post_hash,
            meta=b.meta,
            prev_hash=b.prev_hash,
            hash=b.hash
        )
        for b in GOV.ledger.chain
    ]
    return LedgerResponse(is_valid=is_valid, blocks=blocks)


# Mount static web directory
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def serve_index():
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))
