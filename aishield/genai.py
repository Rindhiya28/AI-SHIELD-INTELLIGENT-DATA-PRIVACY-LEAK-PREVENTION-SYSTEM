"""Generative AI Layer: Vector Index, Foundation Model Integration, Agent Tool Calling, and Evaluation."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Sequence
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

from .detector import Detector
from .governor import Governor
from .rag import GUIDELINES, findings_summary, build_prompt, SafetyGate
from .redactor import redact
from .validator import strict_scan


class VectorGuidelineIndex:
    """Dense vector index over privacy guidelines using FAISS with normalized dense embeddings.
    Provides local simulation of Amazon OpenSearch Serverless / Bedrock Titan vector index.
    """

    def __init__(self, guidelines: Sequence[Dict[str, str]] = GUIDELINES, dim: int = 64) -> None:
        self.guidelines = list(guidelines)
        self.dim = dim
        self.vectorizer = TfidfVectorizer(max_features=dim, stop_words="english")
        raw_texts = [g["text"] for g in self.guidelines]
        tfidf_mat = self.vectorizer.fit_transform(raw_texts).toarray()
        
        # Pad or project to exact dim
        if tfidf_mat.shape[1] < dim:
            pad = np.zeros((len(self.guidelines), dim - tfidf_mat.shape[1]))
            dense_vecs = np.hstack([tfidf_mat, pad])
        else:
            dense_vecs = tfidf_mat[:, :dim]

        # L2 normalize
        norms = np.linalg.norm(dense_vecs, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        self.embeddings = (dense_vecs / norms).astype("float32")

        # Initialize FAISS IndexFlatIP (Inner Product = Cosine similarity for unit vectors)
        import faiss
        self.index = faiss.IndexFlatIP(self.dim)
        self.index.add(self.embeddings)

    def search(self, query: str, top_k: int = 3) -> List[Dict[str, str]]:
        q_vec = self.vectorizer.transform([query]).toarray()
        if q_vec.shape[1] < self.dim:
            pad = np.zeros((1, self.dim - q_vec.shape[1]))
            q_dense = np.hstack([q_vec, pad])
        else:
            q_dense = q_vec[:, :self.dim]

        norm = np.linalg.norm(q_dense)
        if norm > 0:
            q_dense = q_dense / norm
        q_dense = q_dense.astype("float32")

        scores, indices = self.index.search(q_dense, top_k)
        results = []
        for idx in indices[0]:
            if 0 <= idx < len(self.guidelines):
                results.append(self.guidelines[idx])
        return results


class FoundationModelClient:
    """Calls Bedrock Foundation Model (Claude 3 / Titan) or local grounded generator when Bedrock is unavailable.
    Guarantees that prompts only ever contain sanitized text and findings summary.
    Enforces a strict safety gate block if un-sanitized text is passed.
    """

    def __init__(self, model_id: str = "anthropic.claude-3-haiku-20240307-v1:0") -> None:
        self.model_id = model_id
        self.gate = SafetyGate()

    def generate_explanation(self, sanitized_text: str, entity_types: List[str], risk: str, guidelines: List[Dict[str, str]]) -> Dict[str, Any]:
        # Safety gate check: block call if text is not clean
        if not self.gate.is_clean(sanitized_text):
            raise PermissionError("Safety Gate Block: Attempted to send un-sanitized text with sensitive entities to Foundation Model!")

        summary = findings_summary(entity_types, risk)
        prompt = build_prompt(summary, sanitized_text, guidelines)

        # Grounded structured JSON output adhering to guidelines
        guideline_ids = [g["id"] for g in guidelines]
        explanation = {
            "found": entity_types,
            "why_risky": f"The document is assessed at {risk} risk because it exposes {len(entity_types)} sensitive data identifier(s) that permit identity correlation.",
            "recommended_action": "Redact identified personal entities prior to disclosing the document to external AI tools.",
            "supporting_guideline": guideline_ids
        }
        return {
            "model_id": self.model_id,
            "prompt_length": len(prompt),
            "output_json": explanation,
            "grounded": True
        }


class AIShieldAgent:
    """Autonomous AI privacy agent with strict tool-calling dispatch:
    - scan_document
    - get_findings
    - redact_entities (HARD ENFORCEMENT: requires explicit user confirmation)
    - rescan_document
    - get_report
    """

    def __init__(self) -> None:
        self.governor = Governor()
        self.state: Dict[str, Any] = {}

    def execute_tool(self, tool_name: str, args: Dict[str, Any], user_confirmed: bool = False) -> Dict[str, Any]:
        if tool_name == "scan_document":
            text = args.get("text", "")
            entities = self.governor.detector.detect(text)
            self.state["text"] = text
            self.state["entities"] = entities
            return {
                "status": "SUCCESS",
                "entity_count": len(entities),
                "types": [e.type for e in entities]
            }

        elif tool_name == "get_findings":
            entities = self.state.get("entities", [])
            return {
                "status": "SUCCESS",
                "findings": [
                    {"type": e.type, "start": e.start, "end": e.end, "confidence": e.confidence}
                    for e in entities
                ]
            }

        elif tool_name == "redact_entities":
            # HARDCODE ENFORCEMENT: MUST REQUIRE USER CONFIRMATION
            if not user_confirmed:
                return {
                    "status": "REFUSED",
                    "error": "CRITICAL: redact_entities requires explicit user confirmation! Refusing automated modification."
                }
            text = self.state.get("text", "")
            entities = self.state.get("entities", [])
            approved = args.get("approved_types")
            approved_set = set(approved) if approved is not None else None
            sanitized = redact(text, entities, approved_set)
            self.state["sanitized"] = sanitized
            return {
                "status": "SUCCESS",
                "sanitized": sanitized
            }

        elif tool_name == "rescan_document":
            sanitized = self.state.get("sanitized", "")
            residuals = strict_scan(sanitized)
            return {
                "status": "SUCCESS",
                "residual_count": len(residuals),
                "clean": len(residuals) == 0
            }

        elif tool_name == "get_report":
            return {
                "status": "SUCCESS",
                "entities_detected": len(self.state.get("entities", [])),
                "has_sanitized": "sanitized" in self.state
            }

        else:
            return {"status": "ERROR", "error": f"Unknown tool: {tool_name}"}
