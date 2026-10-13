"""Unit and integration tests for Module 3: Generative AI, Foundation Models & RAG.
Evaluates:
1. FAISS Vector guideline index retrieval
2. Foundation model client safety gate & prompt hygiene (no raw values in prompt)
3. AI Agent tool calling with explicit user confirmation enforcement
4. 30-case evaluation suite measuring groundedness, valid JSON output, and prompt hygiene.
"""
import json
import os
import pytest

from aishield.genai import VectorGuidelineIndex, FoundationModelClient, AIShieldAgent
from aishield.detector import Detector
from aishield.governor import Governor
from aishield.rag import GUIDELINES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_vector_guideline_index_faiss():
    """Verify dense embedding retrieval via FAISS vector index."""
    vindex = VectorGuidelineIndex(GUIDELINES, dim=64)
    results = vindex.search("student roll number and registration id", top_k=3)
    assert len(results) == 3
    ids = [r["id"] for r in results]
    # G04 is the guideline specifically for STUDENT_ID
    assert "G04" in ids or any("student" in r["text"].lower() for r in results)


def test_agent_tool_calling_and_confirmation_enforcement():
    """Verify tool execution and verify redact_entities is strictly blocked without user confirmation."""
    agent = AIShieldAgent()
    sample_text = "Reach Rindhiya A at rindhiya@example.com."
    
    # Tool 1: scan_document
    res1 = agent.execute_tool("scan_document", {"text": sample_text})
    assert res1["status"] == "SUCCESS"
    assert res1["entity_count"] >= 1

    # Tool 2: get_findings
    res2 = agent.execute_tool("get_findings", {})
    assert res2["status"] == "SUCCESS"
    assert len(res2["findings"]) >= 1

    # Tool 3: redact_entities WITHOUT confirmation -> MUST BE REFUSED
    refused = agent.execute_tool("redact_entities", {"approved_types": ["EMAIL", "PERSON"]}, user_confirmed=False)
    assert refused["status"] == "REFUSED"
    assert "confirmation" in refused["error"].lower()

    # Tool 3: redact_entities WITH user confirmation -> MUST SUCCEED
    allowed = agent.execute_tool("redact_entities", {"approved_types": ["EMAIL", "PERSON"]}, user_confirmed=True)
    assert allowed["status"] == "SUCCESS"
    assert "[EMAIL]" in allowed["sanitized"]
    assert "rindhiya@example.com" not in allowed["sanitized"]

    # Tool 4: rescan_document
    res4 = agent.execute_tool("rescan_document", {})
    assert res4["status"] == "SUCCESS"
    assert res4["clean"] is True

    # Tool 5: get_report
    res5 = agent.execute_tool("get_report", {})
    assert res5["status"] == "SUCCESS"


def test_foundation_model_safety_gate_block():
    """Ensure foundation model call is rejected when un-sanitized text is supplied."""
    client = FoundationModelClient()
    dirty_text = "Contact me at user@example.com."
    with pytest.raises(PermissionError) as exc_info:
        client.generate_explanation(dirty_text, ["EMAIL"], "LOW", GUIDELINES[:3])
    assert "Safety Gate Block" in str(exc_info.value)


def test_evaluation_30_test_cases():
    """Run evaluation on 30 test cases to verify:
    - 100% Valid JSON explanations
    - 100% Groundedness
    - 100% Prompt hygiene (0% raw sensitive leakage in prompts)
    """
    from bench.gen import make_corpus
    corpus = make_corpus(30, seed=123)
    gov = Governor()
    client = FoundationModelClient()
    vindex = VectorGuidelineIndex(GUIDELINES, dim=64)

    valid_json_count = 0
    grounded_count = 0
    clean_prompt_count = 0

    for d in corpus:
        res = gov.process(d.text)
        # Even if decision is ALLOW or REDACT, evaluate with sanitized text
        sanitized = res.sanitized or "[REDACTED]"
        entity_types = [e.type for e in res.entities]
        guidelines = vindex.search(" ".join(entity_types) if entity_types else "privacy", top_k=3)

        explanation_result = client.generate_explanation(
            sanitized_text=sanitized,
            entity_types=entity_types,
            risk=res.risk_rule,
            guidelines=guidelines
        )

        out_json = explanation_result["output_json"]
        # Check 1: Valid JSON structure
        assert isinstance(out_json, dict)
        assert "why_risky" in out_json and "supporting_guideline" in out_json
        valid_json_count += 1

        # Check 2: Groundedness
        assert explanation_result["grounded"] is True
        grounded_count += 1

        # Check 3: Zero raw values in prompt
        # Ensure none of the ground truth personal values appear in prompt
        prompt_clean = True
        for t, raw_val in d.pii:
            # Check for non-trivial PII
            if len(raw_val) > 4 and raw_val.lower() in sanitized.lower():
                prompt_clean = False
                break
        if prompt_clean:
            clean_prompt_count += 1

    assert valid_json_count == 30
    assert grounded_count == 30
    assert clean_prompt_count == 30
