# AI Shield: Intelligent Data Privacy & Leak Prevention System

**B.Tech Final Year Project**  
- **Student:** Rindhiya A (Register No: 23UAI091)  
- **Guide:** Ms. M. Subashini  
- **Department:** Artificial Intelligence & Data Science  

---

## 1. Executive Summary
AI Shield acts as an intelligent privacy gateway sitting directly between end-users and external AI/LLM tools (e.g., ChatGPT, Claude, Anthropic, Bedrock).
It normalises documents, detects sensitive PII/SPI entities using a multi-strategy engine (regular expressions, Verhoeff checksums, and context cues), provides users with granular approval controls, and rescans the redacted text with a strict validator before releasing it.
Every scan, redaction, rescan, and decision event is permanently recorded in a SHA-256 tamper-evident hash-chained audit ledger. To guarantee strict privacy hygiene, neither logs, API payloads, nor the ledger ever contain raw sensitive values.

---

## 2. System Architecture & Decisions

### Four Governor Decisions:
1. **ALLOW**: No sensitive data found or needed; text is released without modification.
2. **REDACT**: Sensitive data identified and replaced with category tags (e.g., `[PERSON]`, `[EMAIL]`); passed strict rescan.
3. **BLOCK**: Residual sensitive entities detected after redaction rounds; release is halted.
4. **REQUEST_APPROVAL**: User chose to unredact high-risk entities (`STUDENT_ID`, `ID_NUMBER`, `ADDRESS`); requires explicit administrative override.

### Entity Types Supported:
- `PERSON`
- `EMAIL`
- `PHONE`
- `STUDENT_ID`
- `ID_NUMBER` (Aadhaar with Verhoeff check, PAN)
- `ADDRESS` (Pin-code bounded window)
- `DATE_OF_BIRTH`

---

## 3. Repository Structure

```text
aishield_prototype_source/
├── aishield/               # Core Python package
│   ├── app.py             # FastAPI backend application
│   ├── detector.py        # Entity detection (Regex, Verhoeff checksums, Gazetteer, Cues)
│   ├── etl.py             # PySpark / AWS Glue data processing pipeline
│   ├── extract.py         # Multi-format document parser (TXT, PDF, DOCX)
│   ├── governor.py        # Central decision orchestrator
│   ├── handlers.py        # AWS Lambda proxy integration handlers
│   ├── ledger.py          # SHA-256 tamper-evident hash-chained audit ledger
│   ├── normalize.py       # Unicode NFKC normalization and zero-width cleaner
│   ├── rag.py             # RAG guideline retriever, prompt builder, safety gate
│   ├── redactor.py        # Span replacement engine (right-to-left)
│   ├── risk.py            # Risk classification rubric & Random Forest model
│   ├── validator.py       # Strict rescan validator for obfuscated/residual leaks
│   └── web/               # Web Application Frontend (HTML5, Modern CSS, Vanilla JS)
│       ├── index.html
│       ├── style.css
│       └── app.js
├── bench/                 # Benchmark corpus & evaluation
│   ├── gen.py             # Synthetic dataset generator (Zero real personal data)
│   ├── run_bench.py       # 200-document test benchmark
│   ├── run_etl.py         # Local PySpark ETL runner
│   └── results.json       # Benchmark metrics
├── deploy/                # AWS Serverless Platform definitions
│   ├── lambda_policy.json # Least-privilege IAM policies
│   └── state_machine.json # Step Functions state machine with pause tokens
├── docs/                  # Documentation & Project Evidence
│   ├── evidence/          # Playwright captured screenshot evidence
│   └── results.md         # Final verification checklist & measured numbers
├── tests/                 # Comprehensive test suite
│   ├── test_aishield.py   # Baseline engine tests (28 tests)
│   ├── test_web_api.py    # FastAPI endpoints, extraction, and privacy tests (18 tests)
│   └── test_ui_playwright.py # Playwright UI end-to-end integration tests (1 test)
├── demo.py                # Console demo script
└── requirements.txt       # Python dependencies
```

---

## 4. Getting Started

### Prerequisites
- Python 3.10+
- pip

### Installation
```bash
pip install -r requirements.txt
python -m playwright install chromium
```

### Running Tests
Execute the comprehensive test suite (47 passed tests):
```bash
python -m pytest tests -v
```

### Running the Web Application
Start the FastAPI server:
```bash
python -m uvicorn aishield.app:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser at `http://127.0.0.1:8000` to access the AI Shield Web Console.

### Running the Console Demo
```bash
python demo.py
```
