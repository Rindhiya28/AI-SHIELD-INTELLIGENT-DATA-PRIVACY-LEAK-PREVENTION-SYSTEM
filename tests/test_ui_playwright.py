"""End-to-end UI tests and screenshot evidence capture using Playwright."""
import os
import subprocess
import time
import pytest
from playwright.sync_api import sync_playwright

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_DIR = os.path.join(ROOT, "docs", "evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)


@pytest.fixture(scope="module")
def live_server():
    """Start uvicorn background process for testing."""
    import uvicorn
    import threading
    from aishield.app import app

    server = None
    config = uvicorn.Config(app, host="127.0.0.1", port=8765, log_level="warning")
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    time.sleep(1.5)  # allow server to start
    yield "http://127.0.0.1:8765"
    server.should_exit = True


def test_ui_full_flow_and_screenshots(live_server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        
        # 1. Open Console
        page.goto(live_server)
        page.wait_for_selector("#view-title")
        assert "Privacy Checkpoint" in page.text_content("#view-title")
        page.screenshot(path=os.path.join(EVIDENCE_DIR, "ui_01_initial_screen.png"))

        # 2. Load Synthetic Sample
        page.click("#btn-load-sample")
        raw_val = page.input_value("#raw-text")
        assert "Rindhiya A" in raw_val
        assert "23UAI091" in raw_val

        # 3. Scan Document
        page.click("#btn-scan")
        page.wait_for_selector("#findings-panel:not(.hidden)", timeout=10000)
        risk_text = page.text_content("#risk-pill")
        assert risk_text == "HIGH"
        page.screenshot(path=os.path.join(EVIDENCE_DIR, "ui_02_findings_and_risk.png"))

        # 4. Redact Entities with Strict Rescan
        page.click("#btn-redact")
        page.wait_for_selector("#output-panel:not(.hidden)", timeout=10000)
        decision_text = page.text_content("#decision-title")
        assert "REDACT" in decision_text
        sanitized_output = page.input_value("#sanitized-text")
        assert "[PERSON]" in sanitized_output
        assert "rindhiya@example.com" not in sanitized_output
        assert "23UAI091" not in sanitized_output
        page.screenshot(path=os.path.join(EVIDENCE_DIR, "ui_03_sanitized_output_decision.png"))

        # 5. Privacy Report Tab
        page.click("#btn-view-report-job")
        page.wait_for_selector("#report-content:not(.hidden)", timeout=5000)
        assert page.text_content("#rep-job-status") == "REDACT"
        page.screenshot(path=os.path.join(EVIDENCE_DIR, "ui_04_privacy_report.png"))

        # 6. Audit Ledger Verification Tab
        page.click("#nav-ledger")
        page.wait_for_selector("#ledger-status-banner")
        assert "VERIFIED" in page.text_content("#ledger-banner-title")
        page.screenshot(path=os.path.join(EVIDENCE_DIR, "ui_05_ledger_verified.png"))

        # 7. Tamper Simulation on Ledger
        page.click("#btn-tamper-ledger")
        time.sleep(0.5)
        assert "TAMPERING DETECTED" in page.text_content("#ledger-banner-title")
        page.screenshot(path=os.path.join(EVIDENCE_DIR, "ui_06_ledger_tampering_detected.png"))

        browser.close()
