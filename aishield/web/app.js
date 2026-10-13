// AI Shield Web Frontend Controller
let currentJobId = null;
let currentFindings = [];
let currentRisk = "LOW";
let isLedgerTamperedLocally = false;

const SAMPLE_TEXT = `My name is Rindhiya A. My email is rindhiya@example.com, and my register number is 23UAI091. Reach me on 98765 43210 or 9 8 7 6 5 4 3 2 1 0. Date of birth: 14/03/2004. Please summarize my project report.`;

const HIGH_TYPES = ["STUDENT_ID", "ID_NUMBER", "ADDRESS"];

document.addEventListener("DOMContentLoaded", () => {
  setupNavigation();
  setupScanHandlers();
  setupRedactHandlers();
  setupLedgerHandlers();
  refreshLedgerStatus();
});

// Navigation Handling
function setupNavigation() {
  document.querySelectorAll(".nav-item").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-item").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
      
      btn.classList.add("active");
      const tabId = btn.getAttribute("data-tab");
      document.getElementById(tabId).classList.add("active");

      if (tabId === "tab-ledger") {
        fetchLedger();
      }
    });
  });

  document.getElementById("btn-view-report-job").addEventListener("click", () => {
    if (currentJobId) {
      document.getElementById("nav-report").click();
      document.getElementById("report-job-id").value = currentJobId;
      loadReport(currentJobId);
    }
  });

  document.getElementById("btn-load-sample").addEventListener("click", () => {
    document.getElementById("raw-text").value = SAMPLE_TEXT;
    document.getElementById("nav-scan").click();
  });
}

// Scan & Upload Handlers
function setupScanHandlers() {
  const scanBtn = document.getElementById("btn-scan");
  const clearBtn = document.getElementById("btn-clear");
  const rawText = document.getElementById("raw-text");
  const dropArea = document.getElementById("drop-area");
  const fileInput = document.getElementById("file-upload");
  const fileNameDisplay = document.getElementById("file-name-display");

  // File Upload Drag & Drop
  ['dragenter', 'dragover'].forEach(eventName => {
    dropArea.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropArea.classList.add('dragover');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropArea.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropArea.classList.remove('dragover');
    }, false);
  });

  dropArea.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length) handleFileUpload(files[0]);
  });

  dropArea.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) handleFileUpload(fileInput.files[0]);
  });

  async function handleFileUpload(file) {
    fileNameDisplay.textContent = `Uploading: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    fileNameDisplay.classList.remove("hidden");

    const formData = new FormData();
    formData.append("file", file);

    scanBtn.disabled = true;
    document.getElementById("scan-spinner").classList.remove("hidden");

    try {
      const res = await fetch("/api/upload", {
        method: "POST",
        body: formData
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Upload failed");
      fileNameDisplay.textContent = `Uploaded & Scanned: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
      displayScanResults(data);
    } catch (err) {
      alert(`Upload Error: ${err.message}`);
    } finally {
      scanBtn.disabled = false;
      document.getElementById("scan-spinner").classList.add("hidden");
    }
  }

  scanBtn.addEventListener("click", async () => {
    const text = rawText.value.trim();
    if (!text) {
      alert("Please enter or upload document text first.");
      return;
    }

    scanBtn.disabled = true;
    document.getElementById("scan-spinner").classList.remove("hidden");

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: jsonPayload({ text: text })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Scan request failed");
      displayScanResults(data);
    } catch (err) {
      alert(`Scan Error: ${err.message}`);
    } finally {
      scanBtn.disabled = false;
      document.getElementById("scan-spinner").classList.add("hidden");
    }
  });

  clearBtn.addEventListener("click", () => {
    rawText.value = "";
    fileInput.value = "";
    fileNameDisplay.classList.add("hidden");
    document.getElementById("findings-panel").classList.add("hidden");
    document.getElementById("output-panel").classList.add("hidden");
  });
}

function displayScanResults(data) {
  currentJobId = data.job_id;
  currentRisk = data.risk;
  currentFindings = data.entities || [];

  const findingsPanel = document.getElementById("findings-panel");
  findingsPanel.classList.remove("hidden");
  document.getElementById("output-panel").classList.add("hidden");

  // Smooth scroll down to the findings panel so user sees results immediately
  findingsPanel.scrollIntoView({ behavior: 'smooth' });

  // Update Risk Pill
  const riskPill = document.getElementById("risk-pill");
  riskPill.textContent = data.risk;
  riskPill.className = `risk-pill risk-${data.risk}`;

  // Build Checkboxes for Entity Categories
  const uniqueTypes = [...new Set(currentFindings.map(e => e.type))];
  const container = document.getElementById("category-checkboxes");
  container.innerHTML = "";

  if (uniqueTypes.length === 0) {
    container.innerHTML = "<p class='helper'>No sensitive entities detected in this document.</p>";
  } else {
    uniqueTypes.forEach(t => {
      const label = document.createElement("label");
      label.className = "cat-check-item";
      label.innerHTML = `
        <input type="checkbox" value="${t}" class="entity-type-cb" checked>
        <span class="entity-tag tag-${t}">${t}</span>
        <span>(${currentFindings.filter(e => e.type === t).length})</span>
      `;
      container.appendChild(label);
    });
  }

  // Populate Table Body
  const tbody = document.getElementById("findings-table-body");
  tbody.innerHTML = "";
  currentFindings.forEach((e, idx) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>#${idx}</td>
      <td><span class="entity-tag tag-${e.type}">${e.type}</span></td>
      <td>[${e.start}, ${e.end})</td>
      <td>${(e.confidence * 100).toFixed(0)}%</td>
      <td>${e.detector}</td>
      <td class="hash-cell">${e.value_hash}…</td>
    `;
    tbody.appendChild(tr);
  });

  setupCheckboxWatchers();
  refreshLedgerStatus();
}

function setupCheckboxWatchers() {
  const checkboxes = document.querySelectorAll(".entity-type-cb");
  const alertBox = document.getElementById("high-risk-alert");
  const selectAllBtn = document.getElementById("btn-select-all");
  const selectNoneBtn = document.getElementById("btn-select-none");

  function evaluateHighRiskKept() {
    const unselected = Array.from(checkboxes).filter(cb => !cb.checked).map(cb => cb.value);
    const keepsHigh = unselected.some(t => HIGH_TYPES.includes(t));
    if (keepsHigh) {
      alertBox.classList.remove("hidden");
    } else {
      alertBox.classList.add("hidden");
    }
  }

  checkboxes.forEach(cb => cb.addEventListener("change", evaluateHighRiskKept));
  selectAllBtn.onclick = () => { checkboxes.forEach(c => c.checked = true); evaluateHighRiskKept(); };
  selectNoneBtn.onclick = () => { checkboxes.forEach(c => c.checked = false); evaluateHighRiskKept(); };
  evaluateHighRiskKept();
}

// Redact & Rescan Handlers
function setupRedactHandlers() {
  const redactBtn = document.getElementById("btn-redact");
  const copyBtn = document.getElementById("btn-copy");
  const downloadBtn = document.getElementById("btn-download");

  redactBtn.addEventListener("click", async () => {
    if (!currentJobId) return;

    const approvedTypes = Array.from(document.querySelectorAll(".entity-type-cb"))
      .filter(cb => cb.checked)
      .map(cb => cb.value);

    const overrideHigh = document.getElementById("override-high-checkbox").checked;

    redactBtn.disabled = true;
    document.getElementById("redact-spinner").classList.remove("hidden");

    try {
      const res = await fetch("/api/redact", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: jsonPayload({
          job_id: currentJobId,
          approved_types: approvedTypes,
          override_high: overrideHigh
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Redaction failed");
      displayRedactionResult(data);
    } catch (err) {
      alert(`Redaction Error: ${err.message}`);
    } finally {
      redactBtn.disabled = false;
      document.getElementById("redact-spinner").classList.add("hidden");
    }
  });

  copyBtn.addEventListener("click", () => {
    const text = document.getElementById("sanitized-text").value;
    navigator.clipboard.writeText(text);
    copyBtn.textContent = "✅ Copied!";
    setTimeout(() => { copyBtn.textContent = "📋 Copy Sanitised Text"; }, 2000);
  });

  downloadBtn.addEventListener("click", () => {
    const text = document.getElementById("sanitized-text").value;
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `aishield_sanitized_${currentJobId}.txt`;
    a.click();
  });
}

function displayRedactionResult(data) {
  const outputPanel = document.getElementById("output-panel");
  outputPanel.classList.remove("hidden");

  // Decision Banner
  const banner = document.getElementById("decision-banner");
  const icon = document.getElementById("decision-icon");
  const title = document.getElementById("decision-title");
  const desc = document.getElementById("decision-desc");

  banner.className = `decision-banner decision-${data.decision}`;
  title.textContent = `GOVERNOR DECISION: ${data.decision}`;

  if (data.decision === "ALLOW") {
    icon.textContent = "✅";
    desc.textContent = "No sensitive entities detected or approved. Text is released without modification.";
  } else if (data.decision === "REDACT") {
    icon.textContent = "🛡️";
    desc.textContent = "Sensitive entities safely redacted and strict rescan passed clean. Sanitised text released.";
  } else if (data.decision === "BLOCK") {
    icon.textContent = "🛑";
    desc.textContent = "Residual sensitive entities detected after redaction rounds. Release blocked to prevent leakage.";
  } else if (data.decision === "REQUEST_APPROVAL") {
    icon.textContent = "⚠️";
    desc.textContent = "High-risk entity was unselected without explicit override. Release held until approval granted.";
  }

  // Stats
  document.getElementById("stat-rounds").textContent = data.rounds;
  document.getElementById("stat-residual").textContent = data.residual;
  document.getElementById("stat-val-status").textContent = data.residual === 0 ? "CLEAN" : "DIRTY";

  // Text
  document.getElementById("sanitized-text").value = data.sanitized || "[RELEASE BLOCKED BY GOVERNOR]";

  refreshLedgerStatus();
}

// Report Handlers
async function loadReport(jobId) {
  if (!jobId) return;
  try {
    const res = await fetch(`/api/report/${jobId}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Report not found");

    const box = document.getElementById("report-content");
    box.classList.remove("hidden");

    document.getElementById("rep-job-status").textContent = data.status;
    document.getElementById("rep-risk-level").textContent = data.risk;
    const total = Object.values(data.entity_counts).reduce((a, b) => a + b, 0);
    document.getElementById("rep-entities-detected").textContent = total;
    document.getElementById("rep-ledger-integrity").textContent = data.ledger_valid ? "VALID ✅" : "COMPROMISED ❌";

    const bars = document.getElementById("rep-dist-bars");
    bars.innerHTML = "";
    Object.entries(data.entity_counts).forEach(([t, count]) => {
      const pct = Math.max(10, Math.min(100, (count / (total || 1)) * 100));
      const row = document.createElement("div");
      row.className = "dist-bar-item";
      row.innerHTML = `
        <span class="dist-label">${t}</span>
        <div class="dist-bar-track">
          <div class="dist-bar-fill" style="width: ${pct}%;"></div>
        </div>
        <span class="dist-count">${count}</span>
      `;
      bars.appendChild(row);
    });
  } catch (err) {
    alert(`Report Fetch Error: ${err.message}`);
  }
}

document.getElementById("btn-load-report").addEventListener("click", () => {
  const jobId = document.getElementById("report-job-id").value.trim();
  loadReport(jobId);
});

// Ledger Handlers
function setupLedgerHandlers() {
  document.getElementById("btn-refresh-ledger").addEventListener("click", fetchLedger);
  
  document.getElementById("btn-tamper-ledger").addEventListener("click", () => {
    isLedgerTamperedLocally = true;
    renderLedgerTamperedState();
  });

  document.getElementById("btn-reset-tamper").addEventListener("click", () => {
    isLedgerTamperedLocally = false;
    fetchLedger();
  });
}

async function refreshLedgerStatus() {
  try {
    const res = await fetch("/api/ledger");
    const data = await res.json();
    const quickStatus = document.getElementById("quick-ledger-status");
    if (data.is_valid && !isLedgerTamperedLocally) {
      quickStatus.innerHTML = `<span class="status-dot valid"></span><span>Ledger: VALID (${data.blocks.length} blocks)</span>`;
    } else {
      quickStatus.innerHTML = `<span class="status-dot invalid"></span><span>Ledger: TAMPERED</span>`;
    }
  } catch (e) {
    // Ignore minor network err
  }
}

async function fetchLedger() {
  try {
    const res = await fetch("/api/ledger");
    const data = await res.json();
    renderLedgerBlocks(data.blocks, data.is_valid && !isLedgerTamperedLocally);
  } catch (err) {
    alert(`Failed to fetch ledger: ${err.message}`);
  }
}

function renderLedgerBlocks(blocks, isValid) {
  const banner = document.getElementById("ledger-status-banner");
  const icon = document.getElementById("ledger-banner-icon");
  const title = document.getElementById("ledger-banner-title");
  const desc = document.getElementById("ledger-banner-desc");

  if (isValid) {
    banner.className = "ledger-status-banner";
    icon.textContent = "✅";
    title.textContent = "CHAIN INTEGRITY: VERIFIED";
    desc.textContent = "All SHA-256 blocks have valid cryptographic hashes linked back to Genesis.";
  } else {
    banner.className = "ledger-status-banner tampered";
    icon.textContent = "❌";
    title.textContent = "CHAIN INTEGRITY: TAMPERING DETECTED";
    desc.textContent = "Block hash mismatch or broken link detected! Ledger security violated.";
  }

  const tbody = document.getElementById("ledger-table-body");
  tbody.innerHTML = "";

  blocks.forEach(b => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>#${b.index}</td>
      <td><strong>${b.stage}</strong></td>
      <td><span class="entity-tag ${b.status === 'OK' || b.status === 'CLEAN' ? 'tag-DATE_OF_BIRTH' : 'tag-STUDENT_ID'}">${b.status}</span></td>
      <td><code>${b.job_id}</code></td>
      <td class="hash-cell">${b.prev_hash.slice(0, 10)}…</td>
      <td class="hash-cell">${b.hash.slice(0, 10)}…</td>
      <td><code>${JSON.stringify(b.meta)}</code></td>
    `;
    tbody.appendChild(tr);
  });

  refreshLedgerStatus();
}

function renderLedgerTamperedState() {
  const tbody = document.getElementById("ledger-table-body");
  const rows = tbody.querySelectorAll("tr");
  if (rows.length > 1) {
    const secondRow = rows[1];
    const statusCell = secondRow.children[2];
    statusCell.innerHTML = `<span class="entity-tag tag-ID_NUMBER">TAMPERED</span>`;
  }
  renderLedgerBlocks([], false);
}

function jsonPayload(obj) {
  return JSON.stringify(obj);
}
