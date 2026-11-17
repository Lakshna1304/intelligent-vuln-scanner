let activeScanId = null;
let currentVulnerabilities = [];
let severityChartInstance = null;
let pollInterval = null;

document.addEventListener("DOMContentLoaded", () => {
  initChart();
  loadScanHistory();

  document.getElementById("validateBtn").addEventListener("click", validateTargetScope);
  document.getElementById("scanForm").addEventListener("submit", startVulnerabilityScan);
  document.getElementById("vulnSearchInput").addEventListener("input", renderVulnerabilityTable);
  document.getElementById("severityFilter").addEventListener("change", renderVulnerabilityTable);
  document.getElementById("typeFilter").addEventListener("change", renderVulnerabilityTable);
  document.getElementById("compareBtn").addEventListener("click", runScanComparison);
  document.getElementById("nessusFileInput").addEventListener("change", uploadNessusXml);
  document.getElementById("downloadPdfBtn").addEventListener("click", () => {
    if (activeScanId) {
      window.location.href = `/api/scans/${activeScanId}/report`;
    }
  });
});

function initChart() {
  const ctx = document.getElementById("severityChart").getContext("2d");
  severityChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Critical", "High", "Medium", "Low", "Informational"],
      datasets: [{
        data: [0, 0, 0, 0, 0],
        backgroundColor: ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#64748b"],
        borderColor: "#111827",
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "right", labels: { color: "#e2e8f0", font: { size: 12 } } }
      }
    }
  });
}

async function validateTargetScope() {
  const target = document.getElementById("targetInput").value;
  const auth = document.getElementById("authConfirm").checked;
  const feedback = document.getElementById("validationFeedback");

  const res = await fetch("/api/validate-target", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, authorization_confirmed: auth })
  });
  const data = await res.json();
  feedback.textContent = data.message;
  feedback.className = data.valid ? "feedback-text feedback-ok" : "feedback-text feedback-err";
}

async function startVulnerabilityScan(e) {
  e.preventDefault();
  const target = document.getElementById("targetInput").value;
  const scanMode = document.getElementById("scanMode").value;
  const assetCriticality = document.getElementById("assetCriticality").value;
  const authConfirm = document.getElementById("authConfirm").checked;
  const useLiveNvd = document.getElementById("liveNvdToggle").checked;
  const feedback = document.getElementById("validationFeedback");

  const startBtn = document.getElementById("startScanBtn");
  startBtn.disabled = true;

  const res = await fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target,
      scan_mode: scanMode,
      asset_criticality: assetCriticality,
      authorization_confirmed: authConfirm,
      use_live_nvd: useLiveNvd
    })
  });

  const data = await res.json();
  if (!res.ok) {
    feedback.textContent = data.error || "Failed to initiate scan.";
    feedback.className = "feedback-text feedback-err";
    startBtn.disabled = false;
    return;
  }

  feedback.textContent = `Scan #${data.scan_id} dispatched for ${data.target}.`;
  feedback.className = "feedback-text feedback-ok";
  pollScanProgress(data.scan_id);
}

function pollScanProgress(scanId) {
  const wrapper = document.getElementById("progressContainer");
  const statusText = document.getElementById("progressStatusText");
  const pctText = document.getElementById("progressPercentText");
  const barFill = document.getElementById("progressBarFill");

  wrapper.classList.remove("hidden");
  if (pollInterval) clearInterval(pollInterval);

  pollInterval = setInterval(async () => {
    const res = await fetch(`/api/scans/${scanId}`);
    const scan = await res.json();

    statusText.textContent = scan.status_message;
    pctText.textContent = `${scan.progress}%`;
    barFill.style.width = `${scan.progress}%`;

    if (scan.status === "completed") {
      clearInterval(pollInterval);
      document.getElementById("startScanBtn").disabled = false;
      renderScanDashboard(scan);
      loadScanHistory();
    } else if (scan.status === "failed") {
      clearInterval(pollInterval);
      document.getElementById("startScanBtn").disabled = false;
      statusText.textContent = `Scan Error: ${scan.error_message}`;
      loadScanHistory();
    }
  }, 900);
}

async function loadScanHistory() {
  const res = await fetch("/api/scans");
  const data = await res.json();
  const scans = data.scans || [];

  const tbody = document.getElementById("historyTableBody");
  const baseSel = document.getElementById("baselineScanSelect");
  const currSel = document.getElementById("currentScanSelect");

  tbody.innerHTML = "";
  baseSel.innerHTML = "";
  currSel.innerHTML = "";

  if (scans.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-cell">No historical scans found.</td></tr>`;
    return;
  }

  scans.forEach((s, idx) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>#${s.id}</td>
      <td>${escapeHtml(s.target)}</td>
      <td>${escapeHtml(s.scan_mode.toUpperCase())}</td>
      <td><strong>${s.overall_risk_score}</strong> (${escapeHtml(s.risk_grade)})</td>
      <td>${s.vuln_count} (${s.critical_count} Crit)</td>
      <td>${new Date(s.started_at).toLocaleString()}</td>
      <td><button class="btn btn-secondary btn-sm" onclick="selectScan(${s.id})">Inspect</button></td>
    `;
    tbody.appendChild(tr);

    if (s.status === "completed") {
      const opt1 = new Option(`Scan #${s.id} (${s.target} - ${s.risk_grade})`, s.id);
      const opt2 = new Option(`Scan #${s.id} (${s.target} - ${s.risk_grade})`, s.id);
      baseSel.add(opt1);
      currSel.add(opt2);
    }

    if (idx === 0 && !activeScanId && s.status === "completed") {
      selectScan(s.id);
    }
  });

  if (baseSel.options.length >= 2) {
    baseSel.selectedIndex = 1;
    currSel.selectedIndex = 0;
  }
}

async function selectScan(scanId) {
  const res = await fetch(`/api/scans/${scanId}`);
  if (!res.ok) return;
  const scan = await res.json();
  renderScanDashboard(scan);
}

function renderScanDashboard(scan) {
  activeScanId = scan.id;
  const summary = scan.attack_surface_summary || {};
  const dist = summary.severity_distribution || {};

  document.getElementById("kpiRiskScore").textContent = `${scan.overall_risk_score} / 10`;
  document.getElementById("kpiRiskGrade").textContent = `Risk Classification: ${scan.risk_grade}`;
  document.getElementById("kpiOpenPorts").textContent = summary.total_open_ports ?? scan.ports.length;
  document.getElementById("kpiHighExposure").textContent = `${summary.high_exposure_ports_count ?? 0} High-Exposure Services`;
  document.getElementById("kpiConfirmedCves").textContent = summary.confirmed_cves_count ?? 0;
  document.getElementById("kpiPotentialRisks").textContent = summary.potential_risks_count ?? 0;

  document.getElementById("metaTarget").textContent = scan.target;
  document.getElementById("metaOs").textContent = `${scan.os_detected} (${scan.os_accuracy}%)`;
  document.getElementById("metaMode").textContent = scan.scan_mode.toUpperCase();
  document.getElementById("metaCriticality").textContent = scan.asset_criticality;
  document.getElementById("metaExposedServices").textContent =
    (summary.high_exposure_services || []).join(", ") || "None";

  document.getElementById("downloadPdfBtn").disabled = scan.status !== "completed";

  severityChartInstance.data.datasets[0].data = [
    dist.Critical || 0,
    dist.High || 0,
    dist.Medium || 0,
    dist.Low || 0,
    dist.Informational || 0
  ];
  severityChartInstance.update();

  const portsBody = document.getElementById("portsTableBody");
  portsBody.innerHTML = "";
  if (!scan.ports || scan.ports.length === 0) {
    portsBody.innerHTML = `<tr><td colspan="4" class="empty-cell">No open ports detected.</td></tr>`;
  } else {
    scan.ports.forEach(p => {
      const sw = `${p.product || ""} ${p.version || ""}`.trim() || "Unidentified";
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${p.port_number}/${p.protocol}</strong></td>
        <td>${escapeHtml(p.service_name)}</td>
        <td>${escapeHtml(sw)}</td>
        <td>${escapeHtml(p.exposure_level)}</td>
      `;
      portsBody.appendChild(tr);
    });
  }

  currentVulnerabilities = scan.vulnerabilities || [];
  renderVulnerabilityTable();
}

function renderVulnerabilityTable() {
  const tbody = document.getElementById("vulnTableBody");
  const query = document.getElementById("vulnSearchInput").value.toLowerCase().trim();
  const sevFilter = document.getElementById("severityFilter").value;
  const typeFilter = document.getElementById("typeFilter").value;

  const filtered = currentVulnerabilities.filter(v => {
    const matchesSev = sevFilter === "ALL" || v.severity === sevFilter;
    const matchesType = typeFilter === "ALL" || v.finding_type === typeFilter;
    const hay = `${v.cve_id} ${v.title} ${v.service_name} ${v.port_number} ${v.affected_software}`.toLowerCase();
    const matchesQuery = !query || hay.includes(query);
    return matchesSev && matchesType && matchesQuery;
  });

  tbody.innerHTML = "";
  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="empty-cell">No vulnerabilities match the current filter criteria.</td></tr>`;
    return;
  }

  filtered.forEach(v => {
    const tr = document.createElement("tr");
    const sevClass = `sev-${v.severity.toLowerCase()}`;
    tr.innerHTML = `
      <td><strong>#${v.priority_rank}</strong></td>
      <td><span class="sev-badge ${sevClass}">${escapeHtml(v.severity)}</span></td>
      <td><strong>${v.priority_score}</strong>/10</td>
      <td><span class="type-badge">${escapeHtml(v.finding_type)}</span></td>
      <td><code>${escapeHtml(v.cve_id)}</code></td>
      <td>${v.port_number || "-"}/${escapeHtml(v.service_name)}</td>
      <td>${escapeHtml(v.title)}</td>
      <td>${v.cvss_score}</td>
      <td><a href="/vulnerability/${v.id}" class="btn btn-secondary btn-sm">Inspect</a></td>
    `;
    tbody.appendChild(tr);
  });
}

async function runScanComparison() {
  const baseId = document.getElementById("baselineScanSelect").value;
  const currId = document.getElementById("currentScanSelect").value;
  const box = document.getElementById("comparisonResultBox");

  if (!baseId || !currId) return;

  const res = await fetch(`/api/scans/compare?baseline=${baseId}&current=${currId}`);
  const diff = await res.json();
  if (!res.ok) {
    box.innerHTML = `<p class="feedback-err">${escapeHtml(diff.error)}</p>`;
    return;
  }

  const newItems = diff.new_vulnerabilities.map(v => `<li><span class="diff-tag-new">[NEW]</span> ${escapeHtml(v.title)} (${escapeHtml(v.cve_id)})</li>`).join("") || "<li>None</li>";
  const resolvedItems = diff.resolved_vulnerabilities.map(v => `<li><span class="diff-tag-resolved">[RESOLVED]</span> ${escapeHtml(v.title)} (${escapeHtml(v.cve_id)})</li>`).join("") || "<li>None</li>";

  box.innerHTML = `
    <p><strong>Risk Score Delta:</strong> ${diff.risk_delta >= 0 ? "+" : ""}${diff.risk_delta} |
       <strong>Persistent Findings:</strong> ${diff.persistent_vulnerabilities.length}</p>
    <p style="margin-top:0.5rem;"><strong>Newly Discovered Vulnerabilities (${diff.new_vulnerabilities.length}):</strong></p>
    <ul style="margin-left:1.2rem; margin-bottom:0.5rem;">${newItems}</ul>
    <p><strong>Resolved / Remediated Vulnerabilities (${diff.resolved_vulnerabilities.length}):</strong></p>
    <ul style="margin-left:1.2rem;">${resolvedItems}</ul>
  `;
}

async function uploadNessusXml(e) {
  const file = e.target.files[0];
  if (!file) return;
  const formData = new FormData();
  formData.append("file", file);
  formData.append("asset_criticality", document.getElementById("assetCriticality").value);

  const res = await fetch("/api/nessus/import-xml", { method: "POST", body: formData });
  const data = await res.json();
  if (res.ok) {
    await loadScanHistory();
    selectScan(data.scan_id);
  } else {
    alert(data.error || "Nessus XML import failed.");
  }
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
