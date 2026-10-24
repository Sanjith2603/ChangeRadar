const $ = (id) => document.getElementById(id);
let currentReportId = null;
const sampleDiff = `diff --git a/app.py b/app.py
index 1234567..abcdef0 100644
--- a/app.py
+++ b/app.py
@@ -1,7 +1,13 @@
 import os
+import subprocess
+import sqlite3

-DEBUG = False
+DEBUG = True
+API_KEY = "sk_test_123456789abcdef"

 def get_user(user_id):
-    query = "SELECT * FROM users WHERE id = ?"
-    return db.execute(query, (user_id,))
+    query = f"SELECT * FROM users WHERE id = {user_id}"
+    return db.execute(query)
+
+def run_task(command):
+    return subprocess.run(command, shell=True)
+
+def calculate(value):
+    try:
+        return eval(value)
+    except Exception:
+        return None
`;
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}
function showToast(message) {
  const toast = $("toast"); toast.textContent = message; toast.classList.add("show");
  clearTimeout(showToast.timer); showToast.timer = setTimeout(() => toast.classList.remove("show"), 3000);
}
function setView(view) {
  $("analyze-view").classList.toggle("hidden", view !== "analyze");
  $("history-view").classList.toggle("hidden", view !== "history");
  document.querySelectorAll(".nav-item").forEach(btn => btn.classList.toggle("active", btn.dataset.view === view));
  $("crumb").textContent = view === "analyze" ? "New analysis" : "Report history";
  if (view === "history") loadHistory();
}
document.querySelectorAll(".nav-item").forEach(btn => btn.addEventListener("click", () => setView(btn.dataset.view)));
$("sample-btn").addEventListener("click", () => { $("diff-input").value = sampleDiff; updateCount(); showToast("Sample diff loaded. Run the analysis."); });
$("clear-btn").addEventListener("click", () => { $("diff-input").value = ""; $("diff-file").value = ""; updateCount(); });
$("new-analysis-btn").addEventListener("click", () => { $("results-section").classList.add("hidden"); window.scrollTo({top:0,behavior:"smooth"}); });
$("history-new-btn").addEventListener("click", () => setView("analyze"));
$("refresh-history").addEventListener("click", loadHistory);
$("diff-input").addEventListener("input", updateCount);
$("diff-file").addEventListener("change", async (event) => {
  const file = event.target.files[0]; if (!file) return;
  if (file.size > 1024 * 1024) { showToast("File is too large (max 1 MB)."); event.target.value = ""; return; }
  try { $("diff-input").value = await file.text(); updateCount(); showToast(`Loaded ${file.name}`); }
  catch { showToast("Could not read this file."); }
});
function updateCount() { $("input-count").textContent = `${$("diff-input").value.length.toLocaleString()} characters`; }
async function checkHealth() {
  try {
    const r = await fetch("/api/health"); const d = await r.json();
    $("engine-status").textContent = d.ai_configured ? "Rules + Gemini connected" : "Rules active · AI key missing";
  } catch { $("engine-status").textContent = "Local service"; }
}
function renderFinding(f) {
  const severity = String(f.severity || "Low").toLowerCase();
  return `<article class="finding"><div class="finding-top"><span class="severity ${escapeHtml(severity)}">${escapeHtml(f.severity || "Low")}</span><h3>${escapeHtml(f.title)}</h3></div><p>${escapeHtml(f.explanation || "")}</p>${f.evidence ? `<div class="evidence">${escapeHtml(f.evidence)}</div>` : ""}<div class="finding-file">${escapeHtml(f.file || "unknown file")}</div></article>`;
}
function renderAI(report) {
  const root = $("ai-content");
  if (report.ai_status !== "success") {
    const message = report.ai_status === "missing_api_key" ? "Add GEMINI_API_KEY to your .env file and restart the server to enable AI review." : report.ai_status === "timeout" ? "Gemini took too long to respond. The deterministic analysis was saved successfully." : "AI review was unavailable. Your rule-based findings are still saved and usable.";
    root.innerHTML = `<div class="empty-ai"><span>✳</span><strong>Rule-based analysis is ready</strong><p>${escapeHtml(message)}</p></div>`;
    return;
  }
  let html = `<div class="ai-summary">${escapeHtml(report.ai_summary || "AI review completed.")}</div>`;
  const findings = report.ai_findings || [];
  if (findings.length) html += findings.map(f => `<div class="ai-finding"><h3>${escapeHtml(f.title)} <span class="severity ${(f.severity||"info").toLowerCase()}">${escapeHtml(f.severity||"Info")}</span></h3><p>${escapeHtml(f.explanation||"")}</p>${f.evidence ? `<p><b>Evidence:</b> <code>${escapeHtml(f.evidence)}</code></p>` : ""}${f.recommendation ? `<p><b>Recommendation:</b> ${escapeHtml(f.recommendation)}</p>` : ""}<p class="finding-file">${escapeHtml(f.file||"unknown")}</p></div>`).join("");
  else html += `<div class="empty-state">No additional AI findings returned. Review the summary and deterministic findings.</div>`;
  if ((report.tests_to_add || []).length) html += `<div class="tests-box"><strong>Suggested tests</strong><ul>${report.tests_to_add.map(t => `<li>${escapeHtml(t)}</li>`).join("")}</ul></div>`;
  root.innerHTML = html;
}
function renderReport(report) {
  currentReportId = report.id;
  $("metric-files").textContent = report.changed_files;
  $("metric-added").textContent = report.added_lines;
  $("metric-removed").textContent = report.removed_lines;
  $("risk-score").textContent = report.risk_score;
  $("risk-fill").style.width = `${report.risk_score}%`;
  const badge = $("risk-badge"); badge.textContent = `${report.risk_level.toUpperCase()} RISK`; badge.className = `risk-badge ${report.risk_level.toLowerCase()}`;
  $("result-title").textContent = report.title;
  $("result-summary").textContent = report.summary;
  $("finding-count").textContent = `${(report.findings || []).length} finding${(report.findings || []).length === 1 ? "" : "s"}`;
  $("findings-list").innerHTML = (report.findings || []).length ? report.findings.map(renderFinding).join("") : `<div class="empty-state">No current rules matched the added lines.<br>This is not a guarantee that the code is safe.</div>`;
  renderAI(report);
  $("results-section").classList.remove("hidden");
  $("results-section").scrollIntoView({behavior:"smooth", block:"start"});
}
$("analyze-btn").addEventListener("click", async () => {
  const diff = $("diff-input").value.trim();
  if (!diff) { showToast("Paste a diff or load the sample first."); return; }
  const form = new FormData();
  form.append("diff_text", diff);
  form.append("title", $("analysis-title").value.trim());
  const btn = $("analyze-btn"); btn.classList.add("loading"); btn.querySelector("span").textContent = "Analyzing changes…";
  try {
    const response = await fetch("/api/analyze", {method:"POST", body:form});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Analysis failed");
    renderReport(data); showToast(data.ai_status === "success" ? "Analysis and AI review saved." : "Analysis saved. AI review unavailable.");
  } catch (err) { showToast(err.message || "Could not analyze this diff."); }
  finally { btn.classList.remove("loading"); btn.querySelector("span").textContent = "Analyze changes"; }
});
function formatDate(value) {
  try { return new Date(value).toLocaleString([], {month:"short", day:"numeric", hour:"2-digit", minute:"2-digit"}); } catch { return value; }
}
async function loadHistory() {
  const root = $("history-list"); root.innerHTML = `<div class="empty-state">Loading reports…</div>`;
  try {
    const response = await fetch("/api/reports"); const reports = await response.json();
    if (!reports.length) { root.innerHTML = `<div class="empty-state">No saved reports yet.<br>Run your first analysis to see it here.</div>`; return; }
    root.innerHTML = reports.map(r => `<div class="history-row"><div><span class="history-title">${escapeHtml(r.title)}</span><span class="history-meta">${r.changed_files} files · ${r.findings.length} rule findings · ${r.ai_status === "success" ? "AI reviewed" : "Rule-based review"}</span></div><div><span class="severity ${r.risk_level.toLowerCase()}">${escapeHtml(r.risk_level)}</span></div><div class="history-date"><span class="history-meta">${escapeHtml(formatDate(r.created_at))}</span></div><div class="history-actions"><button class="small-btn" data-open="${r.id}">Open</button><button class="small-btn delete" data-delete="${r.id}" title="Delete report">×</button></div></div>`).join("");
    root.querySelectorAll("[data-open]").forEach(btn => btn.addEventListener("click", () => openReport(btn.dataset.open)));
    root.querySelectorAll("[data-delete]").forEach(btn => btn.addEventListener("click", () => deleteReport(btn.dataset.delete)));
  } catch { root.innerHTML = `<div class="empty-state">Could not load report history. Is the server running?</div>`; }
}
async function openReport(id) {
  try {
    const response = await fetch(`/api/reports/${id}`); const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not open report");
    $("diff-input").value = data.diff_text || ""; $("analysis-title").value = data.title || ""; updateCount();
    setView("analyze"); renderReport(data); showToast("Saved report opened.");
  } catch (err) { showToast(err.message); }
}
async function deleteReport(id) {
  if (!confirm("Delete this saved report?")) return;
  try {
    const response = await fetch(`/api/reports/${id}`, {method:"DELETE"});
    if (!response.ok) throw new Error("Could not delete report");
    showToast("Report deleted."); loadHistory();
  } catch (err) { showToast(err.message); }
}
checkHealth();
