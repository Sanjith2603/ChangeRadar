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
    return String(value ?? "").replace(/[&<>"']/g, ch => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[ch]);
}

function showToast(message) {
    const toast = $("toast");

    if (!toast) {
        console.log(message);
        return;
    }

    toast.textContent = message;
    toast.classList.add("show");

    clearTimeout(showToast.timer);

    showToast.timer = setTimeout(() => {
        toast.classList.remove("show");
    }, 3500);
}

async function apiRequest(url, options = {}) {
    const response = await fetch(url, options);

    let data;

    try {
        data = await response.json();
    } catch {
        throw new Error("The server returned an invalid response.");
    }

    if (!response.ok) {
        throw new Error(data.error || `Request failed: ${response.status}`);
    }

    return data;
}

/* ---------------- VIEW NAVIGATION ---------------- */

function setView(view) {
    const analyzeView = $("analyze-view");
    const historyView = $("history-view");

    if (analyzeView) {
        analyzeView.classList.toggle("hidden", view !== "analyze");
    }

    if (historyView) {
        historyView.classList.toggle("hidden", view !== "history");
    }

    document.querySelectorAll(".nav-item").forEach(button => {
        button.classList.toggle("active", button.dataset.view === view);
    });

    const crumb = $("crumb");

    if (crumb) {
        crumb.textContent =
            view === "analyze" ? "New analysis" : "Report history";
    }

    if (view === "history") {
        loadHistory();
    }

    window.scrollTo({ top: 0, behavior: "smooth" });
}

document.querySelectorAll(".nav-item").forEach(button => {
    button.addEventListener("click", () => {
        setView(button.dataset.view);
    });
});

/* ---------------- INPUT CONTROLS ---------------- */

if ($("sample-btn")) {
    $("sample-btn").addEventListener("click", () => {
        $("diff-input").value = sampleDiff;
        updateCount();
        showToast("Sample diff loaded. Click Analyze changes.");
    });
}

if ($("clear-btn")) {
    $("clear-btn").addEventListener("click", () => {
        $("diff-input").value = "";

        if ($("diff-file")) {
            $("diff-file").value = "";
        }

        updateCount();
        showToast("Diff cleared.");
    });
}

if ($("diff-input")) {
    $("diff-input").addEventListener("input", updateCount);
}

if ($("diff-file")) {
    $("diff-file").addEventListener("change", async event => {
        const file = event.target.files[0];

        if (!file) return;

        const allowed = [".diff", ".patch", ".txt"];

        const valid = allowed.some(extension =>
            file.name.toLowerCase().endsWith(extension)
        );

        if (!valid) {
            showToast("Choose a .diff, .patch, or .txt file.");
            event.target.value = "";
            return;
        }

        if (file.size > 1024 * 1024) {
            showToast("File is too large. Maximum size is 1 MB.");
            event.target.value = "";
            return;
        }

        try {
            $("diff-input").value = await file.text();
            updateCount();
            showToast(`Loaded ${file.name}.`);
        } catch {
            showToast("Could not read the selected file.");
        }
    });
}

function updateCount() {
    const input = $("diff-input");
    const counter = $("input-count");

    if (input && counter) {
        counter.textContent =
            `${input.value.length.toLocaleString()} characters`;
    }
}

/* ---------------- HEALTH STATUS ---------------- */

async function checkHealth() {
    try {
        const data = await apiRequest("/api/health");

        if ($("engine-status")) {
            $("engine-status").textContent = data.ai_configured
                ? "Rules + Gemini connected"
                : "Rules active · AI key missing";
        }
    } catch {
        if ($("engine-status")) {
            $("engine-status").textContent = "Local service";
        }
    }
}

/* ---------------- FINDINGS RENDERING ---------------- */

function renderFinding(finding) {
    const severity = String(
        finding.severity || "Low"
    ).toLowerCase();

    return `
        <article class="finding">
            <div class="finding-top">
                <span class="severity ${escapeHtml(severity)}">
                    ${escapeHtml(finding.severity || "Low")}
                </span>

                <h3>
                    ${escapeHtml(finding.title || "Review finding")}
                </h3>
            </div>

            <p>${escapeHtml(finding.explanation || "")}</p>

            ${
                finding.evidence
                    ? `<div class="evidence">${escapeHtml(finding.evidence)}</div>`
                    : ""
            }

            ${
                finding.recommendation
                    ? `<p><b>Recommendation:</b> ${escapeHtml(finding.recommendation)}</p>`
                    : ""
            }

            <div class="finding-file">
                ${escapeHtml(finding.file || "Unknown file")}
            </div>
        </article>
    `;
}

function renderAI(report) {
    const root = $("ai-content");

    if (!root) return;

    if (report.ai_status !== "success") {
        let message;

        if (report.ai_status === "missing_api_key") {
            message =
                "Add GEMINI_API_KEY to your .env file and restart the server to enable AI review.";
        } else if (report.ai_status === "timeout") {
            message =
                "Gemini took too long to respond. Your rule-based analysis was still saved.";
        } else {
            message =
                "AI review was unavailable. Your rule-based findings are still available.";
        }

        root.innerHTML = `
            <div class="empty-ai">
                <span>✳</span>
                <strong>Rule-based analysis is ready</strong>
                <p>${escapeHtml(message)}</p>
            </div>
        `;

        return;
    }

    let html = `
        <div class="ai-summary">
            ${escapeHtml(report.ai_summary || "AI review completed.")}
        </div>
    `;

    const findings = report.ai_findings || [];

    if (findings.length) {
        html += findings.map(finding => {
            const severity = String(
                finding.severity || "Info"
            ).toLowerCase();

            return `
                <div class="ai-finding">
                    <h3>
                        ${escapeHtml(finding.title || "AI finding")}

                        <span class="severity ${escapeHtml(severity)}">
                            ${escapeHtml(finding.severity || "Info")}
                        </span>
                    </h3>

                    <p>${escapeHtml(finding.explanation || "")}</p>

                    ${
                        finding.evidence
                            ? `<p><b>Evidence:</b> <code>${escapeHtml(finding.evidence)}</code></p>`
                            : ""
                    }

                    ${
                        finding.recommendation
                            ? `<p><b>Recommendation:</b> ${escapeHtml(finding.recommendation)}</p>`
                            : ""
                    }

                    <p class="finding-file">
                        ${escapeHtml(finding.file || "Unknown")}
                    </p>
                </div>
            `;
        }).join("");
    } else {
        html += `
            <div class="empty-state">
                No additional AI findings were returned.
                Review the summary and rule-based findings.
            </div>
        `;
    }

    const tests = report.tests_to_add || [];

    if (tests.length) {
        html += `
            <div class="tests-box">
                <strong>Suggested tests</strong>

                <ul>
                    ${tests.map(test => `<li>${escapeHtml(test)}</li>`).join("")}
                </ul>
            </div>
        `;
    }

    root.innerHTML = html;
}

/* ---------------- DISPLAY ANALYSIS REPORT ---------------- */

function renderReport(report) {
    currentReportId = report.id;

    if ($("metric-files")) {
        $("metric-files").textContent = report.changed_files ?? 0;
    }

    if ($("metric-added")) {
        $("metric-added").textContent = report.added_lines ?? 0;
    }

    if ($("metric-removed")) {
        $("metric-removed").textContent = report.removed_lines ?? 0;
    }

    const score = Number(report.risk_score) || 0;

    if ($("risk-score")) {
        $("risk-score").textContent = score;
    }

    if ($("risk-fill")) {
        $("risk-fill").style.width =
            `${Math.max(0, Math.min(100, score))}%`;
    }

    if ($("risk-badge")) {
        const level = String(
            report.risk_level || "Low"
        ).toLowerCase();

        $("risk-badge").textContent = `${level.toUpperCase()} RISK`;
        $("risk-badge").className = `risk-badge ${level}`;
    }

    if ($("result-title")) {
        $("result-title").textContent =
            report.title || "Review results";
    }

    if ($("result-summary")) {
        $("result-summary").textContent = report.summary || "";
    }

    const findings = Array.isArray(report.findings)
        ? report.findings
        : [];

    if ($("finding-count")) {
        $("finding-count").textContent =
            `${findings.length} finding${findings.length === 1 ? "" : "s"}`;
    }

    if ($("findings-list")) {
        $("findings-list").innerHTML = findings.length
            ? findings.map(renderFinding).join("")
            : `
                <div class="empty-state">
                    No current rules matched the added lines.
                    <br>
                    This does not guarantee that the code is safe.
                </div>
            `;
    }

    renderAI(report);

    const resultsSection = $("results-section");

    if (resultsSection) {
        resultsSection.classList.remove("hidden");

        resultsSection.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    }

    showToast("Analysis results displayed.");
}

/* ---------------- RUN ANALYSIS ---------------- */

if ($("analyze-btn")) {
    $("analyze-btn").addEventListener("click", async () => {
        const diff = $("diff-input")?.value.trim() || "";
        const file = $("diff-file")?.files?.[0];

        if (!diff && !file) {
            showToast(
                "Paste a diff, load a repository comparison, or upload a file."
            );
            return;
        }

        const form = new FormData();

        form.append("diff_text", diff);
        form.append(
            "title",
            $("analysis-title")?.value.trim() || ""
        );

        if (file) {
            form.append("diff_file", file);
        }

        const button = $("analyze-btn");
        const label = button.querySelector("span");

        button.disabled = true;

        if (label) {
            label.textContent = "Analyzing changes…";
        }

        try {
            const report = await apiRequest("/api/analyze", {
                method: "POST",
                body: form
            });

            renderReport(report);

            showToast(
                report.ai_status === "success"
                    ? "Analysis and AI review saved."
                    : "Analysis saved. AI review may be unavailable."
            );

            await loadHistory();
        } catch (error) {
            showToast(
                error.message || "Could not analyze this diff."
            );
        } finally {
            button.disabled = false;

            if (label) {
                label.textContent = "Analyze changes";
            }
        }
    });
}

/* ---------------- UNIFIED SOURCE / BRANCH COMPARISON ---------------- */

function updateSourceFields() {
    const source = $("source-type")?.value || "local";
    const localFields = $("local-source-fields");
    const githubFields = $("github-source-fields");
    const button = $("load-source-btn");

    if (localFields) {
        localFields.classList.toggle("hidden", source !== "local");
    }

    if (githubFields) {
        githubFields.classList.toggle("hidden", source !== "github");
    }

    if (button) {
        const label = button.querySelector("span");

        if (label) {
            label.textContent =
                source === "local"
                    ? "Load Local Git Changes"
                    : source === "github"
                        ? "Load GitHub Changes"
                        : "Use Diff Editor";
        }

        button.classList.toggle("hidden", source === "diff");
    }
}

function getDiffStats(diffText) {
    const files = new Set();
    let added = 0;
    let removed = 0;

    for (const line of String(diffText || "").split(/\r?\n/)) {
        if (line.startsWith("diff --git ")) {
            const match = line.match(/^diff --git a\/(.+) b\/(.+)$/);

            if (match) {
                files.add(match[2]);
            }
        } else if (line.startsWith("+++ ")) {
            const path = line.slice(4).trim();

            if (path !== "/dev/null") {
                files.add(path.startsWith("b/") ? path.slice(2) : path);
            }
        }

        if (line.startsWith("+") && !line.startsWith("+++")) {
            added++;
        } else if (line.startsWith("-") && !line.startsWith("---")) {
            removed++;
        }
    }

    return {
        files: files.size,
        added,
        removed
    };
}

function renderBranchSummary(data, diffText, source) {
    const status = $("git-status");

    const stats = getDiffStats(diffText);
    const repo =
        data.repo_name ||
        data.repo_path ||
        data.repo_url ||
        $("github-url")?.value ||
        $("repo-path")?.value ||
        "Repository";

    const base =
        data.base_branch ||
        (source === "github"
            ? $("github-base-branch")?.value
            : $("base-branch")?.value) ||
        "Base branch";

    const compare =
        data.compare_branch ||
        data.branch ||
        (source === "github"
            ? $("github-compare-branch")?.value
            : $("local-compare-branch")?.value) ||
        "Compare branch";

    const message =
        `${source === "github" ? "GitHub" : "Local Git"} comparison loaded: ` +
        `${base} → ${compare} | ${stats.files} file(s) changed, ` +
        `${stats.added} additions, ${stats.removed} deletions.`;

    /*
     * Support the IDs used by different versions of the dashboard.
     */
    const summaryRoot =
        $("branch-summary-content") ||
        $("branch-comparison-content") ||
        $("git-summary-content");

    const emptyRoot =
        $("branch-summary-empty") ||
        $("branch-comparison-empty");

    const setText = (ids, value) => {
        for (const id of ids) {
            const element = $(id);

            if (element) {
                element.textContent = value;
            }
        }
    };

    setText(["summary-repo", "summary-repository"], repo);
    setText(["summary-base-branch", "summary-base"], base);
    setText(["summary-current-branch", "summary-compare-branch"], compare);
    setText(["summary-files", "summary-changed-files"], stats.files);
    setText(["summary-added", "summary-lines-added"], stats.added);
    setText(["summary-removed", "summary-lines-removed"], stats.removed);
    setText(["summary-message", "branch-summary-message"], message);

    if (emptyRoot) {
        emptyRoot.classList.add("hidden");
    }

    if (summaryRoot) {
        summaryRoot.classList.remove("hidden");
    }

    if (status) {
        status.textContent = message;
    }
}

function clearBranchSummary() {
    const summaryRoot =
        $("branch-summary-content") ||
        $("branch-comparison-content") ||
        $("git-summary-content");

    const emptyRoot =
        $("branch-summary-empty") ||
        $("branch-comparison-empty");

    if (summaryRoot) {
        summaryRoot.classList.add("hidden");
    }

    if (emptyRoot) {
        emptyRoot.classList.remove("hidden");
    }
}

async function loadRepositoryChanges() {
    const source = $("source-type")?.value || "local";

    if (source === "diff") {
        showToast("Paste or upload a diff, then click Analyze changes.");
        return;
    }

    const button = $("load-source-btn");
    const label = button?.querySelector("span");
    const status = $("git-status");

    if (button) {
        button.disabled = true;
    }

    if (label) {
        label.textContent = "Loading changes…";
    }

    if (status) {
        status.textContent = "Loading repository comparison…";
    }

    try {
        let endpoint;
        let payload;

        if (source === "github") {
            const repoUrl = $("github-url")?.value.trim() || "";
            const baseBranch = $("github-base-branch")?.value.trim() || "";
            const compareBranch = $("github-compare-branch")?.value.trim() || "";

            if (!repoUrl || !baseBranch || !compareBranch) {
                throw new Error(
                    "Enter the GitHub URL, base branch, and compare branch."
                );
            }

            endpoint = "/api/github-diff";

            payload = {
                repo_url: repoUrl,
                base_branch: baseBranch,
                compare_branch: compareBranch
            };
        } else {
            const repoPath = $("repo-path")?.value.trim() || "";
            const baseBranch = $("base-branch")?.value.trim() || "";
            const compareBranch =
                $("local-compare-branch")?.value.trim() || "";

            if (!repoPath) {
                throw new Error("Enter the local repository path.");
            }

            if (!baseBranch || !compareBranch) {
                throw new Error(
                    "Enter both the base branch and compare branch."
                );
            }

            endpoint = "/api/git-diff";

            payload = {
                repo_path: repoPath,
                base_branch: baseBranch,
                compare_branch: compareBranch
            };
        }

        const result = await apiRequest(endpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });

        const diffText = result.diff_text || "";

        if (!diffText.trim()) {
            throw new Error(
                "The comparison returned an empty diff. Check the branch names and try again."
            );
        }

        if ($("diff-input")) {
            $("diff-input").value = diffText;
        }

        if ($("diff-file")) {
            $("diff-file").value = "";
        }

        updateCount();

        renderBranchSummary(result, diffText, source);

        if ($("analysis-title") && !$("analysis-title").value.trim()) {
            $("analysis-title").value =
                `${source === "github" ? "GitHub" : "Git"} review: ` +
                `${result.repo_name || "repository"}`;
        }

        if ($("results-section")) {
            $("results-section").classList.add("hidden");
        }

        showToast(
            "Repository changes loaded. Click Analyze changes to review risks."
        );
    } catch (error) {
        if (status) {
            status.textContent = `Error: ${error.message}`;
        }

        showToast(error.message || "Could not load repository changes.");
    } finally {
        if (button) {
            button.disabled = false;
        }

        updateSourceFields();
    }
}

if ($("source-type")) {
    $("source-type").addEventListener("change", () => {
        updateSourceFields();
        clearBranchSummary();
    });
}

if ($("load-source-btn")) {
    $("load-source-btn").addEventListener(
        "click",
        loadRepositoryChanges
    );
}

updateSourceFields();

/* ---------------- REPORT HISTORY ---------------- */

function formatDate(value) {
    try {
        return new Date(value).toLocaleString([], {
            month: "short",
            day: "numeric",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit"
        });
    } catch {
        return value || "";
    }
}

async function loadHistory() {
    const root = $("history-list");

    if (!root) return;

    root.innerHTML = `
        <div class="empty-state">Loading saved reports…</div>
    `;

    try {
        const reports = await apiRequest("/api/reports");

        if (!Array.isArray(reports) || reports.length === 0) {
            root.innerHTML = `
                <div class="empty-state">
                    No saved reports yet.
                    <br>
                    Run your first analysis to see it here.
                </div>
            `;

            return;
        }

        root.innerHTML = reports.map(report => {
            const id = Number(report.id);
            const severity = String(
                report.risk_level || "Low"
            ).toLowerCase();

            const findings = Array.isArray(report.findings)
                ? report.findings.length
                : 0;

            return `
                <div class="history-row">
                    <div>
                        <span class="history-title">
                            ${escapeHtml(report.title || "Untitled report")}
                        </span>

                        <span class="history-meta">
                            ${Number(report.changed_files) || 0} files ·
                            ${findings} rule findings ·
                            ${report.ai_status === "success"
                                ? "AI reviewed"
                                : "Rule-based review"}
                        </span>
                    </div>

                    <div>
                        <span class="severity ${escapeHtml(severity)}">
                            ${escapeHtml(report.risk_level || "Low")}
                        </span>
                    </div>

                    <div class="history-date">
                        <span class="history-meta">
                            ${escapeHtml(formatDate(report.created_at))}
                        </span>
                    </div>

                    <div class="history-actions">
                        <button
                            type="button"
                            class="small-btn"
                            data-open="${id}"
                        >Open</button>

                        <button
                            type="button"
                            class="small-btn delete"
                            data-delete="${id}"
                            title="Delete report"
                        >×</button>
                    </div>
                </div>
            `;
        }).join("");
    } catch (error) {
        root.innerHTML = `
            <div class="empty-state">
                Could not load report history.
                <br>
                ${escapeHtml(error.message)}
            </div>
        `;
    }
}

async function openReport(id) {
    try {
        const report = await apiRequest(`/api/reports/${id}`);

        if ($("diff-input")) {
            $("diff-input").value = report.diff_text || "";
            updateCount();
        }

        if ($("analysis-title")) {
            $("analysis-title").value = report.title || "";
        }

        setView("analyze");
        renderReport(report);

        showToast("Saved report opened.");
    } catch (error) {
        showToast(error.message || "Could not open this report.");
    }
}

async function deleteReport(id) {
    if (!window.confirm("Delete this saved report?")) {
        return;
    }

    try {
        await apiRequest(`/api/reports/${id}`, {
            method: "DELETE"
        });

        showToast("Report deleted.");

        await loadHistory();

        if (Number(currentReportId) === Number(id)) {
            currentReportId = null;

            if ($("results-section")) {
                $("results-section").classList.add("hidden");
            }
        }
    } catch (error) {
        showToast(error.message || "Could not delete this report.");
    }
}

if ($("history-list")) {
    $("history-list").addEventListener("click", event => {
        const openButton = event.target.closest("[data-open]");
        const deleteButton = event.target.closest("[data-delete]");

        if (openButton) {
            openReport(openButton.dataset.open);
        }

        if (deleteButton) {
            deleteReport(deleteButton.dataset.delete);
        }
    });
}

if ($("refresh-history")) {
    $("refresh-history").addEventListener("click", loadHistory);
}

if ($("history-new-btn")) {
    $("history-new-btn").addEventListener("click", () => {
        setView("analyze");
    });
}

if ($("new-analysis-btn")) {
    $("new-analysis-btn").addEventListener("click", () => {
        if ($("results-section")) {
            $("results-section").classList.add("hidden");
        }

        window.scrollTo({ top: 0, behavior: "smooth" });
    });
}

/* ---------------- INITIALIZATION ---------------- */

checkHealth();
updateCount();