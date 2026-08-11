//  ANTI PHISHING WEB EXTENSION
//  popup.js
//  Retrieves analysis from content.js and
//  renders the results UI.

const root = document.getElementById("root");
const refreshBtn = document.getElementById("refreshBtn");
const footerURL  = document.getElementById("footer-url");
const footerTime = document.getElementById("footer-time");

let activeTab = "findings"; // "findings" | "url" | "forms"

// fetch result from content script

async function getAnalysis(forceRefresh = false) {
  root.innerHTML = `
    <div class="loading">
      <div class="spinner"></div>
      <p>${forceRefresh ? "Re-scanning page…" : "Analyzing page…"}</p>
    </div>`;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) { showError("Could not access current tab."); return; }

  // update footer
  footerURL.textContent = tab.url || "";
  footerTime.textContent = new Date().toLocaleTimeString();

  // Restrict to http/https
  if (!tab.url || (!tab.url.startsWith("http://") && !tab.url.startsWith("https://"))) {
    showError("Extension only works on regular web pages (http/https).");
    return;
  }

  try {
    let result;

    if (forceRefresh) {
      // Re-run analysis by messaging the content script
      const response = await chrome.tabs.sendMessage(tab.id, { type: "EXTENSION_ANALYZE" });
      result = response;
    } else {
      // Read the cached result stored on window.__extensionResult
      const injected = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => window.__extensionResult
      });
      result = injected?.[0]?.result;
    }

    if (!result) throw new Error("No result returned from content script.");
    render(result);
  } catch (err) {
    console.error("Extension error:", err);
    // content script may not have loaded yet
    try {
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
      const injected = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => window.__extensionResult
      });
      const result = injected?.[0]?.result;
      if (result) { render(result); return; }
    } catch {}
    showError("Could not analyze this page.<br>Try refreshing the page and clicking Scan again.");
  }
}

// render results

function render(data) {
  const { verdict, overallScore, urlAnalysis, formAnalysis, contentAnalysis, allFindings } = data;

  const verdictClass = verdict.toLowerCase(); // "safe" | "suspicious" | "dangerous"
  const verdictEmoji = verdictClass === "safe" ? "✅" : verdictClass === "suspicious" ? "⚠️" : "🚨";
  const verdictSub = verdictClass === "safe"
    ? "No significant threats detected"
    : verdictClass === "suspicious"
    ? "Some indicators found — proceed carefully"
    : "High-risk page — do not enter credentials";

  const domainInfo = urlAnalysis?.domainInfo || {};

  const allIssues = allFindings.filter(f => f.severity);
  const highCount = allIssues.filter(f => f.severity === "high").length;
  const medCount  = allIssues.filter(f => f.severity === "medium").length;
  const lowCount  = allIssues.filter(f => f.severity === "low").length;

  root.innerHTML = `
    <!-- Verdict Banner -->
    <div class="verdict-banner ${verdictClass}">
      <div class="verdict-icon">${verdictEmoji}</div>
      <div>
        <div class="verdict-label">${verdict}</div>
        <div class="verdict-sub">${verdictSub}</div>
        <div class="verdict-sub" style="margin-top:4px">
          ${highCount > 0 ? `<span style="color:var(--danger)">${highCount} high</span>&ensp;` : ""}
          ${medCount  > 0 ? `<span style="color:var(--warn)">${medCount} medium</span>&ensp;` : ""}
          ${lowCount  > 0 ? `<span style="color:var(--low)">${lowCount} low</span>` : ""}
          ${allIssues.length === 0 ? '<span style="color:var(--safe)">No issues</span>' : ""}
        </div>
      </div>
      <div class="score-ring">${overallScore}</div>
    </div>

    <!-- Domain Info Bar -->
    <div class="domain-bar">
      <div class="row">
        <span class="key">Domain</span>
        <span class="val">${domainInfo.rootDomain || "—"}</span>
      </div>
      <div class="row">
        <span class="key">Subdomain</span>
        <span class="val">${domainInfo.subdomain || "(none)"}</span>
      </div>
      <div class="row">
        <span class="key">Protocol</span>
        <span class="val">${new URL(data.url).protocol.replace(":","").toUpperCase()}</span>
      </div>
      <div class="row">
        <span class="key">Trust status</span>
        <span class="val">${domainInfo.isTrusted
          ? '<span class="trusted-badge">✓ Trusted domain</span>'
          : '<span class="unknown-badge">? Not in trusted list</span>'
        }</span>
      </div>
    </div>

    <!-- Tabs -->
    <div class="tabs">
      <button class="tab ${activeTab === 'findings' ? 'active' : ''}" data-tab="findings">
        All Findings ${allIssues.length > 0 ? `(${allIssues.length})` : ""}
      </button>
      <button class="tab ${activeTab === 'url' ? 'active' : ''}" data-tab="url">
        URL / Domain
      </button>
      <button class="tab ${activeTab === 'forms' ? 'active' : ''}" data-tab="forms">
        Forms ${formAnalysis.totalLoginForms > 0 ? `(${formAnalysis.totalLoginForms})` : ""}
      </button>
    </div>

    <!-- Panel -->
    <div class="findings-panel" id="panel">
      ${renderPanel(activeTab, data)}
    </div>
  `;

  // Attach tab clicks
  root.querySelectorAll(".tab").forEach(btn => {
    btn.addEventListener("click", () => {
      activeTab = btn.dataset.tab;
      // Update active class
      root.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === activeTab));
      document.getElementById("panel").innerHTML = renderPanel(activeTab, data);
    });
  });
}

// panel renderers

function renderPanel(tab, data) {
  if (tab === "findings") return renderFindings(data.allFindings);
  if (tab === "url")      return renderURLFindings(data.urlAnalysis);
  if (tab === "forms")    return renderForms(data.formAnalysis);
  return "";
}

function renderFindings(findings) {
  const issues = findings.filter(f => f.severity);
  if (issues.length === 0) {
    return `<div class="empty-state">
      <div class="big">✅</div>
      <p>No suspicious indicators found on this page.</p>
    </div>`;
  }
  const order = { high: 0, medium: 1, low: 2 };
  return issues
    .sort((a, b) => (order[a.severity] ?? 3) - (order[b.severity] ?? 3))
    .map(f => `
      <div class="finding-card ${f.severity}">
        <div class="finding-icon">${severityIcon(f.severity)}</div>
        <div class="finding-msg">
          <span class="sev-pill sev-${f.severity}">${f.severity}</span>${escHtml(f.msg)}
        </div>
      </div>
    `).join("");
}

function renderURLFindings(urlAnalysis) {
  const { findings, riskScore, domainInfo } = urlAnalysis;
  const issues = findings.filter(f => f.severity);

  return `
    <div class="form-card">
      <h3>URL Risk Score: ${riskScore}/100</h3>
      <div class="form-row"><span class="fk">Full hostname</span><span class="fv">${escHtml(domainInfo?.hostname || "—")}</span></div>
      <div class="form-row"><span class="fk">Root domain</span><span class="fv">${escHtml(domainInfo?.rootDomain || "—")}</span></div>
      <div class="form-row"><span class="fk">Subdomain</span><span class="fv">${escHtml(domainInfo?.subdomain || "(none)")}</span></div>
    </div>
    ${issues.length === 0
      ? `<div class="empty-state"><div class="big">🌐</div><p>No URL-level issues found.</p></div>`
      : issues.map(f => `
        <div class="finding-card ${f.severity}">
          <div class="finding-icon">${severityIcon(f.severity)}</div>
          <div class="finding-msg">
            <span class="sev-pill sev-${f.severity}">${f.severity}</span>${escHtml(f.msg)}
          </div>
        </div>`).join("")
    }
  `;
}

function renderForms(formAnalysis) {
  const { formSummaries, totalLoginForms, riskScore } = formAnalysis;

  if (totalLoginForms === 0) {
    return `<div class="empty-state">
      <div class="big">📋</div>
      <p>No login/credential forms detected on this page.</p>
    </div>`;
  }

  const formCards = formSummaries.map(f => `
    <div class="form-card">
      <h3>Login Form #${f.index}</h3>
      <div class="form-row"><span class="fk">Method</span><span class="fv">${escHtml(f.method)}</span></div>
      <div class="form-row"><span class="fk">Action (raw)</span><span class="fv">${escHtml(f.action)}</span></div>
      ${f.actionResolved ? `<div class="form-row"><span class="fk">Submits to</span><span class="fv">${escHtml(f.actionResolved)}</span></div>` : ""}
      ${f.issues.length > 0 ? `
        <div class="form-issues">
          ${f.issues.map(i => `<span class="issue-tag">⚠ ${escHtml(i)}</span>`).join("")}
        </div>` : ""}
    </div>
  `).join("");

  const formFindings = formAnalysis.findings.filter(f => f.severity);

  return `
    <div class="form-card" style="border-color:var(--accent)">
      <h3>Form Risk Score: ${riskScore}/100</h3>
      <div class="form-row"><span class="fk">Login forms found</span><span class="fv">${totalLoginForms}</span></div>
    </div>
    ${formCards}
    ${formFindings.map(f => `
      <div class="finding-card ${f.severity}">
        <div class="finding-icon">${severityIcon(f.severity)}</div>
        <div class="finding-msg">
          <span class="sev-pill sev-${f.severity}">${f.severity}</span>${escHtml(f.msg)}
        </div>
      </div>`).join("")}
  `;
}

// helpers

function severityIcon(sev) {
  return sev === "high" ? "🔴" : sev === "medium" ? "🟡" : "🔵";
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function showError(msg) {
  root.innerHTML = `<div class="error-state">
    <div class="big">⚠️</div>
    <p>${msg}</p>
  </div>`;
}

// boot

refreshBtn.addEventListener("click", () => getAnalysis(true));
getAnalysis(false);
