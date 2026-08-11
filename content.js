//  ANTI PHISHING WEB EXTENSION
//  content.js
//  Injected into every page at document_idle.
//  Runs all detection checks and caches results
//  so popup.js can retrieve them instantly.

(() => {

  // trusted Domains
  const TRUSTED_DOMAINS = new Set([
    "google.com", "gmail.com", "youtube.com", "googleapis.com",
    "facebook.com", "instagram.com", "whatsapp.com", "messenger.com",
    "microsoft.com", "live.com", "outlook.com", "office.com", "azure.com",
    "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com",
    "twitter.com", "x.com",
    "linkedin.com",
    "github.com", "gitlab.com",
    "paypal.com", "stripe.com",
    "netflix.com",
    "dropbox.com",
    "zoom.us",
    "shopify.com",
    "wordpress.com",
    "wikipedia.org",
    "reddit.com",
    "ebay.com",
    "yahoo.com",
    "bing.com",
    "duckduckgo.com"
  ]);

  // suspicious TLDs
  const SUSPICIOUS_TLDS = new Set([
    ".tk", ".ml", ".ga", ".cf", ".gq",   // free Freenom TLDs heavily abused
    ".xyz", ".top", ".click", ".link",
    ".pw", ".cc", ".su", ".ws"
  ]);

  // suspicious Keywords in domains
  const PHISHING_KEYWORDS = [
    "login", "signin", "secure", "account", "verify", "update",
    "confirm", "banking", "support", "helpdesk", "password",
    "credential", "authenticate", "validation", "suspended",
    "unlock", "recover", "alert", "notification", "webscr"
  ];

  // homoglyph / character substitution 
  const HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "6": "g", "8": "b", "ν": "v", "α": "a", "ο": "o",
    "р": "p", "е": "e", "с": "c", "а": "a", "х": "x"
  };

  //  helpers

  function extractRootDomain(hostname) {
    // strip www.
    const parts = hostname.replace(/^www\./, "").split(".");
    if (parts.length >= 2) return parts.slice(-2).join(".");
    return hostname;
  }

  function normalizeHomoglyphs(str) {
    return str.split("").map(c => HOMOGLYPHS[c] || c).join("");
  }

  function levenshtein(a, b) {
    const dp = Array.from({ length: a.length + 1 }, (_, i) =>
      Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
    );
    for (let i = 1; i <= a.length; i++)
      for (let j = 1; j <= b.length; j++)
        dp[i][j] = a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    return dp[a.length][b.length];
  }

  //  CHECK 1, URL & Domain Analysis

  function analyzeURL(url) {
    const findings = [];
    let riskScore = 0;

    let parsed;
    try { parsed = new URL(url); }
    catch { return { findings: [{ type: "error", msg: "Could not parse URL" }], riskScore: 0 }; }

    const hostname = parsed.hostname.toLowerCase();
    const rootDomain = extractRootDomain(hostname);
    const subdomain = hostname.replace(rootDomain, "").replace(/\.$/, "");
    const subparts = subdomain ? subdomain.split(".").filter(Boolean) : [];

    // HTTP (no TLS)
    if (parsed.protocol === "http:") {
      findings.push({ severity: "high", msg: "Page is served over plain HTTP — credentials can be intercepted." });
      riskScore += 30;
    }

    // excessive subdomains
    if (subparts.length >= 3) {
      findings.push({ severity: "high", msg: `Excessive subdomain depth (${subparts.length} levels): ${hostname}` });
      riskScore += 25;
    } else if (subparts.length === 2) {
      findings.push({ severity: "medium", msg: `Unusual subdomain nesting: ${hostname}` });
      riskScore += 10;
    }

    // IP address as host
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
      findings.push({ severity: "high", msg: "Site uses a raw IP address instead of a domain name." });
      riskScore += 35;
    }

    // suspicious TLD
    for (const tld of SUSPICIOUS_TLDS) {
      if (hostname.endsWith(tld)) {
        findings.push({ severity: "medium", msg: `Domain uses a frequently-abused TLD: ${tld}` });
        riskScore += 15;
        break;
      }
    }

    // phishing keywords in hostname
    const foundKeywords = PHISHING_KEYWORDS.filter(kw => hostname.includes(kw));
    if (foundKeywords.length > 0) {
      findings.push({ severity: "medium", msg: `Suspicious keywords in domain: ${foundKeywords.join(", ")}` });
      riskScore += foundKeywords.length * 8;
    }

    // suspicious characters
    if (/[^\x00-\x7F]/.test(hostname)) {
      findings.push({ severity: "high", msg: "Domain contains non-ASCII/international characters — possible IDN homograph attack." });
      riskScore += 40;
    }
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 4) {
      findings.push({ severity: "medium", msg: `Unusually high hyphen count in domain (${hyphenCount}) — common in typosquatting.` });
      riskScore += 15;
    }
    if (parsed.pathname.includes("%") || parsed.search.includes("%00") || parsed.search.includes("%0a")) {
      findings.push({ severity: "medium", msg: "URL contains suspicious percent-encoded characters." });
      riskScore += 10;
    }

    // URL length
    if (url.length > 200) {
      findings.push({ severity: "low", msg: `URL is unusually long (${url.length} chars) — often used to obscure the real destination.` });
      riskScore += 10;
    }

    // typosquatting check
    const normalizedRoot = normalizeHomoglyphs(rootDomain.replace(/\.[^.]+$/, "")); // strip TLD for comparison
    let typoMatches = [];
    for (const trusted of TRUSTED_DOMAINS) {
      const trustedName = trusted.replace(/\.[^.]+$/, "");
      const dist = levenshtein(normalizedRoot, trustedName);
      if (dist > 0 && dist <= 2 && rootDomain !== trusted) {
        typoMatches.push({ trusted, dist });
      }
    }
    if (typoMatches.length > 0) {
      const best = typoMatches.sort((a, b) => a.dist - b.dist)[0];
      findings.push({
        severity: "high",
        msg: `Possible typosquatting: "${rootDomain}" is very close to trusted domain "${best.trusted}" (edit distance: ${best.dist}).`
      });
      riskScore += 40;
    }

    // trusted domain check, is root domain known-good?
    const isTrusted = TRUSTED_DOMAINS.has(rootDomain);
    const domainInfo = { hostname, rootDomain, subdomain: subparts.join(".") || "(none)", isTrusted };

    return { findings, riskScore: Math.min(riskScore, 100), domainInfo };
  }

  //  CHECK 2, Login Form Analysis

  function analyzeForms() {
    const findings = [];
    let riskScore = 0;
    const formSummaries = [];

    const currentHost = location.hostname.toLowerCase();
    const currentRoot = extractRootDomain(currentHost);

    const forms = Array.from(document.querySelectorAll("form"));

    // look for password fields outside <form> tags (hidden forms)
    const allPasswordFields = document.querySelectorAll('input[type="password"]');
    const orphanedPasswords = Array.from(allPasswordFields).filter(
      f => !f.closest("form")
    );
    if (orphanedPasswords.length > 0) {
      findings.push({ severity: "medium", msg: `Found ${orphanedPasswords.length} password field(s) outside any <form> tag — may use JS-based submission to obscure destination.` });
      riskScore += 15;
    }

    forms.forEach((form, idx) => {
      const hasPassword = form.querySelector('input[type="password"]');
      const hasEmail = form.querySelector('input[type="email"], input[name*="email"], input[name*="user"], input[name*="login"]');
      const isLoginForm = hasPassword || hasEmail;

      if (!isLoginForm) return; // skip non-credential forms

      const action = (form.getAttribute("action") || "").trim();
      const method = (form.getAttribute("method") || "GET").toUpperCase();
      const summary = { index: idx + 1, action: action || "(none / same page)", method, issues: [] };

      // form submits over GET (passwords in URL)
      if (method === "GET" && hasPassword) {
        findings.push({ severity: "high", msg: `Form #${idx + 1}: Login form uses GET method — passwords will appear in the URL.` });
        summary.issues.push("GET method exposes password in URL");
        riskScore += 25;
      }

      // form action analysis
      if (action && action !== "" && !action.startsWith("#")) {
        let actionURL;
        try { actionURL = new URL(action, location.href); } catch { actionURL = null; }

        if (actionURL) {
          const actionHost = actionURL.hostname.toLowerCase();
          const actionRoot = extractRootDomain(actionHost);

          // external submission
          if (actionRoot !== currentRoot) {
            const isActionTrusted = TRUSTED_DOMAINS.has(actionRoot);
            findings.push({
              severity: isActionTrusted ? "medium" : "high",
              msg: `Form #${idx + 1}: Credentials submitted to EXTERNAL domain "${actionHost}" (current site: "${currentHost}").${isActionTrusted ? " (Domain appears trusted)" : ""}`
            });
            summary.issues.push(`External submission → ${actionHost}`);
            riskScore += isActionTrusted ? 10 : 45;
          }

          // action over HTTP
          if (actionURL.protocol === "http:") {
            findings.push({ severity: "high", msg: `Form #${idx + 1}: Form action uses HTTP (not HTTPS), credentials sent unencrypted.` });
            summary.issues.push("HTTP form action (unencrypted)");
            riskScore += 30;
          }

          // data URI or javascript: action
          if (action.startsWith("javascript:") || action.startsWith("data:")) {
            findings.push({ severity: "high", msg: `Suspicious javascript code flagged.` });
            summary.issues.push("Dangerous action protocol");
            riskScore += 50;
          }

          summary.actionResolved = actionURL.href;
        }
      } else {
        // No action = submits to current page (usually fine, but note it)
        summary.actionResolved = location.href;
      }

      // autocomplete="off" on password (evasion tactic)
      const pwFields = form.querySelectorAll('input[type="password"]');
      pwFields.forEach(pw => {
        if (pw.getAttribute("autocomplete") === "new-password") return;
        if (pw.getAttribute("autocomplete") === "off") {
          findings.push({ severity: "low", msg: `Form #${idx + 1}: Password field has autocomplete="off", may be trying to prevent password managers from detecting it.` });
          summary.issues.push('autocomplete="off" on password');
          riskScore += 5;
        }
      });

      formSummaries.push(summary);
    });

    return { findings, riskScore: Math.min(riskScore, 100), formSummaries, totalLoginForms: formSummaries.length };
  }

  //  CHECK 3, Page Content Heuristics

  function analyzePageContent() {
    const findings = [];
    let riskScore = 0;

    // 3a. Favicon from external domain
    const favicon = document.querySelector('link[rel~="icon"]');
    if (favicon) {
      try {
        const faviconURL = new URL(favicon.href);
        const currentRoot = extractRootDomain(location.hostname);
        const faviconRoot = extractRootDomain(faviconURL.hostname);
        if (faviconRoot !== currentRoot && faviconURL.hostname !== "") {
          findings.push({ severity: "low", msg: `Favicon loaded from external domain "${faviconURL.hostname}" — may be impersonating another site's branding.` });
          riskScore += 5;
        }
      } catch {}
    }

    // Iframe pointing offsite
    const iframes = document.querySelectorAll("iframe");
    const currentRoot = extractRootDomain(location.hostname);
    iframes.forEach(iframe => {
      try {
        const src = iframe.src || iframe.getAttribute("src") || "";
        if (!src || src === "about:blank") return;
        const iframeURL = new URL(src, location.href);
        const iframeRoot = extractRootDomain(iframeURL.hostname);
        if (iframeRoot !== currentRoot) {
          findings.push({ severity: "medium", msg: `Off-site iframe found pointing to "${iframeURL.hostname}" — may be embedding a phishing page.` });
          riskScore += 20;
        }
      } catch {}
    });

    // title vs domain mismatch (e.g., page says "PayPal" but domain is not paypal.com)
    const title = (document.title || "").toLowerCase();
    for (const trusted of TRUSTED_DOMAINS) {
      const brand = trusted.split(".")[0];
      if (title.includes(brand) && !location.hostname.includes(brand)) {
        findings.push({ severity: "high", msg: `Suspicious javascript code flagged.` });
        riskScore += 35;
        break;
      }
    }

    // 3d. Right-click / dev tools blocking scripts
    const bodyHTML = document.body ? document.body.innerHTML.toLowerCase() : "";
    if (bodyHTML.includes("contextmenu") && bodyHTML.includes("preventdefault")) {
      findings.push({ severity: "low", msg: "Page appears to block right-click — common in pages trying to prevent inspection." });
      riskScore += 5;
    }

    return { findings, riskScore: Math.min(riskScore, 100) };
  }

  //  aggregate & Store Results

  function runAnalysis() {
    const urlResult = analyzeURL(location.href);
    const formResult = analyzeForms();
    const contentResult = analyzePageContent();

    const allFindings = [
      ...urlResult.findings,
      ...formResult.findings,
      ...contentResult.findings
    ];

    // Weighted overall risk: URL 40%, Forms 40%, Content 20%
    const overallScore = Math.min(
      urlResult.riskScore + formResult.riskScore + contentResult.riskScore,
      100
    );

    let verdict = "Safe";
    if (overallScore >= 50) verdict = "Dangerous";
    else if (overallScore >= 20) verdict = "Suspicious";

    return {
      url: location.href,
      timestamp: new Date().toISOString(),
      verdict,
      overallScore,
      urlAnalysis: { ...urlResult },
      formAnalysis: { ...formResult },
      contentAnalysis: { ...contentResult },
      allFindings
    };
  }

  // Store on window so popup.js can retrieve via chrome.scripting.executeScript
  window.__extensionResult = runAnalysis();

  // Listen for on-demand re-analysis requests from popup
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === "EXTENSION_ANALYZE") {
      window.__extensionResult = runAnalysis();
      sendResponse(window.__extensionResult);
    }
    return true; // keep channel open for async
  });

})();
