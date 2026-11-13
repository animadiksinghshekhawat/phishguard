// popup.js — PhishGuard AI Chrome Extension Logic

const API_ENDPOINT = "https://phishguard-ai-cxug.onrender.com/api/check";

// Elements
const urlInput = document.getElementById("urlInput");
const scanBtn = document.getElementById("scanBtn");
const btnText = scanBtn.querySelector(".btn-text");
const btnSpinner = scanBtn.querySelector(".btn-spinner");
const tabStatusText = document.getElementById("tabStatusText");
const statusBadge = document.getElementById("statusBadge");

const loadingState = document.getElementById("loadingState");
const errorState = document.getElementById("errorState");
const errorTitle = document.getElementById("errorTitle");
const errorDesc = document.getElementById("errorDesc");
const retryBtn = document.getElementById("retryBtn");

const resultsPanel = document.getElementById("resultsPanel");
const verdictCard = document.getElementById("verdictCard");
const ringFill = document.getElementById("ringFill");
const scoreNum = document.getElementById("scoreNum");
const verdictTag = document.getElementById("verdictTag");
const verdictMeta = document.getElementById("verdictMeta");
const modelMeta = document.getElementById("modelMeta");

const sigHttps = document.getElementById("sigHttps");
const sigAge = document.getElementById("sigAge");
const sigPR = document.getElementById("sigPR");
const sigBlacklist = document.getElementById("sigBlacklist");
const sigDNS = document.getElementById("sigDNS");
const sigPW = document.getElementById("sigPW");

const reasonsList = document.getElementById("reasonsList");
const toggleFeaturesBtn = document.getElementById("toggleFeaturesBtn");
const accordionArrow = document.getElementById("accordionArrow");
const featuresTableWrapper = document.getElementById("featuresTableWrapper");
const featuresGrid = document.getElementById("featuresGrid");

let currentTabId = null;

// Initialize popup
document.addEventListener("DOMContentLoaded", async () => {
  setupAccordion();
  scanBtn.addEventListener("click", () => handleScan(urlInput.value));
  retryBtn.addEventListener("click", () => handleScan(urlInput.value));
  urlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleScan(urlInput.value);
  });

  // Query active tab
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      currentTabId = tab.id;
      const url = tab.url;
      if (url.startsWith("http://") || url.startsWith("https://")) {
        urlInput.value = url;
        tabStatusText.textContent = `Current tab: ${new URL(url).hostname}`;
        // Check background auto-scan cache for instant 0ms result
        try {
          chrome.runtime.sendMessage({ action: "getCachedScan", url }, (response) => {
            if (response && response.result) {
              setBackendStatus(true);
              renderResults(response.result);
            } else {
              handleScan(url);
            }
          });
        } catch (_) {
          handleScan(url);
        }
      } else {
        tabStatusText.textContent = "Browser system page (paste any external URL below)";
        urlInput.placeholder = "Paste a URL to scan (e.g. https://example.com)";
      }
    }
  } catch (err) {
    console.error("Tab query error:", err);
  }
});

// Setup accordion toggle
function setupAccordion() {
  toggleFeaturesBtn.addEventListener("click", () => {
    const isHidden = featuresTableWrapper.classList.contains("hidden");
    if (isHidden) {
      featuresTableWrapper.classList.remove("hidden");
      accordionArrow.classList.add("open");
    } else {
      featuresTableWrapper.classList.add("hidden");
      accordionArrow.classList.remove("open");
    }
  });
}

// Perform scan request
async function handleScan(targetUrl) {
  const url = (targetUrl || "").trim();
  if (!url) {
    urlInput.focus();
    return;
  }

  showLoading();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 20000);

    const response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`Server returned status ${response.status}`);
    }

    const data = await response.json();
    setBackendStatus(true);
    renderResults(data);

    // Update Chrome tab badge
    try {
      chrome.runtime.sendMessage({
        action: "updateBadge",
        prediction: data.prediction,
        score: data.score,
        tabId: currentTabId
      });
    } catch (_) {}

  } catch (err) {
    console.error("Scan error:", err);
    setBackendStatus(false);
    showError(
      "Backend Unreachable",
      `Could not connect to <code>http://127.0.0.1:5000</code>.<br>Make sure the Flask server is running (run <code>python app.py</code> in your project).`
    );
  }
}

// Render analysis results
function renderResults(data) {
  hideLoading();
  hideError();
  resultsPanel.classList.remove("hidden");

  const isPhishing = data.prediction === "PHISHING";
  const score = Math.round(data.score || 0);

  // Verdict card styling
  verdictCard.className = `verdict-card ${isPhishing ? "danger" : "safe"}`;
  verdictTag.className = `verdict-tag ${isPhishing ? "danger" : "safe"}`;
  verdictTag.textContent = isPhishing ? "🚨 PHISHING DETECTED" : "🛡️ LIKELY LEGITIMATE";
  verdictMeta.textContent = isPhishing
    ? "High probability of deceptive or malicious destination"
    : "No major malicious or deceptive patterns detected";

  scoreNum.textContent = score;

  // Animate SVG Ring (Circumference = 2 * PI * 42 ≈ 263.89)
  const circumference = 264;
  const offset = circumference - (score / 100) * circumference;
  ringFill.style.strokeDashoffset = offset;
  ringFill.style.stroke = isPhishing ? "#ef4444" : (score > 35 ? "#f59e0b" : "#10b981");

  modelMeta.textContent = `Engine: ${data.model || "Random Forest"} (${data.model_accuracy || "97.4"}% acc)`;

  // Signals
  const feats = data.features || {};
  renderSignal(sigHttps, feats.https, feats.https === "Yes");
  renderSignal(sigAge, feats.domain_age || "Unknown", feats.domain_age && feats.domain_age !== "Unknown");
  renderSignal(sigPR, feats.pagerank != null ? feats.pagerank : "—", feats.pagerank > 2);
  renderSignal(sigBlacklist, feats.blacklisted || "No", !feats.blacklisted?.includes("Yes"));
  renderSignal(sigDNS, feats.dns_records || "Yes", feats.dns_records === "Yes");
  renderSignal(sigPW, feats.password_fields != null ? feats.password_fields : "0", feats.password_fields === 0);

  // Reasons list
  reasonsList.innerHTML = "";
  const reasons = data.reasons || [];
  if (reasons.length === 0) {
    const item = document.createElement("div");
    item.className = "reason-item";
    item.innerHTML = `<span class="reason-icon">✓</span><span>No red flags detected.</span>`;
    reasonsList.appendChild(item);
  } else {
    reasons.forEach(r => {
      const item = document.createElement("div");
      item.className = "reason-item";
      item.innerHTML = `<span class="reason-icon">${isPhishing ? "⚠️" : "ℹ️"}</span><span>${escapeHtml(r)}</span>`;
      reasonsList.appendChild(item);
    });
  }

  // All 30 features
  renderAllFeatures(data.flags || {});
}

function renderSignal(element, text, isGood) {
  element.textContent = text;
  element.className = `sig-val ${isGood ? "safe" : "danger"}`;
}

function renderAllFeatures(flags) {
  featuresGrid.innerHTML = "";
  const entries = Object.entries(flags);

  if (entries.length === 0) {
    featuresGrid.innerHTML = `<div style="grid-column: span 2; font-size:10px; color:#64748b;">No feature flags returned.</div>`;
    return;
  }

  entries.forEach(([name, val]) => {
    const pill = document.createElement("div");
    pill.className = "feature-pill";

    let badgeClass = "neutral";
    let badgeText = "UNKN";
    if (val === 1) {
      badgeClass = "safe";
      badgeText = "✓ BENIGN";
    } else if (val === -1) {
      badgeClass = "danger";
      badgeText = "⚠ PHISH";
    }

    pill.innerHTML = `
      <span class="feat-name" title="${name}">${name}</span>
      <span class="feat-badge ${badgeClass}">${badgeText}</span>
    `;
    featuresGrid.appendChild(pill);
  });
}

// UI state helpers
function showLoading() {
  loadingState.classList.remove("hidden");
  resultsPanel.classList.add("hidden");
  errorState.classList.add("hidden");
  btnText.textContent = "Scanning...";
  btnSpinner.classList.remove("hidden");
  scanBtn.disabled = true;
}

function hideLoading() {
  loadingState.classList.add("hidden");
  btnText.textContent = "Scan";
  btnSpinner.classList.add("hidden");
  scanBtn.disabled = false;
}

function showError(title, desc) {
  hideLoading();
  resultsPanel.classList.add("hidden");
  errorState.classList.remove("hidden");
  errorTitle.textContent = title;
  errorDesc.innerHTML = desc;
}

function hideError() {
  errorState.classList.add("hidden");
}

function setBackendStatus(isOnline) {
  if (isOnline) {
    statusBadge.innerHTML = `<span class="pulse-dot"></span><span class="status-label">ONLINE</span>`;
    statusBadge.style.borderColor = "rgba(16, 185, 129, 0.25)";
  } else {
    statusBadge.innerHTML = `<span class="pulse-dot" style="background:#ef4444; box-shadow:0 0 8px #ef4444"></span><span class="status-label" style="color:#ef4444">OFFLINE</span>`;
    statusBadge.style.borderColor = "rgba(239, 68, 68, 0.25)";
  }
}

function escapeHtml(str) {
  return str.replace(/[&<>'"]/g, tag => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    '"': "&quot;"
  }[tag] || tag));
}
