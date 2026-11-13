// background.js — PhishGuard AI Automated Real-Time Background Scanner

const API_ENDPOINT = "https://phishguard-ai-cxug.onrender.com/api/check";

// In-memory cache for recent scans to prevent duplicate requests
const scanCache = new Map();
const CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes

chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishGuard AI Real-Time Background Scanner Active.");
  chrome.action.setBadgeBackgroundColor({ color: "#1677ff" });
});

// Auto-scan whenever a tab is loaded or navigated to a new URL
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only trigger when the page has finished loading
  if (changeInfo.status === "complete" && tab.url) {
    if (shouldScanUrl(tab.url)) {
      scanTabUrl(tabId, tab.url);
    } else {
      // Clear badge for system or internal browser pages
      chrome.action.setBadgeText({ text: "", tabId });
    }
  }
});

// Update badge when user switches between already-loaded tabs
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url && shouldScanUrl(tab.url)) {
      const cached = getCachedResult(tab.url);
      if (cached) {
        applyBadge(activeInfo.tabId, cached.prediction, cached.score);
      } else {
        scanTabUrl(activeInfo.tabId, tab.url);
      }
    } else {
      chrome.action.setBadgeText({ text: "", tabId: activeInfo.tabId });
    }
  } catch (err) {
    // Tab might have been closed
  }
});

// Filter out internal browser pages
function shouldScanUrl(url) {
  if (!url) return false;
  const lower = url.toLowerCase();
  return (
    (lower.startsWith("http://") || lower.startsWith("https://")) &&
    !lower.includes("127.0.0.1") &&
    !lower.includes("localhost")
  );
}

// Background scan runner
async function scanTabUrl(tabId, url) {
  // Check cache first
  const cached = getCachedResult(url);
  if (cached) {
    applyBadge(tabId, cached.prediction, cached.score);
    return cached;
  }

  // Show scanning status on badge
  chrome.action.setBadgeText({ text: "...", tabId });
  chrome.action.setBadgeBackgroundColor({ color: "#2563eb", tabId });

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 20000);

    const response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();

    // Cache result in memory and persistent storage
    setCachedResult(url, data);
    applyBadge(tabId, data.prediction, data.score);

    // Notify user if phishing detected
    if (data.prediction === "PHISHING") {
      showPhishingAlert(url, data.score);
    }

    return data;
  } catch (err) {
    console.warn("Background auto-scan error:", err);
    chrome.action.setBadgeText({ text: "", tabId });
    return null;
  }
}

// Update the badge text and color
function applyBadge(tabId, prediction, score) {
  if (prediction === "PHISHING") {
    chrome.action.setBadgeText({ text: `${Math.round(score)}%`, tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId }); // Red
  } else if (prediction === "LEGITIMATE") {
    chrome.action.setBadgeText({ text: "SAFE", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#10b981", tabId }); // Green
  } else {
    chrome.action.setBadgeText({ text: "", tabId });
  }
}

// Show desktop alert on phishing detection
function showPhishingAlert(url, score) {
  try {
    let hostname = url;
    try { hostname = new URL(url).hostname; } catch (_) {}

    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "🚨 PhishGuard AI Alert!",
      message: `Warning: ${hostname} was flagged as PHISHING (${Math.round(score)}% risk). Exercise caution before entering credentials.`,
      priority: 2
    });
  } catch (e) {
    console.error("Notification error:", e);
  }
}

// Cache helpers
function getCachedResult(url) {
  const item = scanCache.get(url);
  if (!item) return null;
  if (Date.now() - item.time > CACHE_TTL_MS) {
    scanCache.delete(url);
    return null;
  }
  return item.data;
}

function setCachedResult(url, data) {
  scanCache.set(url, { time: Date.now(), data });
  // Also save to chrome.storage.local for popup access
  try {
    const key = `pg_${url}`;
    chrome.storage.local.set({ [key]: { time: Date.now(), data } });
  } catch (_) {}
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getCachedScan") {
    const cached = getCachedResult(request.url);
    sendResponse({ result: cached });
  } else if (request.action === "manualScan") {
    scanTabUrl(request.tabId, request.url).then(res => {
      sendResponse({ result: res });
    });
    return true; // async
  }
  return true;
});
