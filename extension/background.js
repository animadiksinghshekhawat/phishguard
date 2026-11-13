// background.js — PhishGuard AI Background Service Worker

chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishGuard AI extension installed successfully.");
  chrome.action.setBadgeBackgroundColor({ color: "#1677ff" });
});

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "updateBadge") {
    const { prediction, score, tabId } = request;
    const targetTabId = tabId || (sender.tab && sender.tab.id);

    if (prediction === "PHISHING") {
      chrome.action.setBadgeText({ text: `${Math.round(score)}%`, tabId: targetTabId });
      chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId: targetTabId }); // Red
    } else if (prediction === "LEGITIMATE") {
      chrome.action.setBadgeText({ text: "SAFE", tabId: targetTabId });
      chrome.action.setBadgeBackgroundColor({ color: "#10b981", tabId: targetTabId }); // Green
    } else {
      chrome.action.setBadgeText({ text: "", tabId: targetTabId });
    }
    sendResponse({ success: true });
  }

  return true;
});
