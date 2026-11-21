// Bridge between content scripts and the Python desktop agent (Chrome Native Messaging).
// One long-lived port; requests are matched to replies by id. If the agent is missing or
// crashes, pending and new checks resolve to "block" (fail closed).

const HOST_NAME = "com.walled.dlp_guard";
const REQUEST_TIMEOUT_MS = 180_000; // the agent's own dialog auto-cancels after 120 s

let port = null;
let nextId = 1;
let lastError = "";
const pending = new Map();

function connect() {
  if (port) return port;
  try {
    port = chrome.runtime.connectNative(HOST_NAME);
  } catch (err) {
    lastError = String(err && err.message ? err.message : err);
    port = null;
    return null;
  }
  port.onMessage.addListener((reply) => {
    const entry = pending.get(reply.id);
    if (!entry) return;
    pending.delete(reply.id);
    entry.resolve(reply);
  });
  port.onDisconnect.addListener(() => {
    lastError = (chrome.runtime.lastError && chrome.runtime.lastError.message) || "agent disconnected";
    port = null;
    for (const [, entry] of pending) entry.resolve(unavailable());
    pending.clear();
  });
  return port;
}

function unavailable() {
  return {
    decision: "block",
    agentDown: true,
    reason: `Walled DLP desktop agent is not reachable (${lastError || "not installed"}). Blocked to be safe.`,
  };
}

function ask(payload, timeoutMs = REQUEST_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const p = connect();
    if (!p) return resolve(unavailable());
    const id = nextId++;
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve({ decision: "block", reason: "The DLP agent did not answer in time. Blocked to be safe." });
    }, timeoutMs);
    pending.set(id, { resolve: (reply) => { clearTimeout(timer); resolve(reply); } });
    try {
      p.postMessage({ ...payload, id });
    } catch (err) {
      clearTimeout(timer);
      pending.delete(id);
      lastError = String(err && err.message ? err.message : err);
      resolve(unavailable());
    }
  });
}

// Chrome only injects content scripts into pages loaded after install. Tabs that were already
// open would be unprotected until refreshed, so inject into them now. (The fetch/XHR hook is
// late in these tabs; the UI interception in content.js still applies.)
const SITE_PATTERNS = ["https://chatgpt.com/*", "https://chat.openai.com/*", "https://www.perplexity.ai/*", "https://perplexity.ai/*"];
chrome.runtime.onInstalled.addListener(async () => {
  for (const tab of await chrome.tabs.query({ url: SITE_PATTERNS })) {
    try {
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["page_hook.js"], world: "MAIN" });
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["common.js", "content.js"] });
    } catch (err) {
      console.warn("could not inject into tab", tab.id, err);
    }
  }
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "dlp-check") {
    ask(msg.payload).then(sendResponse);
    return true; // async response
  }
  if (msg && msg.type === "dlp-status") {
    ask({ type: "ping" }, 5000).then(sendResponse);
    return true;
  }
  return false;
});
