// Walled DLP Guard - content script (isolated world).
//
// Layer 1 (this file): intercepts user actions *before* the site sees them.
//   * prompt submit: Enter key and Send/Submit button clicks (capture phase)
//   * file uploads: <input type=file> change, drag & drop, paste
//   Prompts with the marker, and every file, are sent to the desktop agent; the action is
//   held until it answers. Continue -> we replay the action. Cancel -> nothing reaches the site.
// Layer 2 (page_hook.js) wraps fetch/XHR as a backstop; it asks this script for decisions.
// Also recolours AI responses with injected CSS.
(() => {
  "use strict";
  if (window.__walledDlpContent) return;
  window.__walledDlpContent = true;

  const W = globalThis.WalledDLP;
  const SITE = /(^|\.)perplexity\.ai$/.test(location.hostname) ? "perplexity" : "chatgpt";

  // Selectors verified on the live sites (Nov 2026); several variants per site because the
  // logged-in, logged-out, desktop and mobile layouts differ.
  const SITES = {
    chatgpt: {
      composer: '#prompt-textarea, textarea[name="prompt"], [contenteditable="true"][role="textbox"], .ProseMirror[contenteditable="true"]',
      send: '[data-testid="send-button"], #composer-submit-button, button[aria-label="Send message"], button[aria-label="Send prompt"]',
      // logged-in (2026 "DIL" renderer), logged-out, and the older message layout
      responses: ["[data-dil-response]", '[data-message-author-role="assistant"]', "[data-assistant-markdown-root]"],
    },
    perplexity: {
      composer: '[data-lexical-editor="true"], #ask-input, textarea[placeholder], [contenteditable="true"][role="textbox"]',
      send: 'button[aria-label="Submit"], button[data-testid="submit-button"]',
      // The user's own question is rendered with data-renderer="lm" too, but inside a
      // [data-message-bubble] - exclude it so only AI-generated text is recoloured.
      responses: ['[data-renderer="lm"]:not([data-message-bubble] *)', '[id^="markdown-content"]'],
    },
  };
  const CFG = SITES[SITE];

  const MAX_INLINE_BYTES = 40 * 1024 * 1024;
  const TEXT_GRANT_MS = 30_000;   // after Continue, let the page's own requests for that prompt through
  const FILE_GRANT_MS = 120_000;  // after a file is checked, let its upload requests through
  const DEFAULT_COLOR = "#f97316";

  let bypass = false; // true while we replay an action we already approved

  function stop(e) {
    e.preventDefault();
    e.stopImmediatePropagation();
  }

  // ------------------------------------------------------------------ AI response colour

  function installStyle() {
    const all = CFG.responses.map((s) => `${s}, ${s} *`).join(",\n");
    // ChatGPT's streaming renderer colours text through per-span CSS variables set inline,
    // so override those too (a stylesheet !important beats a non-important inline style).
    const css =
      `${all} { color: var(--walled-ai-response-color, ${DEFAULT_COLOR}) !important;\n` +
      `  --d-stream-ink: var(--walled-ai-response-color, ${DEFAULT_COLOR}) !important;\n` +
      `  --d-stream-enter-ink: var(--walled-ai-response-color, ${DEFAULT_COLOR}) !important; }`;
    const ensure = () => {
      if (document.getElementById("walled-dlp-style")) return;
      const style = document.createElement("style");
      style.id = "walled-dlp-style";
      style.textContent = css;
      (document.head || document.documentElement).appendChild(style);
    };
    ensure();
    // Single-page apps sometimes rebuild <head>; put the style back if it disappears.
    new MutationObserver(ensure).observe(document.documentElement, { childList: true, subtree: false });
    document.addEventListener("DOMContentLoaded", ensure);
  }

  function applyColor(color) {
    document.documentElement.style.setProperty("--walled-ai-response-color", color || DEFAULT_COLOR);
  }

  installStyle();
  chrome.storage.sync.get({ responseColor: DEFAULT_COLOR }).then((v) => applyColor(v.responseColor)).catch(() => {});
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.responseColor) applyColor(changes.responseColor.newValue);
  });

  // ------------------------------------------------------------------ in-page status toast

  let toastBox = null;
  let toastTimer = null;
  function toast(kind, text, ms = 5000) {
    if (!document.body) return;
    if (!toastBox) {
      const host = document.createElement("div");
      host.style.cssText = "position:fixed;top:16px;right:16px;z-index:2147483647;";
      const root = host.attachShadow({ mode: "closed" });
      root.innerHTML = `<style>
        div{font:13px/1.4 system-ui,sans-serif;max-width:380px;padding:10px 14px;border-radius:10px;
            box-shadow:0 6px 24px rgba(0,0,0,.25);color:#fff;white-space:pre-line}
        .info{background:#1e3a8a}.ok{background:#166534}.block{background:#991b1b}
      </style><div></div>`;
      toastBox = root.querySelector("div");
      document.body.appendChild(host);
    }
    toastBox.className = kind;
    toastBox.textContent = "Walled DLP Guard: " + text;
    toastBox.parentNode.host.style.display = "block";
    clearTimeout(toastTimer);
    if (ms) toastTimer = setTimeout(() => (toastBox.parentNode.host.style.display = "none"), ms);
  }

  // ------------------------------------------------------------------ agent bridge

  async function askAgent(payload) {
    try {
      const reply = await chrome.runtime.sendMessage({ type: "dlp-check", payload: { ...payload, site: SITE } });
      return reply || { decision: "block", reason: "No answer from the extension." };
    } catch (err) {
      return { decision: "block", reason: "The extension was reloaded - refresh this page." };
    }
  }

  // After a check, the site's own follow-up requests (the actual send/upload) must not be
  // asked about again. The grant is recorded here *and* forwarded to page_hook.js: the
  // forwarded copy can arrive a moment after the site starts uploading, so questions from
  // page_hook are also answered from this local record (no race).
  const grantedUntil = { text: 0, file: 0 };
  function grant(kind, ms) {
    grantedUntil[kind] = Date.now() + ms;
    window.postMessage({ source: "walled-dlp-content", type: "approve", kind, until: grantedUntil[kind] }, location.origin);
  }

  // ------------------------------------------------------------------ prompts

  let pendingPrompt = null; // one dialog at a time; concurrent checks share its answer

  function decidePrompt(text) {
    if (pendingPrompt) return pendingPrompt;
    toast("info", "WALLED_SENSITIVE found in your prompt.\nAnswer the desktop dialog to continue.", 0);
    pendingPrompt = askAgent({ type: "check_text", text }).then((reply) => {
      if (reply.decision === "allow") {
        grant("text", TEXT_GRANT_MS);
        toast("ok", "Sending - you chose Continue.");
      } else {
        toast("block", "Prompt not sent. " + (reply.reason || ""), 7000);
      }
      return reply;
    });
    pendingPrompt.finally(() => (pendingPrompt = null));
    return pendingPrompt;
  }

  const composerOf = (node) => (node && node.closest ? node.closest(CFG.composer) : null);
  const readText = (el) => (!el ? "" : typeof el.value === "string" ? el.value : el.innerText || "");

  function composerNear(node) {
    for (let n = node; n; n = n.parentElement) {
      const c = n.querySelector && n.querySelector(CFG.composer);
      if (c) return c;
    }
    return composerOf(document.activeElement) || document.querySelector(CFG.composer);
  }

  function sendButtonNear(node) {
    for (let n = node, i = 0; n && i < 12; n = n.parentElement, i++) {
      const b = n.querySelector && n.querySelector(CFG.send);
      if (b) return b;
    }
    return document.querySelector(CFG.send);
  }

  function replaySend(composer, button) {
    bypass = true;
    try {
      const btn = button && button.isConnected ? button : sendButtonNear(composer);
      if (btn && !btn.disabled) {
        btn.click();
      } else if (composer) {
        composer.focus();
        composer.dispatchEvent(new KeyboardEvent("keydown", {
          key: "Enter", code: "Enter", keyCode: 13, which: 13, bubbles: true, cancelable: true,
        }));
      }
    } finally {
      bypass = false;
    }
  }

  window.addEventListener("keydown", (e) => {
    if (bypass || e.key !== "Enter" || e.shiftKey || e.altKey || e.isComposing) return;
    const composer = composerOf(e.target);
    if (!composer) return;
    const text = readText(composer);
    if (!W.containsMarker(text)) return;
    stop(e);
    decidePrompt(text).then((r) => r.decision === "allow" && replaySend(composer, null));
  }, true);

  window.addEventListener("click", (e) => {
    if (bypass) return;
    const button = e.target.closest && e.target.closest(CFG.send);
    if (!button) return;
    const composer = composerNear(button);
    const text = readText(composer);
    if (!W.containsMarker(text)) return;
    stop(e);
    decidePrompt(text).then((r) => r.decision === "allow" && replaySend(composer, button));
  }, true);

  window.addEventListener("submit", (e) => {
    if (bypass) return;
    const form = e.target;
    const composer = form.querySelector && form.querySelector(CFG.composer);
    const text = readText(composer);
    if (!composer || !W.containsMarker(text)) return;
    stop(e);
    decidePrompt(text).then((r) => {
      if (r.decision !== "allow") return;
      bypass = true;
      try { form.requestSubmit(); } finally { bypass = false; }
    });
  }, true);

  // ------------------------------------------------------------------ files

  function toBase64(blob) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result).split(",", 2)[1] || "");
      reader.onerror = () => reject(reader.error);
      reader.readAsDataURL(blob);
    });
  }

  async function checkFile(file) {
    const payload = { type: "check_file", name: file.name || "pasted file", mime: file.type || "", size: file.size };
    if (file.size <= MAX_INLINE_BYTES) payload.data = await toBase64(file);
    return askAgent(payload);
  }

  // Files are checked one at a time so dialogs never stack up; each gets its own decision.
  async function screenFiles(files, { quiet = false } = {}) {
    const allowed = [];
    const blocked = [];
    if (!quiet) toast("info", `Checking ${files.length} file(s) for sensitive data...`, 0);
    for (const file of files) {
      const reply = await checkFile(file);
      (reply.decision === "allow" ? allowed : blocked).push({ file, reply });
    }
    if (allowed.length) grant("file", FILE_GRANT_MS);
    if (blocked.length) {
      const names = blocked.map((b) => `${b.file.name || "file"}: ${b.reply.reason || "blocked"}`).join("\n");
      toast("block", `Upload stopped:\n${names}`, 8000);
    } else if (!quiet) {
      toast("ok", `${allowed.length} file(s) checked - uploading.`, 2500);
    }
    return allowed.map((a) => a.file);
  }

  function asDataTransfer(files) {
    const dt = new DataTransfer();
    files.forEach((f) => dt.items.add(f));
    return dt;
  }

  function isFileInput(t) {
    return t instanceof HTMLInputElement && t.type === "file" && t.files && t.files.length > 0;
  }

  // Some frameworks read files on "input", most on "change": hold both until checked.
  window.addEventListener("input", (e) => {
    if (!bypass && isFileInput(e.target)) e.stopImmediatePropagation();
  }, true);

  window.addEventListener("change", (e) => {
    const input = e.target;
    if (bypass || !isFileInput(input)) return;
    e.stopImmediatePropagation();
    const files = [...input.files];
    screenFiles(files).then((allowed) => {
      if (!allowed.length) {
        input.value = "";
        return;
      }
      if (allowed.length !== files.length) input.files = asDataTransfer(allowed).files;
      bypass = true;
      try {
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
      } finally {
        bypass = false;
      }
    });
  }, true);

  window.addEventListener("drop", (e) => {
    const dt = e.dataTransfer;
    if (bypass || !dt || !dt.files || !dt.files.length) return;
    stop(e);
    const target = e.target;
    const { clientX, clientY } = e;
    screenFiles([...dt.files]).then((allowed) => {
      if (!allowed.length) return;
      bypass = true;
      try {
        target.dispatchEvent(new DragEvent("drop", {
          bubbles: true, cancelable: true, composed: true, clientX, clientY, dataTransfer: asDataTransfer(allowed),
        }));
      } finally {
        bypass = false;
      }
    });
  }, true);

  window.addEventListener("paste", (e) => {
    const cd = e.clipboardData;
    if (bypass || !cd || !cd.files || !cd.files.length) return; // pasted text is checked when sent
    stop(e);
    const target = e.target;
    screenFiles([...cd.files]).then((allowed) => {
      if (!allowed.length) return;
      bypass = true;
      try {
        target.dispatchEvent(new ClipboardEvent("paste", {
          bubbles: true, cancelable: true, composed: true, clipboardData: asDataTransfer(allowed),
        }));
      } finally {
        bypass = false;
      }
    });
  }, true);

  // ------------------------------------------------------------------ network backstop bridge

  window.addEventListener("message", async (e) => {
    const m = e.data;
    if (e.source !== window || !m || m.source !== "walled-dlp-page") return;
    let decision = "block";
    if ((m.kind === "text" || m.kind === "file") && Date.now() <= grantedUntil[m.kind]) {
      decision = "allow"; // already checked by layer 1 moments ago
    } else if (m.kind === "text") {
      decision = (await decidePrompt(String(m.text || ""))).decision;
    } else if (m.kind === "file" && m.blob instanceof Blob) {
      const file = m.blob instanceof File ? m.blob : new File([m.blob], m.name || "upload", { type: m.blob.type });
      decision = (await screenFiles([file], { quiet: true })).length ? "allow" : "block";
    }
    window.postMessage({ source: "walled-dlp-content", type: "decision", id: m.id, decision }, location.origin);
  });
})();
