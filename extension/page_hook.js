// Walled DLP Guard - network backstop (runs in the page's own JS world at document_start,
// before the site can keep a private copy of fetch/XHR).
//
// Layer 1 (content.js) stops most actions in the UI. This layer catches anything that still
// tries to leave the page: a request body containing the marker, or an uploaded file that
// layer 1 did not already check. Such requests are held until content.js returns a decision.
// After layer 1 approves something it sends a short "grant" so the site's follow-up
// requests for the same prompt/upload are not asked about twice.
(() => {
  "use strict";
  if (window.__walledDlpHook) return;
  Object.defineProperty(window, "__walledDlpHook", { value: true });

  // Chrome injects a given file only once per frame, so common.js (used by content.js in the
  // isolated world) is not available here. Same rules, inlined; tests/js checks they agree.
  const FIXES = { "0": "O", "1": "I", "5": "S", "|": "I", "$": "S" };
  const W = {
    containsMarker: (text) => Boolean(text) &&
      String(text).toUpperCase().replace(/[015|$]/g, (c) => FIXES[c]).replace(/[^A-Z0-9]/g, "").includes("WALLEDSENSITIVE"),
  };
  const MAX_TEXT_BYTES = 2_000_000;
  const MIN_BLOB_UPLOAD_BYTES = 1024;
  const grants = { text: 0, file: 0 };
  const waiting = new Map();
  let nextId = 1;

  window.addEventListener("message", (e) => {
    const m = e.data;
    if (e.source !== window || !m || m.source !== "walled-dlp-content") return;
    if (m.type === "approve" && m.kind in grants) grants[m.kind] = Math.max(grants[m.kind], m.until);
    if (m.type === "decision" && waiting.has(m.id)) {
      waiting.get(m.id)(m.decision);
      waiting.delete(m.id);
    }
  });

  function ask(kind, extra) {
    return new Promise((resolve) => {
      const id = nextId++;
      waiting.set(id, resolve);
      window.postMessage({ source: "walled-dlp-page", id, kind, ...extra }, location.origin);
    });
  }

  const decoder = new TextDecoder("utf-8", { fatal: false });
  const looksLikeText = (s) => !/[\u0000-\u0008\u000E-\u001F]/.test(s.slice(0, 2048));

  // Split a request body into text (checked here) and files (checked by the agent).
  async function inspect(body, method) {
    const out = { text: "", files: [] };
    if (body == null) return out;
    if (typeof body === "string") out.text = body;
    else if (body instanceof URLSearchParams) out.text = body.toString();
    else if (body instanceof FormData) {
      for (const [, value] of body.entries()) {
        if (typeof value === "string") out.text += value + "\n";
        else out.files.push(value);
      }
    } else if (body instanceof Blob) {
      // Real uploads are File objects or large binary blobs; small/JSON blobs are usually
      // the site's own telemetry, so read those as text instead of asking the agent.
      // Binary non-File blobs are only treated as uploads when PUT (direct-to-storage
      // uploads); binary POSTs are typically compressed analytics.
      if (body instanceof File) out.files.push(body);
      else if (body.size <= MAX_TEXT_BYTES) {
        const text = await body.text();
        if (looksLikeText(text)) out.text = text;
        else if (/^PUT$/i.test(method) && body.size >= MIN_BLOB_UPLOAD_BYTES) out.files.push(body);
      } else if (/^PUT$/i.test(method)) out.files.push(body);
    } else if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
      const bytes = body instanceof ArrayBuffer ? new Uint8Array(body) : new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
      if (bytes.byteLength <= MAX_TEXT_BYTES) {
        const text = decoder.decode(bytes);
        if (looksLikeText(text)) out.text = text;
        else if (/^PUT$/i.test(method)) out.files.push(new Blob([bytes]));
      }
    }
    return out;
  }

  // Request bodies are usually JSON; show the user the strings that carry the marker
  // (their prompt) rather than the raw payload.
  function readable(text) {
    try {
      const hits = [];
      (function walk(v) {
        if (typeof v === "string") { if (W.containsMarker(v)) hits.push(v); }
        else if (v && typeof v === "object") Object.values(v).forEach(walk);
      })(JSON.parse(text));
      if (hits.length) return hits.join("\n");
    } catch (_) { /* not JSON */ }
    return text;
  }

  async function allowed(body, method) {
    let parts;
    try {
      parts = await inspect(body, method);
    } catch (err) {
      console.warn("[Walled DLP] could not inspect request body", err);
      return true; // inspection bugs must not break the site; layer 1 is the primary control
    }
    if (parts.text.length <= MAX_TEXT_BYTES && W.containsMarker(parts.text) && Date.now() > grants.text) {
      if ((await ask("text", { text: readable(parts.text).slice(0, 200_000) })) !== "allow") return false;
    }
    for (const file of parts.files) {
      if (Date.now() <= grants.file) break;
      if ((await ask("file", { blob: file, name: file.name || "upload" })) !== "allow") return false;
    }
    return true;
  }

  const BLOCK_MESSAGE = "Blocked by Walled DLP Guard (WALLED_SENSITIVE detected)";

  // ---- fetch
  const originalFetch = window.fetch;
  window.fetch = function (input, init) {
    const method = String((init && init.method) || (input instanceof Request ? input.method : "GET")).toUpperCase();
    const hasInitBody = init && init.body != null;
    if (method === "GET" || method === "HEAD" || (!hasInitBody && !(input instanceof Request))) {
      return originalFetch.apply(this, arguments);
    }
    const self = this;
    const args = arguments;
    return (async () => {
      const body = hasInitBody ? init.body : await input.clone().blob().catch(() => null);
      if (!(await allowed(body, method))) throw new TypeError(BLOCK_MESSAGE);
      return originalFetch.apply(self, args);
    })();
  };

  // ---- XMLHttpRequest
  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method) {
    this.__walledMethod = String(method || "GET").toUpperCase();
    return originalOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    if (body == null) return originalSend.call(this, body);
    const xhr = this;
    allowed(body, xhr.__walledMethod).then((ok) => {
      if (ok) return originalSend.call(xhr, body);
      console.warn("[Walled DLP]", BLOCK_MESSAGE);
      xhr.dispatchEvent(new ProgressEvent("error"));
      xhr.dispatchEvent(new ProgressEvent("loadend"));
    });
  };
})();
