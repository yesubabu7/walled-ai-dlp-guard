// Node tests for the extension's shared logic and the network backstop (page_hook.js),
// run in a simulated page. Usage: node --test tests/js
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const read = (name) => fs.readFileSync(new URL(`../../extension/${name}`, import.meta.url), "utf8");

function loadCommon() {
  const ctx = vm.createContext({});
  vm.runInContext(read("common.js"), ctx);
  return ctx.WalledDLP;
}

test("marker matching mirrors the Python agent", () => {
  const W = loadCommon();
  for (const t of ["WALLED_SENSITIVE", "walled sensitive", "WALLED-\nSENSITIVE", "WALLED_5ENSITIVE"]) {
    assert.equal(W.containsMarker(t), true, t);
  }
  for (const t of ["", "walled garden", "SENSITIVE only", null]) assert.equal(W.containsMarker(t), false, String(t));
});

// ------------------------------------------------------------ simulated page for page_hook.js

function loadPage(decide) {
  const listeners = [];
  const asked = [];
  const fetched = [];
  const xhrs = [];

  class FakeXHR {
    constructor() { this.events = []; this.sent = false; xhrs.push(this); }
    open() {}
    send() { this.sent = true; }
    dispatchEvent(e) { this.events.push(e.type); }
  }

  const win = {
    console, TextDecoder, Blob, File, FormData, URLSearchParams, ArrayBuffer, Uint8Array, Request,
    Date, Promise, Map, Object, String, TypeError,
    location: { origin: "https://chatgpt.com" },
    XMLHttpRequest: FakeXHR,
    ProgressEvent: class { constructor(type) { this.type = type; } },
    fetch: async (input, init) => { fetched.push({ input, init }); return "network-response"; },
    addEventListener: (type, fn) => type === "message" && listeners.push(fn),
  };
  // Inside a vm context `window` is the context's global proxy, not `win` itself; messages
  // must come from that object to pass page_hook's `e.source === window` check.
  let pageWindow = win;
  const deliver = (data) => listeners.forEach((fn) => fn({ source: pageWindow, data }));
  win.postMessage = (data) => queueMicrotask(() => {
    if (data.source !== "walled-dlp-page") return deliver(data);
    asked.push(data);
    deliver({ source: "walled-dlp-content", type: "decision", id: data.id, decision: decide(data) });
  });
  win.window = win;
  win.globalThis = win;

  const ctx = vm.createContext(win);
  pageWindow = vm.runInContext("window", ctx);
  vm.runInContext(read("common.js"), ctx);
  vm.runInContext(read("page_hook.js"), ctx);
  return { win, asked, fetched, xhrs, grant: (kind) => deliver({ source: "walled-dlp-content", type: "approve", kind, until: Date.now() + 60_000 }) };
}

const tick = () => new Promise((r) => setTimeout(r, 10));

test("clean POST goes straight through without asking", async () => {
  const page = loadPage(() => "block");
  assert.equal(await page.win.fetch("/api", { method: "POST", body: '{"q":"hello"}' }), "network-response");
  assert.equal(page.asked.length, 0);
});

test("POST containing the marker is held and blocked on Cancel", async () => {
  const page = loadPage(() => "block");
  await assert.rejects(page.win.fetch("/conversation", { method: "POST", body: '{"q":"WALLED_SENSITIVE"}' }), /Walled DLP/);
  assert.equal(page.fetched.length, 0, "request must never reach the network");
  assert.equal(page.asked[0].kind, "text");
});

test("POST containing the marker is sent on Continue", async () => {
  const page = loadPage(() => "allow");
  assert.equal(await page.win.fetch("/conversation", { method: "POST", body: "WALLED_SENSITIVE" }), "network-response");
  assert.equal(page.fetched.length, 1);
});

test("a recent UI approval is not asked again", async () => {
  const page = loadPage(() => "block");
  page.grant("text");
  await page.win.fetch("/conversation", { method: "POST", body: "WALLED_SENSITIVE" });
  assert.equal(page.asked.length, 0);
});

test("GET requests are never inspected", async () => {
  const page = loadPage(() => "block");
  assert.equal(await page.win.fetch("/search?q=WALLED_SENSITIVE"), "network-response");
  assert.equal(page.asked.length, 0);
});

test("files in FormData uploads are sent to the agent", async () => {
  const page = loadPage(() => "block");
  const form = new FormData();
  form.append("file", new File(["%PDF-1.7 ..."], "report.pdf", { type: "application/pdf" }));
  await assert.rejects(page.win.fetch("https://upload.example/", { method: "POST", body: form }));
  assert.equal(page.asked[0].kind, "file");
  assert.equal(page.asked[0].name, "report.pdf");
});

test("blocked XHR is never sent and reports an error", async () => {
  const page = loadPage(() => "block");
  const xhr = new page.win.XMLHttpRequest();
  xhr.open("POST", "/conversation");
  xhr.send("contains WALLED_SENSITIVE");
  await tick();
  assert.equal(xhr.sent, false);
  assert.deepEqual(xhr.events, ["error", "loadend"]);
});

test("allowed XHR is sent after the decision", async () => {
  const page = loadPage(() => "allow");
  const xhr = new page.win.XMLHttpRequest();
  xhr.open("PUT", "https://blob.example/upload");
  xhr.send(new File(["image bytes"], "photo.png", { type: "image/png" }));
  await tick();
  assert.equal(xhr.sent, true);
});
