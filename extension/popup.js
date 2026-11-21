const DEFAULT_COLOR = "#f97316";

function show(id, text, ok) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = ok ? "ok" : "bad";
}

chrome.runtime.sendMessage({ type: "dlp-status" }).then((reply) => {
  if (reply && reply.decision === "allow") {
    show("agent", `connected (v${reply.version})`, true);
    show("ocr", reply.ocr ? "available" : "not installed", Boolean(reply.ocr));
  } else {
    show("agent", "not running", false);
    document.getElementById("agent").title = (reply && reply.reason) || "";
  }
});

const picker = document.getElementById("color");
chrome.storage.sync.get({ responseColor: DEFAULT_COLOR }).then((v) => (picker.value = v.responseColor));
picker.addEventListener("input", () => chrome.storage.sync.set({ responseColor: picker.value }));
