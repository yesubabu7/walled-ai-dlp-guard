"""Native messaging host: the desktop side of Walled DLP Guard.

Chrome starts this process when the extension calls chrome.runtime.connectNative() and
talks to it over stdin/stdout (see protocol.py). Requests from the extension:

  {"id": 7, "type": "ping"}
  {"id": 8, "type": "check_text", "site": "chatgpt", "text": "..."}
  {"id": 9, "type": "check_file", "site": "perplexity", "name": "a.pdf", "mime": "...", "data": "<base64>"}

Reply: {"id": 8, "decision": "allow" | "block", "found": bool, "reason": "..."}

Each request is handled on its own thread, so a dialog waiting for the user never stops
other checks (several uploads at once each get their own answer).
"""

import base64
import binascii
import logging
import os
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from agent import __version__  # noqa: E402
from agent.dialog import confirm  # noqa: E402
from agent.logger import LOG_DIR, setup_logging  # noqa: E402
from agent.protocol import ProtocolError, read_message, write_message  # noqa: E402
from agent.scanner import MARKER, ScanResult, ocr_available, scan_file, scan_text  # noqa: E402

log = logging.getLogger("walled_dlp.host")

SITE_NAMES = {"chatgpt": "ChatGPT", "perplexity": "Perplexity"}
MAX_FILE_BYTES = 40 * 1024 * 1024
TITLE = "Walled DLP Guard - sensitive data detected"


class Agent:
    def __init__(self, out, tray=None):
        self._out = out
        self._write_lock = threading.Lock()
        self.tray = tray

    def handle(self, msg: dict) -> None:
        try:
            reply = self.process(msg)
        except Exception:
            log.exception("request %s failed", msg.get("id"))
            reply = {"decision": "block", "found": False, "reason": "DLP agent error - blocked to be safe"}
        reply["id"] = msg.get("id")
        with self._write_lock:
            write_message(self._out, reply)

    def process(self, msg: dict) -> dict:
        kind = msg.get("type")
        if kind == "ping":
            return {"decision": "allow", "version": __version__, "ocr": ocr_available()}

        site = SITE_NAMES.get(msg.get("site"), "an AI website")
        if kind == "check_text":
            result = scan_text(str(msg.get("text", "")))
            return self._decide(site, "prompt", result)

        if kind == "check_file":
            name = str(msg.get("name") or "unnamed file")
            try:
                data = base64.b64decode(msg.get("data", ""), validate=True)
            except (binascii.Error, ValueError):
                return {"decision": "block", "found": False, "reason": "file data was not valid base64"}
            size = max(len(data), int(msg.get("size") or 0))
            label = f'file "{name}" ({_size(size)})'
            if size > MAX_FILE_BYTES or (not data and size):
                # The extension sends only metadata for files too large to pass through Chrome.
                return self._ask_unscannable(site, label, f"it is larger than {_size(MAX_FILE_BYTES)}")
            result = scan_file(name, str(msg.get("mime", "")), data)
            if not result.scanned and result.kind in ("pdf", "image"):
                return self._ask_unscannable(site, label, result.note)
            return self._decide(site, label, result)

        return {"decision": "block", "found": False, "reason": f"unknown request type {kind!r}"}

    def _decide(self, site: str, what: str, result: ScanResult) -> dict:
        if not result.found:
            log.info("%s %s: clean (%s)", site, what, result.kind)
            self._record(False)
            return {"decision": "allow", "found": False}

        detail = f"\nWhere: {result.where}" if result.where and result.where != "prompt" else ""
        context = f'\nContext: "{result.snippet}"' if result.snippet else ""
        message = (
            f"{MARKER} was found in the {what} you are about to send to {site}.{detail}{context}\n\n"
            f"Continue  - send it anyway\n"
            f"Cancel    - stop it here (nothing is sent)"
        )
        allowed = confirm(TITLE, message)
        self._record(True)
        log.info("%s %s: marker found (%s) -> user chose %s",
                 site, what, result.where or result.kind, "CONTINUE" if allowed else "CANCEL")
        return {
            "decision": "allow" if allowed else "block",
            "found": True,
            "where": result.where,
            "reason": "user chose Continue" if allowed else f"{MARKER} detected - cancelled by the user",
        }

    def _ask_unscannable(self, site: str, what: str, why: str) -> dict:
        message = (
            f"The {what} you are about to send to {site} could not be checked for sensitive data:\n"
            f"{why}.\n\nContinue  - send it anyway\nCancel    - stop it here"
        )
        allowed = confirm("Walled DLP Guard - file could not be checked", message)
        self._record(True)
        log.info("%s %s: unscannable (%s) -> user chose %s", site, what, why,
                 "CONTINUE" if allowed else "CANCEL")
        return {"decision": "allow" if allowed else "block", "found": False,
                "reason": "user chose Continue" if allowed else "file could not be checked - cancelled"}

    def _record(self, flagged: bool) -> None:
        if self.tray is not None:
            self.tray.record(flagged)


def _size(n: int) -> str:
    return f"{n / 1024 / 1024:.1f} MB" if n >= 1024 * 1024 else f"{max(1, n // 1024)} KB"


def main() -> int:
    stdin = sys.stdin.buffer
    out = sys.stdout.buffer
    sys.stdout = sys.stderr  # stray prints must never corrupt the native-messaging stream

    setup_logging()
    log.info("agent %s started by %s (OCR %s)", __version__, " ".join(sys.argv[1:2]) or "?",
             "available" if ocr_available() else "NOT installed")

    tray = None
    if not os.environ.get("WALLED_DLP_NO_TRAY"):
        try:
            from agent.tray import Tray

            tray = Tray(LOG_DIR / "agent.log")
            tray.start()
        except Exception as exc:
            log.warning("tray icon unavailable: %s", exc)

    agent = Agent(out, tray)
    try:
        while True:
            msg = read_message(stdin)
            if msg is None:
                break
            threading.Thread(target=agent.handle, args=(msg,), daemon=True).start()
    except ProtocolError as exc:
        log.error("protocol error: %s", exc)
        return 1
    finally:
        log.info("Chrome closed the connection; agent exiting")
        if tray is not None:
            tray.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
