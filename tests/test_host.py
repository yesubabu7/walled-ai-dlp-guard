"""End-to-end tests of the native messaging host (dialog answered via WALLED_DLP_AUTO_DECISION)."""

import base64
import struct
import sys

import pytest

from agent.protocol import ProtocolError, encode_message, read_message
from conftest import ROOT


def b64(path) -> str:
    return base64.b64encode(path.read_bytes()).decode()


def test_protocol_roundtrip():
    import io

    msg = {"id": 1, "text": "héllo ✓"}
    assert read_message(io.BytesIO(encode_message(msg))) == msg
    assert read_message(io.BytesIO(b"")) is None
    with pytest.raises(ProtocolError):
        read_message(io.BytesIO(struct.pack("<I", 10) + b"{}"))


def test_ping(host):
    h = host()
    h.send({"id": 1, "type": "ping"})
    reply = h.recv()
    assert reply["id"] == 1 and reply["decision"] == "allow" and "version" in reply
    assert h.close() == 0


def test_clean_prompt_is_allowed_without_asking(host):
    h = host("cancel")  # would block if a dialog were shown
    h.send({"id": 2, "type": "check_text", "site": "chatgpt", "text": "What is 2+2?"})
    assert h.recv() == {"id": 2, "decision": "allow", "found": False}


@pytest.mark.parametrize("choice, decision", [("continue", "allow"), ("cancel", "block")])
def test_sensitive_prompt_follows_user_choice(host, choice, decision):
    h = host(choice)
    h.send({"id": 3, "type": "check_text", "site": "perplexity", "text": "summarise WALLED_SENSITIVE notes"})
    reply = h.recv()
    assert reply["decision"] == decision and reply["found"] is True


@pytest.mark.parametrize("name, found", [
    ("secret_report.pdf", True), ("clean_report.pdf", False), ("secret_note.txt", True),
])
def test_file_checks(host, samples, name, found):
    h = host("cancel")
    h.send({"id": 4, "type": "check_file", "site": "chatgpt", "name": name, "data": b64(samples / name)})
    reply = h.recv()
    assert reply["found"] is found
    assert reply["decision"] == ("block" if found else "allow")


def test_oversized_file_asks_user(host):
    h = host("cancel")
    h.send({"id": 5, "type": "check_file", "site": "chatgpt", "name": "huge.zip", "size": 500_000_000})
    assert h.recv()["decision"] == "block"


def test_bad_input_fails_closed(host):
    h = host("continue")
    h.send({"id": 6, "type": "check_file", "name": "x", "data": "@@not-base64@@"})
    h.send({"id": 7, "type": "launch_missiles"})
    replies = {r["id"]: r for r in (h.recv(), h.recv())}
    assert replies[6]["decision"] == "block" and replies[7]["decision"] == "block"


def test_concurrent_requests_answered_by_id(host, samples):
    h = host("continue")
    h.send({"id": 10, "type": "check_file", "name": "s.pdf", "data": b64(samples / "secret_scanned.pdf")})
    h.send({"id": 11, "type": "ping"})
    first, second = h.recv(), h.recv()
    assert first["id"] == 11, "a slow OCR check must not hold up other requests"
    assert second["id"] == 10 and second["decision"] == "allow"


@pytest.mark.skipif(sys.platform != "win32" or not (ROOT / "native" / "walled_dlp_host.bat").exists(),
                    reason="launcher is created by scripts/install.py on Windows")
def test_chrome_launcher_bat_speaks_clean_protocol(host):
    """Chrome starts the .bat; any stray output (e.g. echo) would corrupt the first message."""
    h = host("cancel", ["cmd", "/c", str(ROOT / "native" / "walled_dlp_host.bat"), "chrome-extension://x/"])
    h.send({"id": 1, "type": "ping"})
    assert h.recv()["id"] == 1
