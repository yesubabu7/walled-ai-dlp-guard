"""The proxy addon end to end on real mitmproxy flow objects (dialog answered by a fake)."""

import asyncio
import json
import threading
import time

from mitmproxy import http
from mitmproxy.test import tflow

from agent.dlp_proxy import DlpAddon


class FakeDialog:
    def __init__(self, answer=True, delay=0.0):
        self.answer, self.delay = answer, delay
        self.calls: list[tuple[str, str]] = []
        self._lock = threading.Lock()

    def __call__(self, title, message):
        with self._lock:
            self.calls.append((title, message))
        time.sleep(self.delay)
        return self.answer


def flow(method, url, body=b"", headers=None):
    req = http.Request.make(method, url, body, headers or {})
    return tflow.tflow(req=req)


def prompt_flow(text, url="https://chatgpt.com/backend-api/conversation"):
    body = json.dumps({"messages": [{"content": {"parts": [text]}}]}).encode()
    return flow("POST", url, body, {"content-type": "application/json"})


def run(coro):
    return asyncio.run(coro)


def test_clean_prompt_passes_without_dialog():
    dialog = FakeDialog(False)
    addon = DlpAddon(ask=dialog)
    f = prompt_flow("what is 2+2?")
    run(addon.request(f))
    assert f.response is None and dialog.calls == []


def test_sensitive_prompt_cancel_blocks():
    dialog = FakeDialog(False)
    addon = DlpAddon(ask=dialog)
    f = prompt_flow("Summarise this WALLED_SENSITIVE report")
    run(addon.request(f))
    assert f.response.status_code == 403
    assert "Blocked by Walled DLP Guard" in f.response.get_text()
    title, message = dialog.calls[0]
    assert "prompt" in title and "TEXT PROMPT" in message and "ChatGPT" in message
    assert 'Prompt: "Summarise this WALLED_SENSITIVE report"' in message


def test_sensitive_prompt_continue_forwards_unchanged():
    addon = DlpAddon(ask=FakeDialog(True))
    f = prompt_flow("Summarise this WALLED_SENSITIVE report")
    original = f.request.content
    run(addon.request(f))
    assert f.response is None and f.request.content == original


def test_perplexity_prompt():
    dialog = FakeDialog(False)
    addon = DlpAddon(ask=dialog)
    f = flow("POST", "https://www.perplexity.ai/rest/sse/perplexity_ask",
             json.dumps({"query_str": "note WALLED_SENSITIVE"}).encode(), {"content-type": "application/json"})
    run(addon.request(f))
    assert f.response.status_code == 403 and "Perplexity" in dialog.calls[0][1]


def test_concurrent_duplicates_share_one_dialog():
    dialog = FakeDialog(True, delay=0.3)
    addon = DlpAddon(ask=dialog)
    a, b = prompt_flow("x WALLED_SENSITIVE"), prompt_flow("x WALLED_SENSITIVE")

    async def both():
        await asyncio.gather(addon.request(a), addon.request(b))

    run(both())
    assert len(dialog.calls) == 1 and a.response is None and b.response is None


def test_retry_after_cancel_asks_again():
    dialog = FakeDialog(False)
    addon = DlpAddon(ask=dialog)
    now = [0.0]
    addon.decisions.clock = lambda: now[0]
    run(addon.request(prompt_flow("retry WALLED_SENSITIVE")))
    now[0] = 100.0  # user edits and resubmits later
    run(addon.request(prompt_flow("retry WALLED_SENSITIVE")))
    assert len(dialog.calls) == 2


def test_side_requests_follow_the_decision():
    dialog = FakeDialog(True, delay=0.3)
    addon = DlpAddon(ask=dialog)
    analytics = lambda: flow("POST", "https://www.perplexity.ai/rest/event/analytics",  # noqa: E731
                             b'{"query":"q WALLED_SENSITIVE"}', {"content-type": "application/json"})
    early = analytics()
    run(addon.request(early))
    assert early.response.status_code == 204 and dialog.calls == []  # dropped: no decision yet

    ask = flow("POST", "https://www.perplexity.ai/rest/sse/perplexity_ask",
               b'{"query_str":"q WALLED_SENSITIVE"}', {"content-type": "application/json"})
    during = analytics()

    async def together():
        await asyncio.gather(addon.request(ask), addon.request(during))

    run(together())
    assert ask.response is None and during.response is None  # waited for, then followed, Continue
    assert len(dialog.calls) == 1


def multipart(name, content, ctype):
    boundary = "b0und"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
            f"Content-Type: {ctype}\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def test_sensitive_pdf_upload_cancel(samples):
    dialog = FakeDialog(False)
    addon = DlpAddon(ask=dialog)
    body, ctype = multipart("secret_report.pdf", (samples / "secret_report.pdf").read_bytes(), "application/pdf")
    f = flow("POST", "https://ppl-ai-file-upload.s3.amazonaws.com/", body,
             {"content-type": ctype, "origin": "https://www.perplexity.ai"})
    run(addon.request(f))
    assert f.response.status_code == 403
    title, message = dialog.calls[0]
    assert "file" in title and "FILE" in message and "secret_report.pdf" in message and "page 1 text" in message


def test_clean_file_uploads_without_dialog(samples):
    dialog = FakeDialog(False)
    addon = DlpAddon(ask=dialog)
    body, ctype = multipart("clean_report.pdf", (samples / "clean_report.pdf").read_bytes(), "application/pdf")
    f = flow("POST", "https://ppl-ai-file-upload.s3.amazonaws.com/", body, {"content-type": ctype})
    run(addon.request(f))
    assert f.response is None and dialog.calls == []


def test_image_upload_ocr(samples):
    dialog = FakeDialog(True)
    addon = DlpAddon(ask=dialog)
    f = flow("PUT", "https://files.oaiusercontent.com/file-xyz?sig=1",
             (samples / "secret_screenshot.png").read_bytes(), {"content-type": "image/png", "origin": "https://chatgpt.com"})
    run(addon.request(f))
    assert f.response is None and "OCR" in dialog.calls[0][1] and "ChatGPT" in dialog.calls[0][1]


def test_learned_upload_host_and_file_name(samples):
    dialog = FakeDialog(False)
    addon = DlpAddon(ask=dialog)
    create = flow("POST", "https://chatgpt.com/backend-api/files",
                  json.dumps({"file_name": "secret_note.txt", "file_size": 113}).encode(),
                  {"content-type": "application/json"})
    create.response = http.Response.make(
        200, json.dumps({"upload_url": "https://sdmntpr.blob.core.windows.net/files/abc?sig=1"}),
        {"content-type": "application/json"})
    addon.response(create)
    assert addon.should_intercept("sdmntpr.blob.core.windows.net")
    assert not addon.should_intercept("example.blob.core.windows.net")

    put = flow("PUT", "https://sdmntpr.blob.core.windows.net/files/abc?sig=1",
               (samples / "secret_note.txt").read_bytes(), {"content-type": "text/plain"})
    run(addon.request(put))
    assert put.response.status_code == 403
    assert "secret_note.txt" in dialog.calls[0][1] and "ChatGPT" in dialog.calls[0][1]


def test_file_name_from_announcement_when_url_hides_it(samples):
    """ChatGPT uploads to .../raw; the real name comes from the size it announced."""
    dialog = FakeDialog(False)
    addon = DlpAddon(ask=dialog)
    note = (samples / "secret_note.txt").read_bytes()
    create = flow("POST", "https://chatgpt.com/backend-api/files",
                  json.dumps({"file_name": "secret_note.txt", "file_size": len(note), "use_case": "my_files"}).encode(),
                  {"content-type": "application/json"})
    create.response = http.Response.make(
        200, json.dumps({"file_id": "file_1", "upload_url": "https://sdmntprindia.oaiusercontent.com/files/file_1?sig=1"}),
        {"content-type": "application/json"})
    addon.response(create)

    put = flow("PUT", "https://sdmntprindia.oaiusercontent.com/files/file_1/raw?sv=1", note,
               {"content-type": "text/plain", "origin": "https://chatgpt.com"})
    run(addon.request(put))
    assert put.response.status_code == 403
    assert "File: secret_note.txt" in dialog.calls[0][1]


def test_other_sites_never_inspected():
    dialog = FakeDialog(False)
    addon = DlpAddon(ask=dialog)
    f = flow("POST", "https://example.com/api", b"WALLED_SENSITIVE", {"content-type": "text/plain"})
    run(addon.request(f))
    assert f.response is None and dialog.calls == []
    assert not addon.should_intercept("example.com") and addon.should_intercept("chatgpt.com")


def html_flow(url, html, headers=None):
    f = flow("GET", url)
    f.response = http.Response.make(200, html, {"content-type": "text/html; charset=utf-8", **(headers or {})})
    return f


def test_html_recoloured():
    addon = DlpAddon(color="#00aa00")
    f = html_flow("https://chatgpt.com/", "<html><head></head><body></body></html>")
    addon.responseheaders(f)
    assert not f.response.stream
    addon.response(f)
    text = f.response.get_text()
    assert 'id="walled-dlp-style"' in text and "#00aa00" in text


def test_csp_without_unsafe_inline_gets_nonce():
    addon = DlpAddon()
    f = html_flow("https://www.perplexity.ai/", "<html><head></head></html>",
                  {"content-security-policy": "default-src 'self'; style-src 'self'"})
    addon.response(f)
    csp = f.response.headers["content-security-policy"]
    nonce = csp.split("'nonce-")[1].split("'")[0]
    assert f'nonce="{nonce}"' in f.response.get_text()


def test_streamed_answers_not_buffered():
    addon = DlpAddon()
    f = flow("POST", "https://www.perplexity.ai/rest/sse/perplexity_ask")
    f.response = http.Response.make(200, b"", {"content-type": "text/event-stream"})
    addon.responseheaders(f)
    assert f.response.stream


def test_websocket_typing_suggestions_dropped():
    addon = DlpAddon(ask=FakeDialog(True))
    f = tflow.twebsocketflow()
    f.request.host = "suggest.perplexity.ai"
    f.websocket.messages[-1].from_client = True
    f.websocket.messages[-1].content = b'{"q":"WALLED_SENSITIVE draft"}'
    addon.websocket_message(f)
    assert f.websocket.messages[-1].dropped
