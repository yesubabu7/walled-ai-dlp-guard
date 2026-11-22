"""mitmproxy addon: the enforcement point of Walled DLP Guard.

For ChatGPT / Perplexity (and their file-storage hosts) every outgoing request is held
while it is inspected:

  * prompt submissions containing WALLED_SENSITIVE  -> native dialog; Continue forwards the
    original request unchanged, Cancel answers it with 403 so nothing reaches the site
  * file uploads (multipart parts, raw PUT/POST bodies) -> scanned (text / PDF / OCR); dialog
    if the marker is found
  * other requests carrying the marker (analytics, search suggestions, WebSocket typing
    suggestions) never get their own dialog: they follow the user's decision for that prompt,
    and are dropped while no decision exists (so the text cannot leak before the user decides)
  * HTML pages of both apps get a <style> that recolours AI answers

TLS is only decrypted for those hosts; everything else is tunnelled untouched.
"""

import asyncio
import hashlib
import json
import logging
import re
import secrets
import time
from typing import Awaitable, Callable

from mitmproxy import http, tls

from agent.dialog import confirm
from agent.policy import (
    UPLOAD_HOSTS,
    Site,
    UploadedFile,
    announced_file,
    inject_style,
    inspect_request,
    learn_upload_targets,
    prompt_text,
    response_css,
    site_by_key,
    site_for,
)
from agent.scanner import MARKER, contains_marker, normalize, scan_file

log = logging.getLogger("walled_dlp.proxy")

ALLOW_GRANT_S = 30.0     # after Continue: related follow-up requests pass without asking
BLOCK_MEMORY_S = 4.0     # after Cancel: duplicates of the same request are blocked silently
MAX_SCAN_BYTES = 40 * 1024 * 1024


def _size(n: int) -> str:
    return f"{n / 1024 / 1024:.1f} MB" if n >= 1024 * 1024 else f"{max(1, n // 1024)} KB"


class Decisions:
    """One dialog per prompt/file: concurrent and repeated requests share a single answer."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self.dialog_lock = asyncio.Lock()          # dialogs are shown one at a time
        self._pending: dict[tuple, asyncio.Future] = {}
        self._recent: dict[tuple, tuple[bool, float]] = {}
        self._site_grant: dict[str, float] = {}
        self._site_pending: dict[str, asyncio.Future] = {}

    async def decide(self, key: tuple, site_key: str, compute: Callable[[], Awaitable[bool]],
                     grants_site: bool = True) -> bool:
        now = self.clock()
        if key in self._recent:
            allowed, at = self._recent[key]
            if now - at < (ALLOW_GRANT_S if allowed else BLOCK_MEMORY_S):
                return allowed
        if key in self._pending:
            return await asyncio.shield(self._pending[key])

        future = asyncio.get_running_loop().create_future()
        self._pending[key] = future
        self._site_pending[site_key] = future
        try:
            allowed = await compute()
        except Exception:
            log.exception("decision failed for %s; blocking", key[0])
            allowed = False
        finally:
            self._pending.pop(key, None)
            if self._site_pending.get(site_key) is future:
                self._site_pending.pop(site_key, None)
        self._recent[key] = (allowed, self.clock())
        if allowed and grants_site:
            self._site_grant[site_key] = self.clock() + ALLOW_GRANT_S
        if not future.done():
            future.set_result(allowed)
        return allowed

    def granted(self, site_key: str) -> bool:
        return self._site_grant.get(site_key, 0) > self.clock()

    async def follow(self, site_key: str) -> bool:
        """Decision for a side request (analytics, suggestions) that carries the marker."""
        if self.granted(site_key):
            return True
        pending = self._site_pending.get(site_key)
        if pending is not None:
            return await asyncio.shield(pending)
        return False


class DlpAddon:
    def __init__(self, color: str = "#f97316", ask: Callable[[str, str], bool] = confirm,
                 on_check: Callable[[bool], None] | None = None):
        self.color = color
        self.ask = ask
        self.on_check = on_check
        self.decisions = Decisions()
        self.learned_hosts: dict[str, str] = {}   # storage host -> site key
        self.upload_names: dict[str, str] = {}    # host+path -> original file name
        self.announced: list[tuple[str, str, int | None, float]] = []  # (site, name, size, when)

    # ------------------------------------------------------------------ which traffic

    def _upload_site(self, host: str, flow: http.HTTPFlow) -> Site | None:
        """For file-storage hosts: the chat app the upload belongs to (None for other hosts)."""
        if host in self.learned_hosts:
            return site_by_key(self.learned_hosts[host])
        if not UPLOAD_HOSTS.search(host):
            return None
        origin = flow.request.headers.get("origin") or flow.request.headers.get("referer", "")
        match = re.match(r"https?://([^/:]+)", origin)
        return (match and site_for(match.group(1))) or site_by_key("perplexity" if "ppl-ai" in host else "chatgpt")

    def should_intercept(self, host: str) -> bool:
        host = (host or "").lower()
        return bool(site_for(host) or UPLOAD_HOSTS.search(host) or host in self.learned_hosts)

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        host = data.client_hello.sni or (data.context.server.address or ("",))[0]
        if not self.should_intercept(host):
            data.ignore_connection = True  # tunnel untouched, never decrypted

    # ------------------------------------------------------------------ requests

    async def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        host = req.pretty_host.lower()
        upload_site = self._upload_site(host, flow)
        site = upload_site or site_for(host)
        if site is None or req.method in ("GET", "HEAD", "OPTIONS"):
            return

        body = req.get_content(strict=False) or b""
        name = self.upload_names.get(f"{host}{req.path.split('?', 1)[0]}")
        if name is None and upload_site is not None:
            name = self._announced_name(site.key, len(body))
        payload = inspect_request(host, req.path, req.method, req.headers.get("content-type", ""),
                                  body, is_upload_host=upload_site is not None, file_name=name)

        for upload in payload.files:
            if not await self._check_file(site, upload):
                self._block(flow, f"{MARKER} detected in file {upload.name!r} - upload cancelled by the user")
                return

        if not payload.has_marker:
            return
        if site.submit.search(req.path):
            prompt = prompt_text(payload)
            if not await self._check_prompt(site, prompt):
                self._block(flow, f"{MARKER} detected in your prompt - you chose Cancel. Edit the prompt and try again.")
        elif not await self.decisions.follow(site.key):
            log.info("%s: dropped side request %s %s (marker, no Continue yet)", site.name, req.method, req.path.split("?")[0])
            flow.response = http.Response.make(204)

    async def _check_prompt(self, site: Site, prompt: str) -> bool:
        async def compute() -> bool:
            message = (
                f"{MARKER} was detected in a TEXT PROMPT you are about to send to {site.name}.\n\n"
                f'Prompt: "{prompt}"\n\n'
                "Continue  - send the prompt\n"
                "Cancel    - block it (nothing is sent)"
            )
            async with self.decisions.dialog_lock:
                allowed = await asyncio.to_thread(self.ask, "Walled DLP Guard - sensitive prompt detected", message)
            log.info("%s prompt: marker found -> user chose %s", site.name, "CONTINUE" if allowed else "CANCEL")
            self._count(True)
            return allowed

        return await self.decisions.decide(("prompt", site.key, normalize(prompt)), site.key, compute)

    async def _check_file(self, site: Site, upload: UploadedFile) -> bool:
        digest = hashlib.sha256(upload.data).hexdigest()

        async def compute() -> bool:
            label = f"{upload.name} ({_size(len(upload.data))})"
            if len(upload.data) > MAX_SCAN_BYTES:
                return await self._ask_file(site, label, None, f"it is larger than {_size(MAX_SCAN_BYTES)}")
            result = await asyncio.to_thread(scan_file, upload.name, upload.content_type, upload.data)
            if result.found:
                return await self._ask_file(site, label, result, None)
            if not result.scanned and result.kind in ("pdf", "image"):
                return await self._ask_file(site, label, None, result.note)
            log.info("%s file %r: clean (%s)", site.name, upload.name, result.kind)
            self._count(False)
            return True

        return await self.decisions.decide(("file", site.key, digest), site.key, compute, grants_site=False)

    async def _ask_file(self, site: Site, label: str, result, problem: str | None) -> bool:
        if result is not None:
            where = f"\nFound in: {result.where}" if result.where else ""
            context = f'\nContext: "{result.snippet}"' if result.snippet else ""
            title = "Walled DLP Guard - sensitive file detected"
            body = f"{MARKER} was detected in a FILE you are about to upload to {site.name}.\n\nFile: {label}{where}{context}"
        else:
            title = "Walled DLP Guard - file could not be checked"
            body = f"A FILE you are about to upload to {site.name} could not be checked:\n\nFile: {label}\nReason: {problem}."
        message = body + "\n\nContinue  - upload the file\nCancel    - block the upload (nothing is sent)"
        async with self.decisions.dialog_lock:
            allowed = await asyncio.to_thread(self.ask, title, message)
        log.info("%s file %s: %s -> user chose %s", site.name, label,
                 "marker found" if result is not None else f"unscannable ({problem})",
                 "CONTINUE" if allowed else "CANCEL")
        self._count(True)
        return allowed

    def _announced_name(self, site_key: str, size: int) -> str | None:
        """Name for an upload whose URL doesn't reveal it: the file the site announced with this size."""
        recent = [a for a in self.announced if a[0] == site_key and time.monotonic() - a[3] < 300]
        same_size = [a for a in recent if a[2] == size]
        match = (same_size or recent)[-1:] or []
        return match[0][1] if match else None

    @staticmethod
    def _block(flow: http.HTTPFlow, reason: str) -> None:
        # Sites show either "detail" or "error" from an error body, so both carry the message.
        message = f"Blocked by Walled DLP Guard: {reason}"
        flow.response = http.Response.make(
            403,
            json.dumps({"detail": message, "error": message, "message": message}),
            {"content-type": "application/json", "cache-control": "no-store"},
        )

    def _count(self, flagged: bool) -> None:
        if self.on_check is not None:
            self.on_check(flagged)

    # ------------------------------------------------------------------ responses

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        if self._wants_body(flow):
            return
        flow.response.stream = True  # keep streamed answers (SSE) live; nothing to change

    def _wants_body(self, flow: http.HTTPFlow) -> bool:
        host = flow.request.pretty_host.lower()
        site = site_for(host)
        if site is None or flow.response is None:
            return False
        ctype = flow.response.headers.get("content-type", "")
        if site.pages.search(host) and "text/html" in ctype:
            return True
        return flow.request.method == "POST" and "json" in ctype and bool(re.search(r"upload|file", flow.request.path, re.I))

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or flow.response.stream:
            return
        host = flow.request.pretty_host.lower()
        site = site_for(host)
        if site is None:
            return
        ctype = flow.response.headers.get("content-type", "")
        if site.pages.search(host) and "text/html" in ctype and flow.response.status_code == 200:
            self._recolour(flow, site)
        elif "json" in ctype:
            request_body = flow.request.get_content(strict=False) or b""
            name, size = announced_file(request_body)
            if name:
                self.announced = [a for a in self.announced if time.monotonic() - a[3] < 300][-20:]
                self.announced.append((site.key, name, size, time.monotonic()))
            hosts, names = learn_upload_targets(request_body, flow.response.get_content(strict=False) or b"")
            for h in hosts:
                if h not in self.learned_hosts:
                    log.info("%s: learned upload host %s", site.name, h)
                self.learned_hosts[h] = site.key
            self.upload_names.update(names)

    def _recolour(self, flow: http.HTTPFlow, site: Site) -> None:
        html = flow.response.get_text(strict=False)
        if not html:
            return
        css = response_css(site, self.color)
        nonce = _allow_inline_style(flow.response)
        tagged = inject_style(html, css)
        if nonce:
            tagged = tagged.replace('<style id="walled-dlp-style">', f'<style id="walled-dlp-style" nonce="{nonce}">', 1)
        flow.response.set_text(tagged)

    # ------------------------------------------------------------------ WebSockets

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        site = site_for(flow.request.pretty_host)
        message = flow.websocket.messages[-1] if flow.websocket else None
        if site is None or message is None or not message.from_client:
            return
        text = message.content.decode("utf-8", errors="ignore")
        if contains_marker(text) and not self.decisions.granted(site.key):
            message.drop()  # e.g. Perplexity's live typing suggestions
            log.info("%s: dropped WebSocket message carrying the marker", site.name)


def _allow_inline_style(response: http.Response) -> str | None:
    """If the page's CSP forbids inline <style>, allow ours with a nonce. Returns the nonce."""
    csp = response.headers.get("content-security-policy")
    if not csp:
        return None
    directives = [d.strip() for d in csp.split(";") if d.strip()]
    names = [d.split()[0].lower() for d in directives]
    target = "style-src-elem" if "style-src-elem" in names else "style-src" if "style-src" in names else \
        "default-src" if "default-src" in names else None
    if target is None:
        return None
    index = names.index(target)
    if "'unsafe-inline'" in directives[index]:
        return None
    nonce = secrets.token_urlsafe(16)
    if target == "default-src":
        directives.append(f"style-src {directives[index].split(None, 1)[1] if ' ' in directives[index] else ''} 'nonce-{nonce}'")
    else:
        directives[index] += f" 'nonce-{nonce}'"
    response.headers["content-security-policy"] = "; ".join(directives)
    return nonce
