"""Pure inspection logic for the proxy: which hosts to inspect, what a request carries, CSS injection.

Kept free of mitmproxy objects so it is easy to unit-test.
"""

import json
import re
from dataclasses import dataclass, field
from email.parser import BytesParser
from email.policy import HTTP
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from agent.scanner import contains_marker

# --------------------------------------------------------------------------- sites


@dataclass(frozen=True)
class Site:
    key: str
    name: str
    hosts: re.Pattern        # hosts whose HTTPS traffic is decrypted and inspected
    pages: re.Pattern        # hosts that serve the app's HTML (for response recolouring)
    submit: re.Pattern       # request paths that submit a prompt
    response_css: tuple[str, ...]  # selectors of AI-generated answer containers


SITES = (
    Site(
        key="chatgpt",
        name="ChatGPT",
        hosts=re.compile(r"(^|\.)(chatgpt\.com|chat\.openai\.com)$"),
        pages=re.compile(r"^(chatgpt\.com|chat\.openai\.com)$"),
        # /backend-api/conversation, /backend-api/f/conversation, /unauth-mweb/conversation/updates ...
        submit=re.compile(r"/conversation($|[/?])"),
        response_css=(
            "[data-dil-response]",
            '[data-message-author-role="assistant"]',
            "[data-assistant-markdown-root]",
        ),
    ),
    Site(
        key="perplexity",
        name="Perplexity",
        hosts=re.compile(r"(^|\.)perplexity\.ai$"),
        pages=re.compile(r"^(www\.)?perplexity\.ai$"),
        submit=re.compile(r"perplexity_ask|/rest/sse/"),
        # The user's own question also uses data-renderer="lm", inside a message bubble.
        response_css=('[data-renderer="lm"]:not([data-message-bubble] *)', '[id^="markdown-content"]'),
    ),
)

# File content is uploaded to object storage, not to the chat host itself. These hosts are
# decrypted too; others are learned at runtime from the sites' "create upload" responses.
UPLOAD_HOSTS = re.compile(r"(^|\.)(oaiusercontent\.com|ppl-ai-file-upload\.s3\.amazonaws\.com)$")

# Hosts routed to the proxy by the PAC file (everything else goes DIRECT and is never seen).
PAC_DOMAINS = (
    "chatgpt.com", "chat.openai.com", "oaiusercontent.com", "perplexity.ai",
    "blob.core.windows.net", "amazonaws.com",
)


def site_for(host: str) -> Site | None:
    host = host.lower().rstrip(".")
    return next((s for s in SITES if s.hosts.search(host)), None)


def site_by_key(key: str) -> Site:
    return next(s for s in SITES if s.key == key)


def pac_script(port: int) -> str:
    checks = " ||\n      ".join(
        f'host == "{d}" || dnsDomainIs(host, ".{d}")' for d in PAC_DOMAINS
    )
    return (
        "function FindProxyForURL(url, host) {\n"
        f"  if ({checks})\n"
        f'    return "PROXY 127.0.0.1:{port}";\n'
        '  return "DIRECT";\n'
        "}\n"
    )


# --------------------------------------------------------------------------- request bodies

TEXT_TYPES = re.compile(r"json|text/|x-www-form-urlencoded|javascript|xml|graphql", re.I)
FILE_TYPES = re.compile(r"^(image/|application/pdf|application/octet-stream|application/vnd|application/msword|video/|audio/)", re.I)


@dataclass
class UploadedFile:
    name: str
    content_type: str
    data: bytes


@dataclass
class Payload:
    text: str = ""                                  # all textual content, decoded
    files: list[UploadedFile] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)  # individual string values (JSON/form fields)

    @property
    def has_marker(self) -> bool:
        return contains_marker(self.text)


def _strings(value, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
        stripped = value.strip()
        if stripped[:1] in "{[":  # JSON nested inside a string field
            try:
                _strings(json.loads(stripped), out)
            except ValueError:
                pass
    elif isinstance(value, dict):
        for v in value.values():
            _strings(v, out)
    elif isinstance(value, list):
        for v in value:
            _strings(v, out)


def decode_text(body: bytes, content_type: str) -> tuple[str, list[str]]:
    """Decoded body text plus its individual string values (JSON fields, form fields)."""
    text = body.decode("utf-8", errors="ignore")
    parts: list[str] = []
    if "x-www-form-urlencoded" in content_type.lower():
        for _k, v in parse_qsl(text, keep_blank_values=True):
            _strings(v, parts)
        return "\n".join(parts), parts
    try:
        _strings(json.loads(text), parts)
    except ValueError:
        parts = [text]
    return text, parts


def parse_multipart(body: bytes, content_type: str) -> tuple[str, list[UploadedFile]]:
    message = BytesParser(policy=HTTP).parsebytes(
        b"Content-Type: " + content_type.encode("latin-1", "ignore") + b"\r\n\r\n" + body
    )
    texts: list[str] = []
    files: list[UploadedFile] = []
    if not message.is_multipart():
        return "", files
    for part in message.iter_parts():
        data = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        if filename:
            files.append(UploadedFile(filename, part.get_content_type(), data))
        else:
            texts.append(data.decode("utf-8", errors="ignore"))
    return "\n".join(texts), files


def inspect_request(host: str, path: str, method: str, content_type: str, body: bytes,
                    is_upload_host: bool, file_name: str | None = None) -> Payload:
    """Split an outgoing request body into text (checked for the marker) and files (scanned)."""
    if not body or method.upper() in ("GET", "HEAD", "OPTIONS"):
        return Payload()
    ctype = content_type.lower()
    if "multipart/form-data" in ctype:
        text, files = parse_multipart(body, content_type)
        return Payload(text, files)
    if is_upload_host or FILE_TYPES.search(ctype) or (not TEXT_TYPES.search(ctype) and _binary(body)):
        name = file_name or unquote_plus(urlsplit(path).path.rsplit("/", 1)[-1]) or "uploaded file"
        return Payload("", [UploadedFile(name, content_type, body)])
    text, strings = decode_text(body, content_type)
    return Payload(text, strings=strings)


def _binary(body: bytes) -> bool:
    sample = body[:2048]
    return b"\x00" in sample


def prompt_text(payload: "Payload", limit: int = 300) -> str:
    """The user's prompt, for the dialog: the shortest string value that carries the marker."""
    hits = [s for s in payload.strings if contains_marker(s)] or [payload.text]
    best = " ".join(min(hits, key=len).split())
    return best if len(best) <= limit else best[: limit - 3] + "..."


# --------------------------------------------------------------------------- upload URL learning

URL_RE = re.compile(r"https://([A-Za-z0-9.-]+)(/[^\"'\\\s?]*)?")
NAME_KEYS = ("file_name", "filename", "fileName", "name")
SIZE_KEYS = ("file_size", "fileSize", "size", "content_length", "file_size_bytes")


def announced_file(request_body: bytes) -> tuple[str | None, int | None]:
    """The (file name, size) a site announces when it asks for an upload URL, searched anywhere in the JSON."""
    try:
        data = json.loads(request_body or b"{}")
    except ValueError:
        return None, None
    stack = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            name = next((node[k] for k in NAME_KEYS if isinstance(node.get(k), str) and "." in node[k]), None)
            if name:
                size = next((node[k] for k in SIZE_KEYS if isinstance(node.get(k), int)), None)
                return name, size
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return None, None


def learn_upload_targets(request_body: bytes, response_body: bytes) -> tuple[set[str], dict[str, str]]:
    """From a site's 'create upload' exchange, the storage hosts and URL-path -> file name."""
    name, _size = announced_file(request_body)
    hosts: set[str] = set()
    names: dict[str, str] = {}
    for host, path in URL_RE.findall(response_body.decode("utf-8", errors="ignore")):
        host = host.lower()
        if site_for(host):
            continue
        hosts.add(host)
        if name:
            names[f"{host}{path or '/'}"] = name
    return hosts, names


# --------------------------------------------------------------------------- response recolouring

def response_css(site: Site, color: str) -> str:
    scope = ",\n".join(f"{s}, {s} *" for s in site.response_css)
    return (
        f"{scope} {{\n"
        f"  color: {color} !important;\n"
        # ChatGPT's streaming renderer colours text through these inline CSS variables
        f"  --d-stream-ink: {color} !important;\n"
        f"  --d-stream-enter-ink: {color} !important;\n"
        "}\n"
    )


def inject_style(html: str, css: str) -> str:
    if 'id="walled-dlp-style"' in html:
        return html
    tag = f'<style id="walled-dlp-style">{css}</style>'
    match = re.search(r"</head\s*>", html, re.I)
    if match:
        return html[: match.start()] + tag + html[match.start():]
    match = re.search(r"<body[^>]*>", html, re.I)
    if match:
        return html[: match.end()] + tag + html[match.end():]
    return tag + html
