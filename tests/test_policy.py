import json

from agent.policy import (
    inject_style,
    inspect_request,
    learn_upload_targets,
    pac_script,
    prompt_text,
    response_css,
    site_by_key,
    site_for,
)


def test_sites_and_hosts():
    assert site_for("chatgpt.com").key == "chatgpt"
    assert site_for("ab.chatgpt.com").key == "chatgpt"
    assert site_for("www.perplexity.ai").key == "perplexity"
    assert site_for("suggest.perplexity.ai").key == "perplexity"
    assert site_for("example.com") is None
    assert site_for("notchatgpt.com") is None


def test_submit_paths():
    chatgpt, pplx = site_by_key("chatgpt"), site_by_key("perplexity")
    assert chatgpt.submit.search("/backend-api/conversation")
    assert chatgpt.submit.search("/backend-api/f/conversation")
    assert chatgpt.submit.search("/unauth-mweb/conversation/updates?x=1")
    assert not chatgpt.submit.search("/backend-api/conversations?offset=0")
    assert pplx.submit.search("/rest/sse/perplexity_ask")
    assert not pplx.submit.search("/rest/event/analytics")


def test_pac_routes_only_ai_and_storage_hosts():
    pac = pac_script(8899)
    assert '"PROXY 127.0.0.1:8899"' in pac and '"DIRECT"' in pac
    for host in ("chatgpt.com", "perplexity.ai", "oaiusercontent.com", "amazonaws.com"):
        assert host in pac


def test_json_prompt_text_extracted():
    body = json.dumps({"messages": [{"content": {"parts": ["Summarise this WALLED_SENSITIVE report"]}}],
                       "model": "auto"}).encode()
    payload = inspect_request("chatgpt.com", "/backend-api/conversation", "POST", "application/json", body, False)
    assert payload.has_marker and not payload.files
    assert prompt_text(payload) == "Summarise this WALLED_SENSITIVE report"


def test_form_urlencoded_with_nested_json():
    inner = json.dumps({"parts": ["hello walled_sensitive"]})
    body = f"payload={inner}&x=1".encode()
    payload = inspect_request("chatgpt.com", "/x/conversation/updates", "POST",
                              "application/x-www-form-urlencoded", body, False)
    assert payload.has_marker
    assert prompt_text(payload) == "hello walled_sensitive"


def test_clean_request_has_no_marker():
    payload = inspect_request("chatgpt.com", "/backend-api/conversation", "POST", "application/json",
                              b'{"q":"what is 2+2"}', False)
    assert not payload.has_marker and not payload.files


def test_get_requests_ignored():
    assert not inspect_request("chatgpt.com", "/?q=WALLED_SENSITIVE", "GET", "", b"", False).has_marker


def test_multipart_upload_parsed(samples):
    pdf = (samples / "secret_report.pdf").read_bytes()
    boundary = "XyZ"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nuploads/abc\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"secret_report.pdf\"\r\n"
        f"Content-Type: application/pdf\r\n\r\n"
    ).encode() + pdf + f"\r\n--{boundary}--\r\n".encode()
    payload = inspect_request("ppl-ai-file-upload.s3.amazonaws.com", "/", "POST",
                              f"multipart/form-data; boundary={boundary}", body, True)
    assert [f.name for f in payload.files] == ["secret_report.pdf"]
    assert payload.files[0].data == pdf


def test_raw_put_to_storage_is_a_file():
    payload = inspect_request("files.oaiusercontent.com", "/file-abc?sig=1", "PUT", "text/plain",
                              b"note WALLED_SENSITIVE", True, file_name="secret_note.txt")
    assert payload.files[0].name == "secret_note.txt" and not payload.text


def test_binary_body_on_site_is_a_file():
    payload = inspect_request("chatgpt.com", "/backend-api/files/upload", "POST", "image/png",
                              b"\x89PNG\r\n\x1a\n\x00\x00", False)
    assert payload.files and payload.files[0].content_type == "image/png"


def test_learn_upload_targets():
    hosts, names = learn_upload_targets(
        json.dumps({"file_name": "secret_note.txt", "file_size": 113}).encode(),
        json.dumps({"upload_url": "https://sdmntpr.blob.core.windows.net/files/abc?sv=1&sig=x",
                    "status": "success"}).encode(),
    )
    assert hosts == {"sdmntpr.blob.core.windows.net"}
    assert names == {"sdmntpr.blob.core.windows.net/files/abc": "secret_note.txt"}


def test_learn_ignores_site_urls():
    hosts, _ = learn_upload_targets(b"{}", b'{"link": "https://chatgpt.com/c/123"}')
    assert hosts == set()


def test_css_injection():
    css = response_css(site_by_key("chatgpt"), "#123456")
    assert "[data-dil-response]" in css and "#123456 !important" in css and "--d-stream-ink" in css
    html = "<html><head><title>x</title></head><body>hi</body></html>"
    out = inject_style(html, css)
    assert out.index('id="walled-dlp-style"') < out.index("</head>")
    assert inject_style(out, css) == out  # idempotent


def test_perplexity_css_excludes_user_bubble():
    css = response_css(site_by_key("perplexity"), "#f97316")
    assert ':not([data-message-bubble] *)' in css
