"""Windows integration: local CA certificate, PAC file server, system proxy settings.

* The CA lets the app decrypt HTTPS for ChatGPT/Perplexity only. It is created locally and
  installed into the *current user's* trust store with certutil; Windows asks the user to
  confirm. Its private key never leaves %LOCALAPPDATA%\\WalledDLPGuard.
* A PAC (proxy auto-config) file served on 127.0.0.1 sends only the AI sites and their
  upload storage to the proxy; all other traffic goes DIRECT and is never touched.
* The previous proxy setting is saved and restored on exit (and on next start after a crash).
"""

import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

log = logging.getLogger("walled_dlp.system")

APP_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "WalledDLPGuard"
CA_CERT = APP_DIR / "mitmproxy-ca-cert.cer"
BACKUP = APP_DIR / "proxy-backup.json"
INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


# --------------------------------------------------------------------------- certificate

def ensure_ca() -> Path:
    """Create the local CA on first use (mitmproxy's CertStore writes it to APP_DIR)."""
    from mitmproxy.certs import CertStore

    APP_DIR.mkdir(parents=True, exist_ok=True)
    CertStore.from_store(APP_DIR, "mitmproxy", 2048)
    return CA_CERT


def ca_thumbprint() -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    cert = x509.load_der_x509_certificate(CA_CERT.read_bytes()) if CA_CERT.read_bytes()[:1] == b"0" \
        else x509.load_pem_x509_certificate(CA_CERT.read_bytes())
    return hashlib.sha1(cert.public_bytes(Encoding.DER)).hexdigest()


def ca_installed() -> bool:
    if not CA_CERT.exists():
        return False
    result = subprocess.run(["certutil", "-user", "-store", "Root", ca_thumbprint()],
                            capture_output=True, text=True)
    return result.returncode == 0


def install_ca() -> bool:
    ensure_ca()
    if ca_installed():
        print("Certificate already trusted.")
        return True
    print("Windows will ask you to confirm installing the Walled DLP Guard certificate (named 'mitmproxy').")
    result = subprocess.run(["certutil", "-user", "-addstore", "Root", str(CA_CERT)])
    return result.returncode == 0 and ca_installed()


def uninstall_ca() -> None:
    if CA_CERT.exists() and ca_installed():
        subprocess.run(["certutil", "-user", "-delstore", "Root", ca_thumbprint()])


# --------------------------------------------------------------------------- PAC server

def start_pac_server(port: int, script: str) -> ThreadingHTTPServer:
    body = script.encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, name="pac", daemon=True).start()
    return server


# --------------------------------------------------------------------------- system proxy

def _refresh_wininet() -> None:
    import ctypes

    wininet = ctypes.windll.wininet
    wininet.InternetSetOptionW(None, 39, None, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
    wininet.InternetSetOptionW(None, 37, None, 0)  # INTERNET_OPTION_REFRESH


def _read(name: str):
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS) as key:
        try:
            return winreg.QueryValueEx(key, name)[0]
        except FileNotFoundError:
            return None


def enable_pac(url: str) -> None:
    import winreg

    if not BACKUP.exists():  # keep the oldest backup if a previous run crashed
        BACKUP.parent.mkdir(parents=True, exist_ok=True)
        BACKUP.write_text(json.dumps({"AutoConfigURL": _read("AutoConfigURL")}), encoding="utf-8")
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, url)
    _refresh_wininet()
    log.info("system proxy: PAC %s", url)


def restore_proxy() -> None:
    if sys.platform != "win32" or not BACKUP.exists():
        return
    import winreg

    previous = json.loads(BACKUP.read_text(encoding="utf-8")).get("AutoConfigURL")
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE) as key:
        if previous:
            winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, previous)
        else:
            try:
                winreg.DeleteValue(key, "AutoConfigURL")
            except FileNotFoundError:
                pass
    _refresh_wininet()
    BACKUP.unlink()
    log.info("system proxy restored")


def pac_url(port: int) -> str:
    return f"http://127.0.0.1:{port}/walled-dlp.pac?v={int(time.time())}"
