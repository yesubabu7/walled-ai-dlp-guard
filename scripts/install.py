"""Register the Walled DLP desktop agent with Chrome (and Edge) as a native messaging host.

    python scripts/install.py            # register for the current Windows user
    python scripts/install.py --uninstall

Creates native/walled_dlp_host.bat (launches agent/host.py with this venv's Python) and
native/com.walled.dlp_guard.json (the host manifest), then points the per-user registry key
HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.walled.dlp_guard at it.
Only the extension with our fixed ID may connect (allowed_origins).
"""

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOST_NAME = "com.walled.dlp_guard"
NATIVE_DIR = ROOT / "native"
BROWSER_KEYS = {
    "Chrome": rf"Software\Google\Chrome\NativeMessagingHosts\{HOST_NAME}",
    "Edge": rf"Software\Microsoft\Edge\NativeMessagingHosts\{HOST_NAME}",
}


def extension_id() -> str:
    """Chrome derives an extension's ID from the public key in its manifest."""
    manifest = json.loads((ROOT / "extension" / "manifest.json").read_text(encoding="utf-8"))
    digest = hashlib.sha256(base64.b64decode(manifest["key"])).hexdigest()[:32]
    return "".join(chr(ord("a") + int(c, 16)) for c in digest)


def python_exe() -> Path:
    venv = ROOT / ".venv" / "Scripts" / "python.exe"
    return venv if venv.exists() else Path(sys.executable)


def install() -> None:
    if sys.platform != "win32":
        sys.exit("This installer targets Windows. On macOS/Linux copy the manifest to the browser's "
                 "NativeMessagingHosts folder (see README).")
    import winreg

    NATIVE_DIR.mkdir(exist_ok=True)
    launcher = NATIVE_DIR / "walled_dlp_host.bat"
    # @echo off is essential: anything echoed to stdout would corrupt the messaging channel.
    launcher.write_text(
        f'@echo off\n"{python_exe()}" -u "{ROOT / "agent" / "host.py"}" %*\n', encoding="ascii", newline="\r\n"
    )
    ext_id = extension_id()
    manifest_path = NATIVE_DIR / f"{HOST_NAME}.json"
    manifest_path.write_text(json.dumps({
        "name": HOST_NAME,
        "description": "Walled DLP Guard desktop agent",
        "path": str(launcher),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{ext_id}/"],
    }, indent=2), encoding="utf-8")

    for browser, key in BROWSER_KEYS.items():
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as handle:
            winreg.SetValueEx(handle, "", 0, winreg.REG_SZ, str(manifest_path))
        print(f"registered for {browser}: HKCU\\{key}")

    sys.path.insert(0, str(ROOT))
    from agent.scanner import find_tesseract

    tesseract = find_tesseract()
    print(f"\nnative host manifest: {manifest_path}")
    print(f"extension ID:         {ext_id}")
    print(f"Tesseract OCR:        {tesseract or 'NOT FOUND - image scanning disabled (winget install UB-Mannheim.TesseractOCR)'}")
    print("\nNext: chrome://extensions -> Developer mode -> Load unpacked -> select the 'extension' folder.")


def uninstall() -> None:
    import winreg

    for browser, key in BROWSER_KEYS.items():
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
            print(f"removed {browser} registration")
        except FileNotFoundError:
            print(f"{browser}: not registered")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--uninstall", action="store_true")
    (uninstall if parser.parse_args().uninstall else install)()
