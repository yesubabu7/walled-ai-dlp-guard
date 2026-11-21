"""Native desktop Continue / Cancel confirmation.

Windows: a real system MessageBox (user32) - not a browser dialog. MessageBox only offers
fixed button sets, so a thread-local CBT hook renames OK -> "Continue" just before the box
is shown (a standard Win32 technique). The box is always on top, Cancel is the default
button, and MessageBoxTimeoutW auto-cancels after a timeout (fail closed).

Other platforms: a Tk confirmation dialog as a fallback.
"""

import ctypes
import logging
import os
import sys
import threading

log = logging.getLogger("walled_dlp.dialog")

DEFAULT_TIMEOUT_SECONDS = 120

# Test hook: WALLED_DLP_AUTO_DECISION=continue|cancel answers without showing anything.
AUTO_DECISION_ENV = "WALLED_DLP_AUTO_DECISION"


def confirm(title: str, message: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> bool:
    """Show the dialog and block until the user answers. True = Continue."""
    auto = os.environ.get(AUTO_DECISION_ENV, "").lower()
    if auto in ("continue", "cancel"):
        return auto == "continue"
    if sys.platform == "win32":
        return _confirm_windows(title, message, timeout)
    return _confirm_tk(title, message, timeout)


# ---------------------------------------------------------------- Windows

if sys.platform == "win32":
    from ctypes import wintypes

    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    LRESULT = ctypes.c_ssize_t
    HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)

    _user32.SetWindowsHookExW.argtypes = [ctypes.c_int, HOOKPROC, wintypes.HINSTANCE, wintypes.DWORD]
    _user32.SetWindowsHookExW.restype = wintypes.HHOOK
    _user32.CallNextHookEx.argtypes = [wintypes.HHOOK, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM]
    _user32.CallNextHookEx.restype = LRESULT
    _user32.UnhookWindowsHookEx.argtypes = [wintypes.HHOOK]
    _user32.UnhookWindowsHookEx.restype = wintypes.BOOL
    _user32.SetDlgItemTextW.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.LPCWSTR]
    _user32.SetDlgItemTextW.restype = wintypes.BOOL
    _user32.MessageBoxTimeoutW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                           wintypes.UINT, wintypes.WORD, wintypes.DWORD]
    _user32.MessageBoxTimeoutW.restype = ctypes.c_int
    _kernel32.GetCurrentThreadId.restype = wintypes.DWORD

    WH_CBT = 5
    HCBT_ACTIVATE = 5
    IDOK, IDCANCEL, MB_TIMEDOUT = 1, 2, 32000
    MB_OKCANCEL = 0x1
    MB_ICONWARNING = 0x30
    MB_DEFBUTTON2 = 0x100
    MB_SYSTEMMODAL = 0x1000
    MB_SETFOREGROUND = 0x10000
    MB_TOPMOST = 0x40000


def _confirm_windows(title: str, message: str, timeout: int) -> bool:
    renamed = threading.Event()

    @HOOKPROC
    def on_cbt(code, wparam, lparam):
        if code == HCBT_ACTIVATE and not renamed.is_set():
            renamed.set()
            _user32.SetDlgItemTextW(wparam, IDOK, "Continue")
            _user32.SetDlgItemTextW(wparam, IDCANCEL, "Cancel")
        return _user32.CallNextHookEx(None, code, wparam, lparam)

    hook = _user32.SetWindowsHookExW(WH_CBT, on_cbt, None, _kernel32.GetCurrentThreadId())
    try:
        flags = (MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SYSTEMMODAL
                 | MB_SETFOREGROUND | MB_TOPMOST)
        result = _user32.MessageBoxTimeoutW(None, message, title, flags, 0, timeout * 1000)
    finally:
        if hook:
            _user32.UnhookWindowsHookEx(hook)
    if result == MB_TIMEDOUT:
        log.info("dialog timed out after %ss -> Cancel", timeout)
    return result == IDOK


# ---------------------------------------------------------------- fallback

def _confirm_tk(title: str, message: str, timeout: int) -> bool:
    import tkinter as tk
    from tkinter import messagebox

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    root.after(timeout * 1000, root.destroy)
    try:
        return bool(messagebox.askokcancel(title, message, default=messagebox.CANCEL, parent=root))
    except tk.TclError:
        return False
    finally:
        try:
            root.destroy()
        except tk.TclError:
            pass
