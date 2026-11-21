import sys
import time

import pytest

from agent import dialog


def test_auto_decision_env(monkeypatch):
    monkeypatch.setenv(dialog.AUTO_DECISION_ENV, "continue")
    assert dialog.confirm("t", "m") is True
    monkeypatch.setenv(dialog.AUTO_DECISION_ENV, "cancel")
    assert dialog.confirm("t", "m") is False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows MessageBox")
def test_real_dialog_times_out_to_cancel(monkeypatch):
    """Shows the real native dialog for one second; no answer must mean Cancel (fail closed)."""
    monkeypatch.delenv(dialog.AUTO_DECISION_ENV, raising=False)
    start = time.monotonic()
    assert dialog.confirm("Walled DLP Guard - test", "This test dialog closes itself.", timeout=1) is False
    assert time.monotonic() - start < 10
