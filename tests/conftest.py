import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.protocol import encode_message, read_message  # noqa: E402

SAMPLES = ROOT / "samples"


class HostProcess:
    """Talks to the agent exactly like Chrome does: length-prefixed JSON over stdin/stdout."""

    def __init__(self, decision: str, command: list[str] | None = None):
        env = {**os.environ, "WALLED_DLP_AUTO_DECISION": decision, "WALLED_DLP_NO_TRAY": "1"}
        cmd = command or [sys.executable, str(ROOT / "agent" / "host.py"), "chrome-extension://test/"]
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, env=env)

    def send(self, msg: dict) -> None:
        self.proc.stdin.write(encode_message(msg))
        self.proc.stdin.flush()

    def recv(self) -> dict:
        return read_message(self.proc.stdout)

    def close(self) -> int:
        self.proc.stdin.close()
        return self.proc.wait(timeout=15)


@pytest.fixture
def host():
    started: list[HostProcess] = []

    def start(decision: str = "cancel", command=None) -> HostProcess:
        h = HostProcess(decision, command)
        started.append(h)
        return h

    yield start
    for h in started:
        if h.proc.poll() is None:
            h.proc.kill()


@pytest.fixture(scope="session", autouse=True)
def samples():
    if not (SAMPLES / "secret_scanned.pdf").exists():
        subprocess.run([sys.executable, str(ROOT / "scripts" / "make_samples.py")], check=True,
                       stdout=subprocess.DEVNULL)
    return SAMPLES
