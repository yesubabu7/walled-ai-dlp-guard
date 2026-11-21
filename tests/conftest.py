import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SAMPLES = ROOT / "samples"


@pytest.fixture(scope="session", autouse=True)
def samples():
    if not (SAMPLES / "secret_scanned.pdf").exists():
        subprocess.run([sys.executable, str(ROOT / "scripts" / "make_samples.py")], check=True,
                       stdout=subprocess.DEVNULL)
    return SAMPLES
