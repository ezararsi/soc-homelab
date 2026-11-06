import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURE = Path(__file__).parent / "fixtures" / "sample_alerts.json"


def load_sample_docs():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))
