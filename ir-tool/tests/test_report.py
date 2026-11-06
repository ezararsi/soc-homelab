from datetime import datetime, timezone

from conftest import load_sample_docs
from wazuh_ir.analysis import summarize
from wazuh_ir.models import Alert
from wazuh_ir.report import recommended_actions, write_report

FIXED_TIME = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


def _summary():
    return summarize([Alert.from_source(d) for d in load_sample_docs()])


def test_report_contains_nist_sections_and_findings(tmp_path):
    report = write_report(_summary(), tmp_path, "IR-TEST-1", "Testdaten", FIXED_TIME)
    text = report.read_text(encoding="utf-8")
    assert text.startswith("# Incident-Report IR-TEST-1")
    for section in (
        "## 1. Zusammenfassung",
        "## 2. Erkennung & Analyse",
        "## 3. Eindämmung, Beseitigung & Wiederherstellung",
        "## 4. Nachbereitung",
    ):
        assert section in text
    assert "T1558.003" in text
    assert "https://attack.mitre.org/techniques/T1110/001/" in text
    assert "**High**" in text


def test_charts_are_written(tmp_path):
    write_report(_summary(), tmp_path, "IR-TEST-2", "Testdaten", FIXED_TIME)
    for name in ("severity.png", "timeline.png", "mitre.png"):
        png = tmp_path / name
        assert png.exists() and png.stat().st_size > 1000
        assert png.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_actions_derived_from_tactics():
    actions = recommended_actions(_summary())
    assert any("Kerberoasting" in a for a in actions)        # Credential Access
    assert any("isolieren" in a for a in actions)            # Execution


def test_empty_report(tmp_path):
    report = write_report(summarize([]), tmp_path, "IR-EMPTY", "Testdaten", FIXED_TIME)
    assert "keine Alarme" in report.read_text(encoding="utf-8")
    assert not (tmp_path / "severity.png").exists()
