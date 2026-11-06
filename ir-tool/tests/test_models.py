from datetime import timezone

from conftest import load_sample_docs
from wazuh_ir.models import Alert, parse_timestamp, severity_for_level


def test_severity_bands_match_wazuh_dashboard():
    assert severity_for_level(0) == "Low"
    assert severity_for_level(6) == "Low"
    assert severity_for_level(7) == "Medium"
    assert severity_for_level(11) == "Medium"
    assert severity_for_level(12) == "High"
    assert severity_for_level(14) == "High"
    assert severity_for_level(15) == "Critical"


def test_parse_timestamp_wazuh_format_with_offset():
    ts = parse_timestamp("2026-10-24T01:12:03.123+0200")
    assert ts.utcoffset().total_seconds() == 7200
    assert ts.astimezone(timezone.utc).hour == 23


def test_parse_timestamp_iso_z():
    assert parse_timestamp("2026-01-15T09:00:00Z").tzinfo is not None


def test_alert_from_source_reads_nested_fields():
    doc = next(d for d in load_sample_docs() if d["rule"]["id"] == "100100")
    alert = Alert.from_source(doc)
    assert alert.agent == "DC01"
    assert alert.level == 10
    assert alert.severity == "Medium"
    assert alert.mitre_ids == ("T1110.001",)
    assert alert.mitre_tactics == ("Credential Access",)
    assert alert.user == "anna.huber"
    assert alert.src_ip == "10.10.10.100"


def test_alert_from_minimal_source_uses_safe_defaults():
    alert = Alert.from_source({"timestamp": "2026-01-15T09:00:00Z", "rule": {"level": 3}})
    assert alert.agent == "unbekannt"
    assert alert.mitre_ids == ()
    assert alert.src_ip is None and alert.user is None


def test_windows_dash_placeholder_is_treated_as_empty():
    doc = {
        "timestamp": "2026-01-15T09:00:00Z",
        "rule": {"level": 3},
        "data": {"win": {"eventdata": {"ipAddress": "-", "targetUserName": "-"}}},
    }
    alert = Alert.from_source(doc)
    assert alert.src_ip is None and alert.user is None
