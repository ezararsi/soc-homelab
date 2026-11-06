from conftest import load_sample_docs
from wazuh_ir.analysis import summarize, to_dataframe
from wazuh_ir.models import Alert


def _alerts():
    return [Alert.from_source(d) for d in load_sample_docs()]


def test_dataframe_is_sorted_by_time():
    df = to_dataframe(list(reversed(_alerts())))
    assert df["timestamp"].is_monotonic_increasing


def test_summary_counts():
    s = summarize(_alerts())
    assert s.total == 23
    assert sum(s.by_severity.values()) == s.total
    assert s.by_severity["High"] == 4          # 3x Kerberoasting + 1x PowerShell
    assert s.by_agent == {"DC01": 21, "CLIENT01": 2}
    assert s.highest_severity == "High"


def test_findings_group_by_rule_and_agent_and_sort_by_severity():
    s = summarize(_alerts(), finding_level=7)
    assert s.findings[0].level == 12
    kerb = next(f for f in s.findings if f.rule_id == "100110")
    assert kerb.count == 3
    assert kerb.mitre_ids == ["T1558.003"]
    assert kerb.src_ips == ["10.10.10.100"]
    # Level-5-Fehlanmeldungen liegen unter der Schwelle und werden kein eigenes Finding
    assert all(f.rule_id != "60122" for f in s.findings)


def test_mitre_statistics():
    s = summarize(_alerts())
    techniques = dict(s.mitre_techniques)
    assert techniques["T1110.001"] == 11
    tactics = dict(s.mitre_tactics)
    assert tactics["Credential Access"] >= 14


def test_empty_input():
    s = summarize([])
    assert s.total == 0
    assert s.findings == []
    assert s.highest_severity == "None"
