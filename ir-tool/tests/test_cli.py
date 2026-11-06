import json

from conftest import FIXTURE, load_sample_docs
from wazuh_ir.cli import load_alerts_from_file, main
from wazuh_ir.config import ConfigError, load_config


def test_offline_run_creates_report_and_signals_high(tmp_path, capsys):
    code = main(["--input", str(FIXTURE), "--out", str(tmp_path), "--id", "IR-CLI"])
    assert code == 3                                   # High-Alarme vorhanden
    assert (tmp_path / "IR-CLI" / "incident-report.md").exists()
    assert "23 Alarme ausgewertet" in capsys.readouterr().out


def test_agent_and_level_filter(tmp_path, capsys):
    code = main(["--input", str(FIXTURE), "--out", str(tmp_path), "--id", "IR-F",
                 "--agent", "DC01", "--min-level", "8"])
    out = capsys.readouterr().out
    assert "5 Alarme ausgewertet" in out              # 100100, 100102, 3x 100110
    assert code == 3


def test_low_only_returns_zero(tmp_path):
    docs = [d for d in load_sample_docs() if d["rule"]["level"] < 7]
    f = tmp_path / "low.json"
    f.write_text(json.dumps(docs), encoding="utf-8")
    assert main(["--input", str(f), "--out", str(tmp_path), "--id", "IR-LOW"]) == 0


def test_reads_opensearch_response_and_json_lines(tmp_path):
    docs = load_sample_docs()[:3]
    resp = tmp_path / "resp.json"
    resp.write_text(json.dumps({"hits": {"hits": [{"_source": d} for d in docs]}}), encoding="utf-8")
    lines = tmp_path / "alerts.json"
    lines.write_text("\n".join(json.dumps(d) for d in docs), encoding="utf-8")
    assert len(load_alerts_from_file(resp)) == 3
    assert len(load_alerts_from_file(lines)) == 3


def test_missing_config_gives_clear_error(tmp_path, monkeypatch, capsys):
    for var in ("WAZUH_INDEXER_URL", "WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    code = main(["--env", str(tmp_path / "missing.env"), "--out", str(tmp_path)])
    assert code == 1
    assert "WAZUH_INDEXER_URL" in capsys.readouterr().err


def test_load_config_parses_tls_setting(monkeypatch, tmp_path):
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200/")
    monkeypatch.setenv("WAZUH_INDEXER_USER", "reader")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "x")
    monkeypatch.setenv("WAZUH_VERIFY_TLS", "false")
    cfg = load_config(tmp_path / "none.env")
    assert cfg.indexer_url == "https://127.0.0.1:9200"
    assert cfg.verify_tls is False


def test_config_error_type():
    assert issubclass(ConfigError, Exception)
