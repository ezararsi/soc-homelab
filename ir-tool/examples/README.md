# Beispiel-Report

`IR-BEISPIEL/` wurde mit den **synthetischen Testdaten** aus `tests/fixtures/sample_alerts.json` erzeugt und zeigt Aufbau und Diagramme des Reports:

```bash
python -m wazuh_ir --input tests/fixtures/sample_alerts.json --out examples --id IR-BEISPIEL
```

Reports aus dem Live-Lab landen standardmäßig in `reports/` (per `.gitignore` nicht versioniert, da sie echte Konten und IP-Adressen enthalten).
