# wazuh_ir – Incident-Response-Tool

Python-Werkzeug, das Alarme aus dem Wazuh-SIEM abfragt, auswertet und daraus einen **Incident-Report nach NIST SP 800-61** mit Diagrammen erstellt.

```
Wazuh-Indexer ──► Alarme abfragen ──► Auswerten (pandas) ──► Report (Markdown + PNG)
 (wazuh-alerts-*)    client.py           analysis.py            report.py
```

## Funktionen

| Funktion | Details |
|---|---|
| Abfrage | Zeitraum, Mindest-Level, einzelner Agent; Blättern über große Ergebnismengen (`search_after`) |
| Offline-Modus | Auswertung exportierter Alarme (`--input`): Liste, OpenSearch-Antwort oder JSON-Lines (`alerts.json`) |
| Auswertung | Schweregrade, betroffene Systeme, Top-Regeln, Zeitverlauf, MITRE-ATT&CK-Techniken und -Taktiken |
| Findings | gleiche Regel auf demselben System wird zu einem Finding zusammengefasst (erstmals/zuletzt, Konten, Quell-IPs) |
| Report | NIST-Struktur: Zusammenfassung → Erkennung & Analyse → Eindämmung/Beseitigung/Wiederherstellung → Nachbereitung |
| Maßnahmen | Sofortmaßnahmen werden aus den beobachteten ATT&CK-Taktiken abgeleitet |
| Automatisierung | Exit-Code `3` bei High/Critical, `0` sonst – z. B. für eine geplante Aufgabe |
| Sicherheit | Zugangsdaten nur aus `.env`/Umgebung, Passwort nie in Ausgaben, TLS-Prüfung mit eigener CA möglich |

## Installation

```bash
cd ir-tool
python -m venv .venv
.venv\Scripts\activate          # Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
copy .env.example .env          # Linux: cp .env.example .env  -> Werte eintragen
```

Leserechte genügen: Für das Tool einen eigenen Indexer-Benutzer mit Leserolle auf `wazuh-alerts-*` verwenden, nicht `admin`.

## Verwendung

```bash
# SSH-Tunnel zum Indexer (eigenes Fenster offen lassen)
ssh -L 9200:127.0.0.1:9200 socadmin@10.10.20.10

# Letzte 24 Stunden, Findings ab Level 7
python -m wazuh_ir --hours 24

# Bestimmter Zeitraum und Agent
python -m wazuh_ir --from 2026-11-01T08:00:00+01:00 --to 2026-11-01T18:00:00+01:00 --agent DC01

# Offline aus exportierter Datei
python -m wazuh_ir --input alerts.json --id IR-2026-001
```

Ausgabe: `reports/<Incident-ID>/incident-report.md` plus `severity.png`, `timeline.png`, `mitre.png`.
Beispiel (synthetische Daten): [`examples/IR-BEISPIEL/incident-report.md`](examples/IR-BEISPIEL/incident-report.md)

## Tests

```bash
pytest
```

28 Tests decken Datenmodell, Auswertung, Report-Erstellung, CLI und den Indexer-Client ab. Der Client wird dabei gemockt, die Tests laufen also ohne Lab.

## Aufbau

```
ir-tool/
├── wazuh_ir/
│   ├── config.py      Konfiguration aus .env (ohne Klartext-Ausgabe des Passworts)
│   ├── models.py      Alert-Datenklasse, Schweregrade, Zeitstempel-Parser
│   ├── client.py      Indexer-Abfrage mit Paging und klaren Fehlermeldungen
│   ├── analysis.py    pandas-Auswertung und Findings
│   ├── report.py      Markdown-Report und matplotlib-Diagramme
│   └── cli.py         Kommandozeile
├── tests/             pytest + synthetische Testdaten
└── examples/          Beispiel-Report
```
