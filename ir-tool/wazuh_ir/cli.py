"""Kommandozeile: python -m wazuh_ir --hours 24 --min-level 7 --out reports/

Zwei Betriebsarten:
  * live:    Abfrage des Wazuh-Indexers (Zugangsdaten aus .env)
  * offline: Auswertung einer exportierten JSON-Datei (--input), z. B. für Forensik
             oder wenn der Indexer nicht erreichbar ist
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .analysis import summarize
from .config import ConfigError, load_config
from .models import Alert, parse_timestamp
from .report import write_report


def load_alerts_from_file(path: str | Path) -> list[Alert]:
    """Liest Alarme aus JSON: Liste von _source-Dokumenten, OpenSearch-Antwort oder JSON-Lines."""
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text.startswith("{") and "\n{" in text:  # JSON-Lines (z. B. alerts.json des Managers)
        docs = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        data = json.loads(text)
        if isinstance(data, dict) and "hits" in data:
            docs = [h["_source"] for h in data["hits"]["hits"]]
        elif isinstance(data, dict):
            docs = [data]
        else:
            docs = data
    return [Alert.from_source(doc) for doc in docs]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wazuh_ir",
        description="Wazuh-Alarme auswerten und Incident-Report (NIST SP 800-61) erstellen.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--hours", type=int, default=24, help="Zeitraum: letzte N Stunden (Standard 24)")
    src.add_argument("--from", dest="start", help="Beginn (ISO-8601, z. B. 2026-11-01T08:00:00+01:00)")
    p.add_argument("--to", dest="end", help="Ende (ISO-8601), Standard: jetzt")
    p.add_argument("--min-level", type=int, default=3, help="Mindest-Rule-Level für die Abfrage (Standard 3)")
    p.add_argument("--finding-level", type=int, default=7,
                   help="Ab diesem Level wird ein Alarm zum Finding (Standard 7 = Medium)")
    p.add_argument("--agent", help="nur Alarme dieses Agenten (z. B. DC01)")
    p.add_argument("--input", help="offline: JSON-Datei mit Alarmen statt Indexer-Abfrage")
    p.add_argument("--env", default=".env", help="Pfad zur .env-Datei (Standard .env)")
    p.add_argument("--out", default="reports", help="Ausgabeordner (Standard reports/)")
    p.add_argument("--id", dest="incident_id", help="Incident-ID (Standard: IR-<Datum>-<Uhrzeit>)")
    return p


def resolve_timerange(args: argparse.Namespace, now: datetime) -> tuple[datetime, datetime]:
    end = parse_timestamp(args.end) if args.end else now
    start = parse_timestamp(args.start) if args.start else end - timedelta(hours=args.hours)
    if start >= end:
        raise ValueError("Beginn muss vor dem Ende liegen.")
    return start, end


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    now = datetime.now(timezone.utc)
    incident_id = args.incident_id or now.strftime("IR-%Y%m%d-%H%M")

    try:
        if args.input:
            alerts = load_alerts_from_file(args.input)
            alerts = [a for a in alerts if a.level >= args.min_level
                      and (not args.agent or a.agent == args.agent)]
            source = f"Datei {Path(args.input).name}"
        else:
            from .client import IndexerClient, IndexerError  # erst hier: requests nur im Live-Modus

            start, end = resolve_timerange(args, now)
            config = load_config(args.env)
            try:
                alerts = IndexerClient(config).fetch_alerts(start, end, args.min_level, args.agent)
            except IndexerError as exc:
                print(f"Fehler: {exc}", file=sys.stderr)
                return 2
            source = f"Wazuh-Indexer {config.indexer_url}"
    except (ConfigError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1

    summary = summarize(alerts, finding_level=args.finding_level)
    out_dir = Path(args.out) / incident_id
    report = write_report(summary, out_dir, incident_id, source, now)

    print(f"{summary.total} Alarme ausgewertet, {len(summary.findings)} Findings, "
          f"höchster Schweregrad: {summary.highest_severity}")
    print(f"Report: {report}")
    # Exit-Code 3 bei High/Critical - nützlich für Automatisierung (z. B. geplante Aufgabe)
    return 3 if summary.highest_severity in {"High", "Critical"} else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
