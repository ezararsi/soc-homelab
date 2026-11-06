"""Incident-Report im Markdown-Format nach NIST SP 800-61 (Rev. 2) inkl. Diagrammen."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # ohne Bildschirm rendern (Server, CI, Tests)
import matplotlib.pyplot as plt  # noqa: E402

from .analysis import SEVERITY_ORDER, Summary  # noqa: E402

SEVERITY_COLORS = {"Critical": "#7f1d1d", "High": "#dc2626", "Medium": "#f59e0b", "Low": "#64748b"}

# Empfohlene Sofortmaßnahmen je MITRE-ATT&CK-Taktik (Containment / Eradication / Recovery)
TACTIC_ACTIONS: dict[str, list[str]] = {
    "Credential Access": [
        "Passwörter der betroffenen Konten zurücksetzen, aktive Sitzungen beenden.",
        "Bei Kerberoasting: Dienstkonto-Passwörter (lang, zufällig) erneuern, AES statt RC4 erzwingen.",
        "Quell-IP der Fehlanmeldungen an der Firewall sperren und Herkunft prüfen.",
    ],
    "Initial Access": [
        "Betroffenes Konto sperren, Anmeldeherkunft und -zeit mit dem Benutzer verifizieren.",
    ],
    "Execution": [
        "Betroffenes System vom Netz isolieren (Firewall-Regel bzw. Netzwerkkarte trennen).",
        "Prozessbaum (Sysmon Event 1) und Kommandozeile sichern und auswerten.",
    ],
    "Persistence": [
        "Neu angelegte Konten, Dienste, geplante Aufgaben und Run-Keys prüfen und entfernen.",
    ],
    "Privilege Escalation": [
        "Mitgliedschaften privilegierter Gruppen gegen den Soll-Stand prüfen, unberechtigte entfernen.",
    ],
    "Defense Evasion": [
        "Audit-Richtlinie und Sysmon-Status wiederherstellen, Integrität der Logs prüfen.",
        "Zeitraum ohne Protokollierung als blinden Fleck dokumentieren.",
    ],
    "Discovery": [
        "Ausführendes Konto und System prüfen - Erkundung geht oft weiteren Schritten voraus.",
    ],
    "Lateral Movement": [
        "Ziel- und Quellsystem isolieren, verwendete Konten zurücksetzen.",
    ],
    "Command and Control": [
        "Zieladressen/Domänen an der Firewall und im DNS blockieren.",
    ],
    "Exfiltration": [
        "Ausgehende Verbindungen des Systems sperren, betroffene Daten bestimmen (Meldepflichten prüfen).",
    ],
    "Impact": [
        "System isolieren, Wiederherstellung aus geprüftem Backup/Snapshot vorbereiten.",
    ],
}

DEFAULT_ACTIONS = [
    "Betroffene Systeme und Konten bestimmen, Beweise (Logs, Speicherabbild) sichern.",
    "Alarme mit dem verantwortlichen Administrator abgleichen (geplante Änderung oder Angriff?).",
]


def _fmt(ts: datetime | None) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S %Z").strip() if ts else "-"


def render_charts(summary: Summary, out_dir: Path) -> dict[str, str]:
    """Erstellt PNG-Diagramme und liefert {Name: Dateiname}."""
    out_dir.mkdir(parents=True, exist_ok=True)
    charts: dict[str, str] = {}

    # 1. Alarme nach Schweregrad
    fig, ax = plt.subplots(figsize=(6, 3.2))
    values = [summary.by_severity.get(s, 0) for s in SEVERITY_ORDER]
    bars = ax.bar(SEVERITY_ORDER, values, color=[SEVERITY_COLORS[s] for s in SEVERITY_ORDER])
    ax.bar_label(bars)
    ax.set_title("Alarme nach Schweregrad")
    ax.set_ylabel("Anzahl")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(out_dir / "severity.png", dpi=120)
    plt.close(fig)
    charts["severity"] = "severity.png"

    # 2. Zeitverlauf
    if not summary.hourly.empty:
        fig, ax = plt.subplots(figsize=(8, 3.2))
        ax.plot(summary.hourly.index, summary.hourly.values, marker="o", color="#2563eb")
        ax.fill_between(summary.hourly.index, summary.hourly.values, alpha=0.15, color="#2563eb")
        ax.set_title("Alarme pro Stunde (UTC)")
        ax.set_ylabel("Anzahl")
        ax.spines[["top", "right"]].set_visible(False)
        fig.autofmt_xdate()
        fig.tight_layout()
        fig.savefig(out_dir / "timeline.png", dpi=120)
        plt.close(fig)
        charts["timeline"] = "timeline.png"

    # 3. MITRE-ATT&CK-Techniken
    if summary.mitre_techniques:
        top = summary.mitre_techniques[:10][::-1]
        fig, ax = plt.subplots(figsize=(6, 0.4 * len(top) + 1.2))
        ax.barh([t for t, _ in top], [n for _, n in top], color="#7c3aed")
        ax.set_title("MITRE-ATT&CK-Techniken")
        ax.set_xlabel("Anzahl Alarme")
        ax.spines[["top", "right"]].set_visible(False)
        fig.tight_layout()
        fig.savefig(out_dir / "mitre.png", dpi=120)
        plt.close(fig)
        charts["mitre"] = "mitre.png"

    return charts


def recommended_actions(summary: Summary) -> list[str]:
    actions: list[str] = []
    for tactic, _ in summary.mitre_tactics:
        for action in TACTIC_ACTIONS.get(tactic, []):
            if action not in actions:
                actions.append(action)
    return actions or list(DEFAULT_ACTIONS)


def render_markdown(
    summary: Summary,
    charts: dict[str, str],
    incident_id: str,
    source: str,
    generated_at: datetime | None = None,
) -> str:
    generated_at = generated_at or datetime.now(timezone.utc)
    lines: list[str] = []
    add = lines.append

    add(f"# Incident-Report {incident_id}")
    add("")
    add("| Feld | Wert |")
    add("|---|---|")
    add(f"| Erstellt | {_fmt(generated_at)} |")
    add(f"| Datenquelle | {source} |")
    add(f"| Betrachteter Zeitraum | {_fmt(summary.start)} bis {_fmt(summary.end)} |")
    add(f"| Höchster Schweregrad | **{summary.highest_severity}** |")
    add(f"| Alarme gesamt | {summary.total} |")
    add(f"| Betroffene Systeme | {', '.join(summary.by_agent) or '-'} |")
    add("")
    add("> Struktur nach NIST SP 800-61 Rev. 2: Erkennung & Analyse → Eindämmung, "
        "Beseitigung & Wiederherstellung → Nachbereitung.")
    add("")

    # 1. Zusammenfassung
    add("## 1. Zusammenfassung")
    add("")
    if summary.total == 0:
        add("Im betrachteten Zeitraum wurden keine Alarme gefunden.")
        add("")
        return "\n".join(lines)
    sev_text = ", ".join(f"{summary.by_severity[s]} {s}" for s in SEVERITY_ORDER)
    add(f"Es wurden **{summary.total} Alarme** ausgewertet ({sev_text}). "
        f"Daraus ergeben sich **{len(summary.findings)} relevante Findings** "
        f"auf {len(summary.by_agent)} System(en).")
    if summary.mitre_tactics:
        tactics = ", ".join(t for t, _ in summary.mitre_tactics[:5])
        add(f"Beobachtete ATT&CK-Taktiken: {tactics}.")
    add("")

    # 2. Erkennung & Analyse
    add("## 2. Erkennung & Analyse (Detection & Analysis)")
    add("")
    if "severity" in charts:
        add(f"![Alarme nach Schweregrad]({charts['severity']})")
        add("")
    add("### 2.1 Findings")
    add("")
    if summary.findings:
        add("| # | Schweregrad | Regel | Beschreibung | System | Anzahl | Erstmals | Zuletzt | ATT&CK | Konten | Quell-IP |")
        add("|---|---|---|---|---|---|---|---|---|---|---|")
        for i, f in enumerate(summary.findings, start=1):
            add(
                f"| {i} | {f.severity} ({f.level}) | {f.rule_id} | {f.description} | {f.agent} | "
                f"{f.count} | {_fmt(f.first_seen)} | {_fmt(f.last_seen)} | "
                f"{', '.join(f.mitre_ids) or '-'} | {', '.join(f.users) or '-'} | "
                f"{', '.join(f.src_ips) or '-'} |"
            )
    else:
        add("Keine Alarme oberhalb der Relevanzschwelle.")
    add("")

    add("### 2.2 Zeitverlauf")
    add("")
    if "timeline" in charts:
        add(f"![Zeitverlauf]({charts['timeline']})")
        add("")

    add("### 2.3 MITRE ATT&CK")
    add("")
    if summary.mitre_techniques:
        if "mitre" in charts:
            add(f"![MITRE-ATT&CK-Techniken]({charts['mitre']})")
            add("")
        add("| Technik | Alarme |")
        add("|---|---|")
        for technique, count in summary.mitre_techniques:
            add(f"| [{technique}](https://attack.mitre.org/techniques/{technique.replace('.', '/')}/) | {count} |")
    else:
        add("Keine ATT&CK-Zuordnung in den Alarmen.")
    add("")

    add("### 2.4 Häufigste Regeln")
    add("")
    add("| Regel | Beschreibung | Anzahl |")
    add("|---|---|---|")
    for rule_id, desc, count in summary.top_rules:
        add(f"| {rule_id} | {desc} | {count} |")
    add("")

    # 3. Eindämmung, Beseitigung, Wiederherstellung
    add("## 3. Eindämmung, Beseitigung & Wiederherstellung")
    add("")
    add("Empfohlene Maßnahmen (abgeleitet aus den beobachteten ATT&CK-Taktiken):")
    add("")
    for action in recommended_actions(summary):
        add(f"- [ ] {action}")
    add("")

    # 4. Nachbereitung
    add("## 4. Nachbereitung (Post-Incident Activity)")
    add("")
    add("- [ ] Ursache (Root Cause) und Einfallsweg dokumentiert")
    add("- [ ] Erkennungsregeln angepasst (zu spät / gar nicht erkannte Schritte)")
    add("- [ ] Härtungsmaßnahmen umgesetzt und im Change-Log erfasst")
    add("- [ ] Lessons Learned mit dem Team besprochen")
    add("")
    add("---")
    add("*Automatisch erstellt mit `wazuh_ir`. Bewertung und Maßnahmen sind durch einen Analysten zu bestätigen.*")
    add("")
    return "\n".join(lines)


def write_report(
    summary: Summary,
    out_dir: str | Path,
    incident_id: str,
    source: str,
    generated_at: datetime | None = None,
) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    charts = render_charts(summary, out) if summary.total else {}
    report = out / "incident-report.md"
    report.write_text(
        render_markdown(summary, charts, incident_id, source, generated_at), encoding="utf-8"
    )
    return report
