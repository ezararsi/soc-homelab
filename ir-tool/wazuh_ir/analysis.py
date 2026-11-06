"""Auswertung der Alarme mit pandas."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

import pandas as pd

from .models import Alert, severity_for_level

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

COLUMNS = [
    "timestamp", "agent", "rule_id", "level", "severity", "description",
    "mitre_ids", "mitre_tactics", "src_ip", "user",
]


def to_dataframe(alerts: list[Alert]) -> pd.DataFrame:
    rows = [
        {
            "timestamp": a.timestamp,
            "agent": a.agent,
            "rule_id": a.rule_id,
            "level": a.level,
            "severity": a.severity,
            "description": a.description,
            "mitre_ids": list(a.mitre_ids),
            "mitre_tactics": list(a.mitre_tactics),
            "src_ip": a.src_ip,
            "user": a.user,
        }
        for a in alerts
    ]
    df = pd.DataFrame(rows, columns=COLUMNS)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
        df = df.sort_values("timestamp").reset_index(drop=True)
    return df


@dataclass
class Finding:
    """Zusammengefasster Vorfall: gleiche Regel auf demselben System."""

    rule_id: str
    description: str
    agent: str
    level: int
    count: int
    first_seen: datetime
    last_seen: datetime
    mitre_ids: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    src_ips: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return severity_for_level(self.level)


@dataclass
class Summary:
    total: int
    start: datetime | None
    end: datetime | None
    by_severity: dict[str, int]
    by_agent: dict[str, int]
    top_rules: list[tuple[str, str, int]]          # (rule_id, Beschreibung, Anzahl)
    mitre_techniques: list[tuple[str, int]]        # (Technik, Anzahl)
    mitre_tactics: list[tuple[str, int]]
    findings: list[Finding]
    hourly: pd.Series

    @property
    def highest_severity(self) -> str:
        for sev in SEVERITY_ORDER:
            if self.by_severity.get(sev, 0) > 0:
                return sev
        return "None"


def _unique(values: pd.Series) -> list[str]:
    return sorted({str(v) for v in values.dropna() if str(v)})


def _flatten(series: pd.Series) -> Counter:
    counter: Counter = Counter()
    for items in series:
        counter.update(items)
    return counter


def build_findings(df: pd.DataFrame, min_level: int = 7) -> list[Finding]:
    """Fasst relevante Alarme (ab min_level) zu Findings zusammen, schwerste zuerst."""
    relevant = df[df["level"] >= min_level]
    findings: list[Finding] = []
    for (rule_id, agent), group in relevant.groupby(["rule_id", "agent"], sort=False):
        findings.append(
            Finding(
                rule_id=str(rule_id),
                description=str(group["description"].iloc[0]),
                agent=str(agent),
                level=int(group["level"].max()),
                count=len(group),
                first_seen=group["timestamp"].min().to_pydatetime(),
                last_seen=group["timestamp"].max().to_pydatetime(),
                mitre_ids=sorted(_flatten(group["mitre_ids"])),
                mitre_tactics=sorted(_flatten(group["mitre_tactics"])),
                users=_unique(group["user"]),
                src_ips=_unique(group["src_ip"]),
            )
        )
    findings.sort(key=lambda f: (-f.level, -f.count, f.first_seen))
    return findings


def summarize(alerts: list[Alert], finding_level: int = 7, top_n: int = 10) -> Summary:
    df = to_dataframe(alerts)
    if df.empty:
        return Summary(0, None, None, {s: 0 for s in SEVERITY_ORDER}, {}, [], [], [], [],
                       pd.Series(dtype=int))

    by_severity = {s: int((df["severity"] == s).sum()) for s in SEVERITY_ORDER}
    by_agent = df["agent"].value_counts().to_dict()

    rule_counts = (
        df.groupby(["rule_id", "description"]).size().sort_values(ascending=False).head(top_n)
    )
    top_rules = [(rid, desc, int(n)) for (rid, desc), n in rule_counts.items()]

    hourly = df.set_index("timestamp").resample("1h").size()

    return Summary(
        total=len(df),
        start=df["timestamp"].min().to_pydatetime(),
        end=df["timestamp"].max().to_pydatetime(),
        by_severity=by_severity,
        by_agent={str(k): int(v) for k, v in by_agent.items()},
        top_rules=top_rules,
        mitre_techniques=_flatten(df["mitre_ids"]).most_common(),
        mitre_tactics=_flatten(df["mitre_tactics"]).most_common(),
        findings=build_findings(df, finding_level),
        hourly=hourly,
    )
