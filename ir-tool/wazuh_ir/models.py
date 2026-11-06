"""Datenmodell: ein Wazuh-Alarm als unveränderliches Objekt."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITY_BANDS = (
    (15, "Critical"),
    (12, "High"),
    (7, "Medium"),
    (0, "Low"),
)


def severity_for_level(level: int) -> str:
    """Wazuh-Rule-Level (0-15) -> Schweregrad wie im Wazuh-Dashboard."""
    for threshold, name in SEVERITY_BANDS:
        if level >= threshold:
            return name
    return "Low"


def _get(data: dict[str, Any], dotted: str, default: Any = None) -> Any:
    """Liest verschachtelte Felder wie 'rule.mitre.id' fehlertolerant aus."""
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def parse_timestamp(value: str) -> datetime:
    """Wazuh-Zeitstempel wie '2026-10-24T01:12:03.123+0200' oder ISO-8601 mit 'Z'."""
    text = value.strip().replace("Z", "+00:00")
    # +0200 -> +02:00, damit datetime.fromisoformat es versteht
    if len(text) >= 5 and text[-5] in "+-" and text[-4:].isdigit():
        text = f"{text[:-2]}:{text[-2:]}"
    return datetime.fromisoformat(text)


@dataclass(frozen=True)
class Alert:
    timestamp: datetime
    agent: str
    rule_id: str
    level: int
    description: str
    groups: tuple[str, ...] = field(default_factory=tuple)
    mitre_ids: tuple[str, ...] = field(default_factory=tuple)
    mitre_tactics: tuple[str, ...] = field(default_factory=tuple)
    src_ip: str | None = None
    user: str | None = None

    @property
    def severity(self) -> str:
        return severity_for_level(self.level)

    @classmethod
    def from_source(cls, src: dict[str, Any]) -> "Alert":
        """Erzeugt einen Alert aus dem _source-Dokument des Indexers."""
        win = _get(src, "data.win.eventdata", {}) or {}
        return cls(
            timestamp=parse_timestamp(src["timestamp"]),
            agent=_get(src, "agent.name", "unbekannt"),
            rule_id=str(_get(src, "rule.id", "")),
            level=int(_get(src, "rule.level", 0)),
            description=_get(src, "rule.description", ""),
            groups=tuple(_as_list(_get(src, "rule.groups"))),
            mitre_ids=tuple(_as_list(_get(src, "rule.mitre.id"))),
            mitre_tactics=tuple(_as_list(_get(src, "rule.mitre.tactic"))),
            src_ip=_clean(_get(src, "data.srcip") or win.get("ipAddress")),
            user=_clean(_get(src, "data.dstuser") or win.get("targetUserName")),
        )


def _clean(value: Any) -> str | None:
    """Windows schreibt für 'kein Wert' oft '-' - das ist für die Auswertung None."""
    if value is None:
        return None
    text = str(value).strip()
    return None if text in {"", "-"} else text
