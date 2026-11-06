"""Konfiguration aus Umgebungsvariablen bzw. einer lokalen .env-Datei.

Zugangsdaten stehen nie im Code. Vorlage: .env.example (die echte .env ist per
.gitignore vom Repository ausgeschlossen).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:  # python-dotenv ist optional - Umgebungsvariablen funktionieren auch ohne
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None


class ConfigError(Exception):
    """Pflichtwert fehlt oder ist ungültig."""


@dataclass(frozen=True)
class Config:
    indexer_url: str
    user: str
    password: str
    verify_tls: bool | str  # True, False oder Pfad zu einem CA-Zertifikat
    index_pattern: str = "wazuh-alerts-*"
    timeout: int = 30

    def __repr__(self) -> str:  # Passwort nie in Logs oder Tracebacks ausgeben
        return (
            f"Config(indexer_url={self.indexer_url!r}, user={self.user!r}, "
            f"password='***', verify_tls={self.verify_tls!r}, "
            f"index_pattern={self.index_pattern!r})"
        )


def _parse_verify(value: str) -> bool | str:
    lowered = value.strip().lower()
    if lowered in {"", "true", "1", "yes"}:
        return True
    if lowered in {"false", "0", "no"}:
        return False
    return value.strip()  # Pfad zu einer CA-Datei


def load_config(env_file: str | Path | None = ".env") -> Config:
    """Lädt die Konfiguration. Wirft ConfigError, wenn Pflichtwerte fehlen."""
    if load_dotenv is not None and env_file and Path(env_file).exists():
        load_dotenv(env_file, override=False)

    missing = [
        name
        for name in ("WAZUH_INDEXER_URL", "WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASSWORD")
        if not os.environ.get(name)
    ]
    if missing:
        raise ConfigError(
            "Fehlende Umgebungsvariablen: " + ", ".join(missing) + " (Vorlage: .env.example)"
        )

    return Config(
        indexer_url=os.environ["WAZUH_INDEXER_URL"].rstrip("/"),
        user=os.environ["WAZUH_INDEXER_USER"],
        password=os.environ["WAZUH_INDEXER_PASSWORD"],
        verify_tls=_parse_verify(os.environ.get("WAZUH_VERIFY_TLS", "true")),
        index_pattern=os.environ.get("WAZUH_INDEX_PATTERN", "wazuh-alerts-*"),
        timeout=int(os.environ.get("WAZUH_TIMEOUT", "30")),
    )
