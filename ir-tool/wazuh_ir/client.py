"""Zugriff auf den Wazuh-Indexer (OpenSearch-API, Index wazuh-alerts-*).

Hinweis: Alarme liegen im Indexer, nicht in der Manager-API (Port 55000).
Im Lab lauscht der Indexer nur lokal auf WAZUH01. Zugriff vom Admin-PC daher
über einen SSH-Tunnel, ohne zusätzliche Firewall-Freigabe:

    ssh -L 9200:127.0.0.1:9200 socadmin@10.10.20.10
    -> WAZUH_INDEXER_URL=https://127.0.0.1:9200
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterator

import requests

from .config import Config
from .models import Alert


class IndexerError(Exception):
    """Fehler bei der Abfrage des Indexers."""


def build_query(
    start: datetime,
    end: datetime,
    min_level: int = 0,
    agent: str | None = None,
    size: int = 1000,
    search_after: list[Any] | None = None,
) -> dict[str, Any]:
    """Baut die OpenSearch-Abfrage (Zeitraum, Mindest-Level, optional Agent)."""
    filters: list[dict[str, Any]] = [
        {"range": {"timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}},
        {"range": {"rule.level": {"gte": min_level}}},
    ]
    if agent:
        filters.append({"term": {"agent.name": agent}})

    query: dict[str, Any] = {
        "size": size,
        "query": {"bool": {"filter": filters}},
        # Sortierung + Tiebreaker ermöglicht stabiles Blättern mit search_after
        "sort": [{"timestamp": "asc"}, {"_id": "asc"}],
    }
    if search_after:
        query["search_after"] = search_after
    return query


class IndexerClient:
    def __init__(self, config: Config, session: requests.Session | None = None) -> None:
        self.config = config
        self.session = session or requests.Session()
        self.session.auth = (config.user, config.password)
        self.session.verify = config.verify_tls

    def _search(self, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.config.indexer_url}/{self.config.index_pattern}/_search"
        try:
            response = self.session.post(url, json=body, timeout=self.config.timeout)
        except requests.RequestException as exc:
            raise IndexerError(f"Indexer nicht erreichbar: {exc}") from exc
        if response.status_code == 401:
            raise IndexerError("Anmeldung am Indexer fehlgeschlagen (401) - Zugangsdaten prüfen.")
        if response.status_code >= 400:
            raise IndexerError(f"Indexer-Fehler {response.status_code}: {response.text[:300]}")
        return response.json()

    def iter_alerts(
        self,
        start: datetime,
        end: datetime,
        min_level: int = 0,
        agent: str | None = None,
        page_size: int = 1000,
        limit: int = 50_000,
    ) -> Iterator[Alert]:
        """Liefert alle passenden Alarme seitenweise (search_after)."""
        search_after: list[Any] | None = None
        returned = 0
        while returned < limit:
            body = build_query(start, end, min_level, agent, page_size, search_after)
            hits = self._search(body).get("hits", {}).get("hits", [])
            if not hits:
                return
            for hit in hits:
                yield Alert.from_source(hit["_source"])
                returned += 1
                if returned >= limit:
                    return
            search_after = hits[-1].get("sort")
            if not search_after or len(hits) < page_size:
                return

    def fetch_alerts(self, *args: Any, **kwargs: Any) -> list[Alert]:
        return list(self.iter_alerts(*args, **kwargs))
