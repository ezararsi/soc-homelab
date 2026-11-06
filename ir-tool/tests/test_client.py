from datetime import datetime, timezone
from unittest.mock import MagicMock

import requests

from conftest import load_sample_docs
from wazuh_ir.client import IndexerClient, IndexerError, build_query
from wazuh_ir.config import Config

CFG = Config("https://127.0.0.1:9200", "reader", "secret", False)
START = datetime(2026, 1, 15, 0, 0, tzinfo=timezone.utc)
END = datetime(2026, 1, 16, 0, 0, tzinfo=timezone.utc)


def _response(status, payload=None, text=""):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload or {}
    r.text = text
    return r


def _hits(docs, offset=0):
    return {"hits": {"hits": [
        {"_source": d, "sort": [d["timestamp"], str(offset + i)]} for i, d in enumerate(docs)
    ]}}


def test_build_query_filters():
    q = build_query(START, END, min_level=7, agent="DC01", size=50)
    filters = q["query"]["bool"]["filter"]
    assert {"range": {"rule.level": {"gte": 7}}} in filters
    assert {"term": {"agent.name": "DC01"}} in filters
    assert q["size"] == 50
    assert "search_after" not in q


def test_pagination_with_search_after():
    docs = load_sample_docs()
    session = MagicMock()
    session.post.side_effect = [
        _response(200, _hits(docs[:10])),
        _response(200, _hits(docs[10:20], 10)),
        _response(200, _hits(docs[20:], 20)),
    ]
    alerts = IndexerClient(CFG, session).fetch_alerts(START, END, page_size=10)
    assert len(alerts) == len(docs)
    second_body = session.post.call_args_list[1].kwargs["json"]
    assert second_body["search_after"] == [docs[9]["timestamp"], "9"]
    url = session.post.call_args_list[0].args[0]
    assert url == "https://127.0.0.1:9200/wazuh-alerts-*/_search"


def test_limit_stops_early():
    docs = load_sample_docs()
    session = MagicMock()
    session.post.return_value = _response(200, _hits(docs[:10]))
    alerts = IndexerClient(CFG, session).fetch_alerts(START, END, page_size=10, limit=5)
    assert len(alerts) == 5


def test_auth_error_is_reported_clearly():
    session = MagicMock()
    session.post.return_value = _response(401)
    try:
        IndexerClient(CFG, session).fetch_alerts(START, END)
    except IndexerError as exc:
        assert "401" in str(exc)
    else:
        raise AssertionError("IndexerError erwartet")


def test_connection_error_is_wrapped():
    session = MagicMock()
    session.post.side_effect = requests.ConnectionError("timed out")
    try:
        IndexerClient(CFG, session).fetch_alerts(START, END)
    except IndexerError as exc:
        assert "nicht erreichbar" in str(exc)
    else:
        raise AssertionError("IndexerError erwartet")


def test_password_not_in_repr():
    assert "secret" not in repr(CFG)
