import json

import pytest
import requests

from netwatch import health


class FakeResponse:
    def __init__(self, status_code=200, body=None, text="", url=""):
        self.status_code = status_code
        self._body = body
        self.text = text or (json.dumps(body) if body is not None else "")
        self.url = url

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


@pytest.fixture
def fake_http(monkeypatch):
    """Table url → FakeResponse | Exception. URL absente = connexion refusée."""
    table = {}

    def fake_get(url, timeout=None, verify=None, headers=None):
        r = table.get(url, requests.exceptions.ConnectionError())
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(health.requests, "get", fake_get)
    return table


ES, GRAFANA, PROM, AUTOBLOCK, OLLAMA = ("http://es", "http://grafana", "http://prom", "http://ab", "http://ollama")


def _all_up(table):
    table[f"{ES}/_cluster/health"] = FakeResponse(body={"status": "green", "number_of_data_nodes": 1, "active_shards": 10})
    table[f"{GRAFANA}/api/health"] = FakeResponse(body={"database": "ok", "commit": "abcdef123"})
    table[f"{PROM}/-/healthy"] = FakeResponse(text="Prometheus Server is Healthy.")
    table[f"{AUTOBLOCK}/health"] = FakeResponse(body={"status": "ok", "dry_run": True})


def test_all_core_up(fake_http):
    _all_up(fake_http)
    services, status = health.check_all(ES, GRAFANA, PROM, AUTOBLOCK)
    assert status == "up"
    assert [s["name"] for s in services] == ["Elasticsearch", "Grafana", "Prometheus", "AutoBlock"]
    assert all(s["status"] == "up" and s["optional"] is False for s in services)
    assert "DRY_RUN" in services[3]["detail"]
    assert "commit=abcdef1" in services[1]["detail"]


def test_ollama_only_checked_when_url_given(fake_http):
    _all_up(fake_http)
    fake_http[f"{OLLAMA}/api/tags"] = FakeResponse(body={"models": [{"name": "mistral:latest"}]})
    services, _ = health.check_all(ES, GRAFANA, PROM, AUTOBLOCK, ollama_url=OLLAMA)
    assert services[-1]["name"] == "Assistant IA (Ollama)" and "mistral" in services[-1]["detail"]
    services, _ = health.check_all(ES, GRAFANA, PROM, AUTOBLOCK, ollama_url="")
    assert all(s["name"] != "Assistant IA (Ollama)" for s in services)


def test_ollama_without_models_is_degraded(fake_http):
    _all_up(fake_http)
    fake_http[f"{OLLAMA}/api/tags"] = FakeResponse(body={"models": []})
    services, status = health.check_all(ES, GRAFANA, PROM, AUTOBLOCK, ollama_url=OLLAMA)
    assert services[-1]["status"] == "degraded" and status == "degraded"


@pytest.mark.parametrize("color,expected", [("green", "up"), ("yellow", "degraded"), ("red", "down")])
def test_es_cluster_colors(fake_http, color, expected):
    _all_up(fake_http)
    fake_http[f"{ES}/_cluster/health"] = FakeResponse(body={"status": color})
    services, _ = health.check_all(ES, GRAFANA, PROM, AUTOBLOCK)
    assert services[0]["status"] == expected


def test_http_5xx_timeout_and_refused(fake_http):
    _all_up(fake_http)
    fake_http[f"{ES}/_cluster/health"] = FakeResponse(status_code=503)
    fake_http[f"{GRAFANA}/api/health"] = requests.exceptions.Timeout()
    del fake_http[f"{PROM}/-/healthy"]
    services, status = health.check_all(ES, GRAFANA, PROM, AUTOBLOCK)
    assert services[0]["detail"] == "HTTP 503"
    assert services[1]["detail"].startswith("Timeout")
    assert services[2]["detail"] == "Connexion refusée"
    assert status == "degraded"


def test_everything_down(fake_http):
    _, status = health.check_all(ES, GRAFANA, PROM, AUTOBLOCK)
    assert status == "down"


def test_optional_services_cannot_make_stack_down(fake_http):
    extra = health.extra_checks(kibana_url="http://kibana", arkime_url="http://arkime")
    services, status = health.check_all(ES, GRAFANA, PROM, AUTOBLOCK, extra=extra)
    assert status == "down"
    _all_up(fake_http)
    services, status = health.check_all(ES, GRAFANA, PROM, AUTOBLOCK, extra=extra)
    assert status == "degraded"
    assert [s["optional"] for s in services] == [False] * 4 + [True] * 2


def test_extra_checks_only_for_configured_urls():
    assert health.extra_checks() == []
    names = [c[0] for c in health.extra_checks(blackbox_url="http://b", ntopng_url="http://n", netbox_url="http://nb")]
    assert names == ["Blackbox (sondes)", "ntopng", "NetBox"]


def test_netbox_with_and_without_token():
    (name, url, fn, *rest), = health.extra_checks(netbox_url="http://nb", netbox_auth={"Authorization": "Token x"})
    assert url.endswith("/api/status/") and rest[0]["Authorization"] == "Token x"
    (name, url, fn), = health.extra_checks(netbox_url="http://nb")
    assert url.endswith("/login/")


def test_parsers_edge_cases():
    assert health._parse_alive(FakeResponse(status_code=401)) == ("up", "auth requise")
    assert health._parse_alive(FakeResponse(url="http://x/login?next=/")) == ("up", "page de connexion")
    assert health._parse_kibana(FakeResponse(body={"status": {"overall": {"level": "available"}}}))[0] == "up"
    assert health._parse_kibana(FakeResponse(text="<html>"))[0] == "up"
    assert health._parse_netbox(FakeResponse(status_code=403))[0] == "degraded"
    assert health._parse_netbox(FakeResponse(body={"netbox-version": "4.7", "rq-workers-running": 1})) == ("up", "v4.7 · workers=1")
    assert health._parse_grafana(FakeResponse(text="<html>"))[0] == "up"
    assert health._parse_es(FakeResponse(text="nope")) == ("degraded", "Réponse non parseable")
