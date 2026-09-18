"""
Point d'entrée HTTPS unique (Caddy) : sous-requête /auth/check et réécriture
des liens vers les outils en mode proxy.
"""
from urllib.parse import parse_qs, urlsplit

import pytest

import config


def _next_of(resp):
    parts = urlsplit(resp.headers["Location"])
    assert parts.path.endswith("/login")
    return parse_qs(parts.query)["next"][0]


def test_auth_check_unauthenticated_redirects_to_login_with_wanted_uri(client):
    resp = client.get("/auth/check", headers={"X-Forwarded-Uri": "/grafana/d/netwatch-overview?orgId=1"})
    assert resp.status_code == 302
    assert _next_of(resp) == "/grafana/d/netwatch-overview?orgId=1"


def test_auth_check_without_forwarded_uri(client):
    resp = client.get("/auth/check")
    assert resp.status_code == 302 and _next_of(resp) == "/"


def test_auth_check_authenticated_returns_2xx_and_user_header(logged_in):
    resp = logged_in.get("/auth/check", headers={"X-Forwarded-Uri": "/kibana/app/discover"})
    assert resp.status_code == 204
    assert resp.headers["X-Webauth-User"] == "admin"


def test_login_accepts_tool_path_as_next(client):
    resp = client.post("/login?next=/grafana/d/x", data={"username": "admin", "password": "test-password"})
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/grafana/d/x")


@pytest.fixture
def proxy_mode(monkeypatch):
    monkeypatch.setattr(config, "PROXY_MODE", True)
    monkeypatch.setattr(config, "NETWATCH_GRAFANA_URL", "http://localhost:3000")
    monkeypatch.setattr(config, "NETWATCH_KIBANA_URL", "http://localhost:5601")
    monkeypatch.setattr(config, "NETWATCH_ARKIME_URL", "http://localhost:8005")
    monkeypatch.setattr(config, "NETWATCH_NTOPNG_URL", "http://localhost:3001")
    monkeypatch.setattr(config, "NETWATCH_NETBOX_URL", "http://localhost:8000/netbox")


@pytest.mark.parametrize("internal,public", [
    ("http://localhost:3000", "/grafana"),
    ("http://localhost:3000/", "/grafana/"),
    ("http://localhost:3000/d/netwatch-overview", "/grafana/d/netwatch-overview"),
    ("http://localhost:5601/app/discover#/?_a=(x)", "/kibana/app/discover#/?_a=(x)"),
    ("http://localhost:8005/sessions?expression=ip%3D%3D10.0.0.1", "/arkime/sessions?expression=ip%3D%3D10.0.0.1"),
    ("http://localhost:3001", "/ntopng"),
    ("http://localhost:8000/netbox/ipam/ip-addresses/42/", "/netbox/ipam/ip-addresses/42/"),
])
def test_browser_url_proxy_mode_maps_tools(app_module, proxy_mode, internal, public):
    assert app_module.browser_url(internal) == public


def test_browser_url_proxy_mode_port_prefix_is_not_confused(app_module, proxy_mode):
    # :3000 (Grafana) ne doit pas absorber :30001 ni :3001 (ntopng)
    assert app_module.browser_url("http://localhost:30001/x") == "http://localhost:30001/x"
    assert app_module.browser_url("http://localhost:3001/flows") == "/ntopng/flows"


def test_browser_url_proxy_mode_leaves_unproxied_service(app_module, proxy_mode):
    assert app_module.browser_url("http://localhost:5001/health") == "http://localhost:5001/health"


def test_browser_url_proxy_mode_skips_empty_tool_url(app_module, proxy_mode, monkeypatch):
    monkeypatch.setattr(config, "NETWATCH_KIBANA_URL", "")
    assert app_module.browser_url("http://localhost:5601/app") == "http://localhost:5601/app"


def test_browser_url_direct_mode_unchanged_for_tools(app, app_module, monkeypatch):
    monkeypatch.setattr(config, "PROXY_MODE", False)
    with app.test_request_context("/", base_url="http://172.31.20.90:5050"):
        assert app_module.browser_url("http://localhost:3000/d/x") == "http://172.31.20.90:3000/d/x"
