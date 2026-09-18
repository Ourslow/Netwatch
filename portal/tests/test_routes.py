"""
Tests du portail via le client de test Flask : authentification, édition
Core, en-têtes de sécurité, et les API purement fichier (hostgroups,
seuils, disposition) — sans Elasticsearch ni aucun service externe.
"""
import io

import pytest

from netwatch import health as nw_health


# ── Helpers purs ──────────────────────────────────────────────────────

def test_fmt_bytes(app_module):
    assert app_module.fmt_bytes(None) == "—"
    assert app_module.fmt_bytes(512) == "512.0 B"
    assert app_module.fmt_bytes(1536) == "1.5 KB"
    assert app_module.fmt_bytes(3 * 1024**3) == "3.0 GB"
    assert app_module.fmt_bytes(2 * 1024**5) == "2.0 PB"


def test_fmt_uptime(app_module):
    assert app_module.fmt_uptime(0) == "—"
    assert app_module.fmt_uptime(90) == "0h 1m"
    assert app_module.fmt_uptime(3600 * 5 + 120) == "5h 2m"
    assert app_module.fmt_uptime(3600 * 50) == "2j 2h"


def test_geo_flag(app_module):
    assert app_module.geo_flag("fr") == "🇫🇷"
    assert app_module.geo_flag("") == ""
    assert app_module.geo_flag("FRA") == ""


def test_safe_int(app_module):
    assert app_module._safe_int("42") == 42
    assert app_module._safe_int("abc", 7) == 7
    assert app_module._safe_int(None) is None


def test_browser_url_rewrites_localhost_only(app):
    from app import browser_url
    with app.test_request_context("/", base_url="http://172.31.20.90:5050"):
        assert browser_url("http://localhost:3000/d/x") == "http://172.31.20.90:3000/d/x"
        assert browser_url("http://127.0.0.1:9200") == "http://172.31.20.90:9200"
        assert browser_url("http://grafana.lan:3000") == "http://grafana.lan:3000"
        assert browser_url("not a url") == "not a url"


def test_range_selection(app, app_module):
    with app.test_request_context("/?range=7d"):
        assert app_module._range() == ("7d", 168)
        assert app_module._range_days() == 7
    with app.test_request_context("/?range=bogus"):
        assert app_module._range() == ("24h", 24)
    with app.test_request_context("/", headers={"Cookie": "nw_range=1h"}):
        assert app_module._range() == ("1h", 1)
        assert app_module._range_days() == 1
    with app.test_request_context("/?days=90"):
        assert app_module._range_days() == 30


# ── Authentification ──────────────────────────────────────────────────

def test_protected_routes_redirect_to_login(client):
    for path in ("/", "/alerts", "/status", "/api/status", "/hostgroups"):
        resp = client.get(path)
        assert resp.status_code == 302, path
        assert "/login" in resp.headers["Location"]


def test_login_wrong_password(client):
    resp = client.post("/login", data={"username": "admin", "password": "wrong"}, follow_redirects=True)
    assert resp.status_code == 200
    assert "Identifiants incorrects" in resp.get_data(as_text=True)


def test_login_refused_when_no_password_configured(client, monkeypatch):
    import config
    monkeypatch.setattr(config, "PORTAL_PASSWORD", "")
    resp = client.post("/login", data={"username": "admin", "password": ""})
    assert resp.status_code == 200


def test_login_success_and_logout(client):
    resp = client.post("/login", data={"username": "admin", "password": "test-password"})
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/")
    assert client.get("/api/hostgroups").status_code == 200
    resp = client.get("/logout")
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]
    assert client.get("/api/hostgroups").status_code == 302


@pytest.mark.parametrize("next_url", ["http://evil.example/steal", "//evil.example/x", "javascript:alert(1)"])
def test_login_open_redirect_blocked(client, next_url):
    resp = client.post(f"/login?next={next_url}", data={"username": "admin", "password": "test-password"})
    assert resp.status_code == 302
    assert "evil.example" not in resp.headers["Location"]
    assert not resp.headers["Location"].startswith("javascript:")


def test_login_relative_next_allowed(client):
    resp = client.post("/login?next=/alerts", data={"username": "admin", "password": "test-password"})
    assert resp.headers["Location"].endswith("/alerts")


def test_security_headers_and_cookie_flags(client):
    resp = client.get("/login")
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert "Referrer-Policy" in resp.headers
    resp = client.post("/login", data={"username": "admin", "password": "test-password"})
    cookie = resp.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_404_page(logged_in):
    resp = logged_in.get("/does-not-exist")
    assert resp.status_code == 404


# ── Édition Core (OLLAMA_URL vide) ────────────────────────────────────

def test_core_edition_disables_ai_endpoints(logged_in):
    resp = logged_in.post("/api/explain", json={"signature": "ET TEST"})
    assert resp.status_code == 503
    assert "édition Core" in resp.get_json()["error"]
    resp = logged_in.get("/agents")
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/")


def test_ai_edition_validates_payload(logged_in, monkeypatch):
    import config
    monkeypatch.setattr(config, "AI_ENABLED", True)
    resp = logged_in.post("/api/explain", json={})
    assert resp.status_code == 400


# ── /api/status (health mocké) ────────────────────────────────────────

def test_api_status(logged_in, monkeypatch):
    fake = ([{"name": "Elasticsearch", "url": "x", "status": "up", "latency": 3, "detail": None, "optional": False}], "up")
    monkeypatch.setattr(nw_health, "check_all", lambda *a, **k: fake)
    data = logged_in.get("/api/status").get_json()
    assert data["global"] == "up" and data["services"][0]["name"] == "Elasticsearch"


# ── Hostgroups API ────────────────────────────────────────────────────

CSV = b"Name,Description,Enabled,Hosts,Member hostgroups,Tags\nLAN,Reseau local,TRUE,10.0.0.0/24,,\n"


def test_hostgroups_import_export_delete(logged_in):
    assert logged_in.get("/api/hostgroups").get_json() == []

    resp = logged_in.post("/api/hostgroups/import", data={"file": (io.BytesIO(CSV), "hg.csv")},
                          content_type="multipart/form-data")
    assert resp.status_code == 200 and resp.get_json() == {"imported": 1, "groups": ["LAN"]}

    groups = logged_in.get("/api/hostgroups").get_json()
    assert groups[0]["name"] == "LAN" and groups[0]["host_count"] == 256

    csv_out = logged_in.get("/hostgroups/export.csv")
    assert csv_out.status_code == 200 and "text/csv" in csv_out.headers["Content-Type"]
    assert "LAN,Reseau local,True,256" in csv_out.get_data(as_text=True)

    assert logged_in.get("/hostgroups").status_code == 200

    assert logged_in.delete("/api/hostgroups/absent").status_code == 404
    assert logged_in.delete("/api/hostgroups/LAN").get_json() == {"deleted": "LAN"}
    assert logged_in.get("/api/hostgroups").get_json() == []


def test_hostgroups_import_errors(logged_in):
    assert logged_in.post("/api/hostgroups/import", data={}, content_type="multipart/form-data").status_code == 400
    resp = logged_in.post("/api/hostgroups/import", data={"file": (io.BytesIO(b"Name,Hosts\n"), "empty.csv")},
                          content_type="multipart/form-data")
    assert resp.status_code == 400


def test_hostgroups_clear(logged_in):
    logged_in.post("/api/hostgroups/import", data={"file": (io.BytesIO(CSV), "hg.csv")}, content_type="multipart/form-data")
    assert logged_in.post("/api/hostgroups/clear").get_json() == {"cleared": True}
    assert logged_in.get("/api/hostgroups").get_json() == []


# ── Thresholds API ────────────────────────────────────────────────────

def test_thresholds_api_crud(logged_in):
    assert logged_in.get("/api/thresholds").get_json() == []
    resp = logged_in.post("/api/thresholds", json={"metric": "avg_rtt_ms", "scope": " M365 ", "operator": ">",
                                                   "value": "120", "severity": "critical"})
    rule = resp.get_json()
    assert resp.status_code == 200 and rule["scope"] == "M365" and rule["value"] == 120.0

    assert logged_in.post("/api/thresholds", json={"metric": "nope"}).status_code == 400

    resp = logged_in.patch(f"/api/thresholds/{rule['id']}", json={"enabled": False})
    assert resp.get_json() == {"id": rule["id"], "enabled": False}
    assert logged_in.get("/api/thresholds").get_json()[0]["enabled"] is False

    assert logged_in.delete(f"/api/thresholds/{rule['id']}").get_json() == {"deleted": rule["id"]}
    assert logged_in.get("/api/thresholds").get_json() == []


# ── Dashboard layout API ──────────────────────────────────────────────

def test_dashboard_layout_api(logged_in, app_module):
    from netwatch import dashboard_layout as dl
    assert logged_in.get("/api/dashboard-layout").get_json() == {"layout": dl.DEFAULT_LAYOUT}
    resp = logged_in.post("/api/dashboard-layout", json={"layout": [{"id": "x", "type": "top_apps", "size": "sm"},
                                                                      {"id": "y", "type": "bogus"}]})
    assert resp.get_json() == {"layout": [{"id": "x", "type": "top_apps", "size": "sm"}]}
    assert logged_in.post("/api/dashboard-layout/reset").get_json() == {"layout": dl.DEFAULT_LAYOUT}
