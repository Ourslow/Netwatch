"""Comptes nominatifs et rôles : compte d'amorçage, création, lecture seule, opérateur, admin, journal."""
import json

from netwatch import users as nw_users

PW = "MotDePasse-Test-123"


def _login(client, username, password):
    client.get("/logout")
    return client.post("/login", data={"username": username, "password": password})


def _create(admin_client, username, role, password=PW):
    resp = admin_client.post("/admin/users", data={"username": username, "password": password, "role": role})
    assert resp.status_code == 302
    return nw_users.get_user(username)


def test_env_admin_is_bootstrap_admin(logged_in):
    users = nw_users.list_users()
    assert users[0]["username"] == "admin" and users[0]["role"] == "admin" and users[0]["source"] == "env"
    assert logged_in.get("/admin/users").status_code == 200


def test_admin_creates_user_and_viewer_is_read_only(logged_in, app):
    client = app.test_client()
    u = _create(logged_in, "lecture", "viewer")
    assert u and u["role"] == "viewer" and "password_hash" not in u
    assert json.load(open(nw_users.USERS_PATH, encoding="utf-8"))["users"][0]["password_hash"].startswith("scrypt:")

    assert _login(client, "lecture", PW).status_code == 302
    assert client.get("/hostgroups").status_code == 200
    resp = client.post("/api/hostgroups/clear")
    assert resp.status_code == 403 and "lecture seule" in resp.get_json()["error"].lower()
    assert client.get("/admin/users").status_code == 403
    # Les demandes d'explication IA (POST sans effet) restent permises en lecture : 503 en édition Core, pas 403
    assert client.post("/api/explain", json={"signature": "ET TEST"}).status_code != 403


def test_operator_can_act_but_not_administer(logged_in, app):
    client = app.test_client()
    _create(logged_in, "ops", "operator")
    assert _login(client, "ops", PW).status_code == 302
    assert client.post("/api/dashboard-layout/reset").status_code == 200
    assert client.get("/admin/users").status_code == 403
    resp = client.post("/admin/users", data={"username": "x", "password": PW, "role": "admin"})
    assert resp.status_code == 403 and nw_users.get_user("x") is None


def test_validation_rules(logged_in):
    logged_in.post("/admin/users", data={"username": "court", "password": "trop-court", "role": "viewer"}, follow_redirects=True)
    assert nw_users.get_user("court") is None
    logged_in.post("/admin/users", data={"username": "Majuscule!", "password": PW, "role": "viewer"}, follow_redirects=True)
    assert nw_users.get_user("Majuscule!") is None
    _create(logged_in, "double", "viewer")
    resp = logged_in.post("/admin/users", data={"username": "double", "password": PW, "role": "operator"}, follow_redirects=True)
    assert "existe déjà" in resp.get_data(as_text=True)
    assert nw_users.get_user("double")["role"] == "viewer"


def test_bootstrap_account_is_managed_in_env_only(logged_in):
    resp = logged_in.post("/admin/users/admin", data={"action": "delete"}, follow_redirects=True)
    assert ".env" in resp.get_data(as_text=True)
    assert nw_users.get_user("admin") is not None


def test_disabled_user_cannot_login_and_last_admin_is_protected(logged_in, app, monkeypatch):
    client = app.test_client()
    _create(logged_in, "second", "admin")
    logged_in.post("/admin/users/second", data={"action": "disable"})
    assert nw_users.get_user("second")["disabled"] is True
    assert _login(client, "second", PW).status_code == 200  # reste sur la page de connexion
    logged_in.post("/admin/users/second", data={"action": "enable"})

    # Sans compte d'amorçage, « second » devient le dernier administrateur actif : intouchable
    # (garde-fou du module, atteignable par l'API interne ; via le portail l'auto-protection joue avant)
    import pytest
    import config
    monkeypatch.setattr(config, "PORTAL_PASSWORD", "")
    assert nw_users.active_admin_count() == 1
    for call in (lambda: nw_users.set_role("second", "viewer"), lambda: nw_users.set_disabled("second", True),
                 lambda: nw_users.delete_user("second")):
        with pytest.raises(ValueError, match="dernier administrateur"):
            call()
    assert nw_users.get_user("second")["role"] == "admin" and not nw_users.get_user("second")["disabled"]


def test_self_protection_and_password_reset(logged_in, app):
    client = app.test_client()
    _create(logged_in, "moi", "admin")
    assert _login(client, "moi", PW).status_code == 302
    resp = client.post("/admin/users/moi", data={"action": "disable"}, follow_redirects=True)
    assert "votre propre compte" in resp.get_data(as_text=True)
    client.post("/admin/users/moi", data={"action": "password", "password": "Nouveau-MotDePasse-456"})
    assert _login(client, "moi", PW).status_code == 200
    assert _login(client, "moi", "Nouveau-MotDePasse-456").status_code == 302


def test_auth_check_maps_roles_for_grafana(logged_in, app):
    client = app.test_client()
    _create(logged_in, "lecture", "viewer")
    assert logged_in.get("/auth/check").headers["X-Webauth-User"] == "admin"
    _login(client, "lecture", PW)
    assert client.get("/auth/check").headers["X-Webauth-User"] == "lecture"


def test_events_are_journaled_without_secrets(logged_in, app):
    client = app.test_client()
    _create(logged_in, "lecture", "viewer")
    _login(client, "lecture", "mauvais-mot-de-passe-xx")
    _login(client, "lecture", PW)
    client.post("/api/hostgroups/clear")
    kinds = [e["kind"] for e in nw_users.list_events(20)]
    for k in ("user_created", "login_failed", "login", "forbidden"):
        assert k in kinds
    raw = open(nw_users.AUTH_LOG_PATH, encoding="utf-8").read()
    assert PW not in raw and "mauvais-mot-de-passe" not in raw
    page = logged_in.get("/admin/users").get_data(as_text=True)
    assert "login_failed" in page and "forbidden" in page
