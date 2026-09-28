"""Licence hors ligne : signature Ed25519, états, source, page d'administration, bridage optionnel."""
import base64
import json
from datetime import date, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import config
from netwatch import license as nw_license

KID = "test"


def _b64e(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


@pytest.fixture
def signer(monkeypatch):
    """Paire de clés éphémère : la clé publique remplace celle de l'éditeur pendant le test."""
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setitem(nw_license.PUBLIC_KEYS, KID, base64.b64encode(pub).decode())

    def issue(expires, edition="pro", features=None, customer="PME Test", kid=KID, tamper=False):
        payload = {"id": "NW-TEST-1", "customer": customer, "edition": edition, "sensors": 1,
                   "issued": "2026-09-28", "expires": expires, "features": features or []}
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        sig = key.sign(raw)
        if tamper:
            payload["customer"] = "Autre"
            raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return f"NW1.{kid}.{_b64e(raw)}.{_b64e(sig)}"
    return issue


def test_states(signer):
    today = date(2026, 9, 28)
    ok = nw_license.evaluate(signer("2027-09-28"), today=today)
    assert ok["state"] == "valid" and ok["edition"] == "pro" and ok["days_left"] == 365
    assert set(ok["features"]) == set(nw_license.PRO_FEATURES)
    grace = nw_license.evaluate(signer((today - timedelta(days=10)).isoformat()), today=today)
    assert grace["state"] == "grace" and grace["edition"] == "pro"
    expired = nw_license.evaluate(signer((today - timedelta(days=40)).isoformat()), today=today)
    assert expired["state"] == "expired" and expired["edition"] == "community" and expired["features"] == []
    subset = nw_license.evaluate(signer("2027-01-01", features=["reports"]), today=today)
    assert subset["features"] == ["reports"]


def test_rejects_tampered_unknown_key_and_garbage(signer):
    assert nw_license.evaluate(signer("2027-09-28", tamper=True))["state"] == "invalid"
    assert nw_license.evaluate(signer("2027-09-28", kid="inconnu"))["state"] == "invalid"
    assert nw_license.evaluate("NW1.test.pasdubase64.xx")["state"] == "invalid"
    assert nw_license.evaluate("")["state"] == "none"
    assert nw_license.evaluate("")["edition"] == "community"


def test_file_has_priority_over_env(signer, monkeypatch):
    monkeypatch.setattr(config, "LICENSE_KEY", signer("2027-01-01", customer="Env"))
    assert nw_license.status()["customer"] == "Env" and nw_license.status()["source"] == "env"
    nw_license.save_key(signer("2027-06-01", customer="Fichier"))
    assert nw_license.status()["customer"] == "Fichier" and nw_license.status()["source"] == "fichier"
    with pytest.raises(ValueError):
        nw_license.save_key(signer("2027-06-01", tamper=True))
    assert nw_license.remove_key() is True and nw_license.status()["customer"] == "Env"


def test_enforcement_is_off_by_default_and_gates_when_on(logged_in, signer, monkeypatch):
    assert config.LICENSE_ENFORCE is False
    assert logged_in.get("/compliance").status_code == 200
    monkeypatch.setattr(config, "LICENSE_ENFORCE", True)
    resp = logged_in.get("/compliance")
    assert resp.status_code == 402 and "Pro" in resp.get_data(as_text=True)
    resp = logged_in.post("/api/reports/generate")
    assert resp.status_code == 402 and "licence" in resp.get_json()["error"].lower()
    nw_license.save_key(signer("2027-09-28", features=["compliance"]))
    assert logged_in.get("/compliance").status_code == 200
    assert logged_in.post("/api/reports/generate").status_code == 402   # fonction hors périmètre de la licence


def test_admin_license_page(logged_in, app, signer):
    page = logged_in.get("/admin/license").get_data(as_text=True)
    assert "Édition Community" in page and "Aucune licence" in page
    resp = logged_in.post("/admin/license", data={"license": "NW1.x.y.z"}, follow_redirects=True)
    assert "signature invalide" in resp.get_data(as_text=True) or "illisible" in resp.get_data(as_text=True)
    resp = logged_in.post("/admin/license", data={"license": signer("2027-09-28")}, follow_redirects=True)
    page = resp.get_data(as_text=True)
    assert "Édition Pro" in page and "PME Test" in page
    assert logged_in.get("/status").get_data(as_text=True).count("PME Test") >= 1
    logged_in.post("/admin/license/remove")
    assert nw_license.status()["state"] == "none"
    # Réservé aux administrateurs
    other = app.test_client()
    logged_in.post("/admin/users", data={"username": "ops", "password": "MotDePasse-Test-123", "role": "operator"})
    other.post("/login", data={"username": "ops", "password": "MotDePasse-Test-123"})
    assert other.get("/admin/license").status_code == 403


def test_grace_banner(logged_in, signer):
    nw_license.save_key(signer((date.today() - timedelta(days=5)).isoformat()))
    page = logged_in.get("/hostgroups").get_data(as_text=True)
    assert "tolérance" in page
