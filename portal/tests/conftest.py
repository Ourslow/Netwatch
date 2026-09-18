"""
Fixtures communes aux tests du portail.

L'environnement est fixé AVANT tout import de `config` (qui lit os.environ à
l'import) : édition Core (OLLAMA_URL vide), pas de Proxmox, services
NetWatch pointés sur un port fermé (127.0.0.1:9) pour que tout appel réseau
échoue immédiatement au lieu d'attendre un timeout. load_dotenv() n'écrase
jamais une variable déjà définie, donc un .env local ne perturbe pas les tests.
"""
import os
import sys

_PORTAL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PORTAL_DIR not in sys.path:
    sys.path.insert(0, _PORTAL_DIR)

_TEST_ENV = {
    "FLASK_SECRET_KEY": "test-secret-key",
    "FLASK_DEBUG": "false",
    "PORTAL_USERNAME": "admin",
    "PORTAL_PASSWORD": "test-password",
    "PROXMOX_HOST": "",
    "ESXI_HOST": "",
    "OLLAMA_URL": "",
    "NETWATCH_ES_URL": "http://127.0.0.1:9",
    "NETWATCH_GRAFANA_URL": "http://127.0.0.1:9",
    "NETWATCH_PROMETHEUS_URL": "http://127.0.0.1:9",
    "NETWATCH_AUTOBLOCK_URL": "http://127.0.0.1:9",
    "NETWATCH_BLACKBOX_URL": "",
    "NETWATCH_KIBANA_URL": "",
    "NETWATCH_NTOPNG_URL": "",
    "NETWATCH_ARKIME_URL": "",
    "NETWATCH_NETBOX_URL": "",
    "NETBOX_TOKEN": "",
    "NETBOX_TOKEN_KEY": "",
    "THRESHOLD_WEBHOOK_URL": "",
}
os.environ.update(_TEST_ENV)

import pytest  # noqa: E402

from netwatch import hostgroups, thresholds, dashboard_layout  # noqa: E402


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    """Redirige tous les fichiers de données du portail vers un répertoire
    temporaire : aucun test ne touche portal/data/."""
    d = tmp_path / "data"
    d.mkdir()
    monkeypatch.setattr(hostgroups, "DATA_DIR", str(d))
    monkeypatch.setattr(hostgroups, "STORE_PATH", str(d / "hostgroups.json"))
    monkeypatch.setattr(thresholds, "DATA_DIR", str(d))
    monkeypatch.setattr(thresholds, "RULES_PATH", str(d / "thresholds.json"))
    monkeypatch.setattr(thresholds, "STATE_PATH", str(d / "threshold_state.json"))
    monkeypatch.setattr(dashboard_layout, "DATA_DIR", str(d))
    monkeypatch.setattr(dashboard_layout, "LAYOUT_PATH", str(d / "dashboard_layout.json"))
    return d


@pytest.fixture
def app_module():
    import app as portal_app
    return portal_app


@pytest.fixture
def app(app_module):
    app_module.app.config.update(TESTING=True)
    return app_module.app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def logged_in(client):
    resp = client.post("/login", data={"username": "admin", "password": "test-password"})
    assert resp.status_code == 302
    return client
