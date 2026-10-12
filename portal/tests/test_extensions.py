"""
Chargement de l'extension Pro (netwatch.extensions) : édition Community sans
paquet, paquet factice, paquet cassé (le portail démarre quand même), et le
paquet pro/ du dépôt (menu, palette, routes, carte de statut).
"""
import textwrap

import pytest
from flask import Flask

from netwatch import extensions as nw_extensions


def _noop(fn):
    return fn


def _pro_required(feature):
    return _noop


def _load(app, **kw):
    import config
    return nw_extensions.load(app, login_required=_noop, admin_required=_noop,
                              pro_required=_pro_required, config=config, **kw)


def _fake_package(tmp_path, body):
    pkg = tmp_path / "netwatch_pro"
    pkg.mkdir()
    (pkg / "__init__.py").write_text(textwrap.dedent(body), encoding="utf-8")
    return str(tmp_path)


@pytest.fixture(autouse=True)
def _restore_state():
    """Chaque test repart de l'état réel (extension pro/ chargée par app.py) après son passage."""
    saved = dict(nw_extensions.STATE)
    saved_api = nw_extensions._API
    yield
    nw_extensions.STATE.update(saved)
    nw_extensions._API = saved_api


@pytest.fixture
def _forget_fake_package():
    import sys
    real = sys.modules.get("netwatch_pro")
    saved_path = list(sys.path)
    yield
    sys.path[:] = saved_path   # le chargeur a inséré le dossier du paquet factice
    # ne pas laisser un netwatch_pro factice masquer le vrai pour les tests suivants
    if real is not None:
        sys.modules["netwatch_pro"] = real
    else:
        sys.modules.pop("netwatch_pro", None)


# ── Chargeur ──────────────────────────────────────────────────────────────

def test_disabled_means_community():
    app = Flask("x")
    api = _load(app, enabled=False)
    assert nw_extensions.STATE["loaded"] is False
    assert api.features == [] and api.nav == {s: [] for s in nw_extensions.NAV_SECTIONS}
    assert "désactivée" in nw_extensions.describe()
    with app.test_request_context("/"):
        ctx = {}
        for fn in app.template_context_processors[None]:
            ctx.update(fn())
        assert ctx["ai_enabled"] is False and ctx["pro_ext"]["loaded"] is False
        assert ctx["ext_commands"] == [] and ctx["ext_partials"] == {}


def test_absent_package_is_community(tmp_path, _forget_fake_package):
    """Aucun paquet netwatch_pro trouvable → Community, sans erreur."""
    import sys
    sys.modules.pop("netwatch_pro", None)
    saved_path = list(sys.path)
    sys.path[:] = [p for p in sys.path if not p.endswith("/pro")]   # masque le pro/ du dépôt
    try:
        app = Flask("x")
        _load(app, paths=[(str(tmp_path), "vide")], enabled=True)
    finally:
        sys.path[:] = saved_path
    st = nw_extensions.STATE
    assert st["loaded"] is False and st["error"] is None
    assert "absente" in nw_extensions.describe()


def test_fake_package_registers_everything(tmp_path, _forget_fake_package):
    import sys
    sys.modules.pop("netwatch_pro", None)
    path = _fake_package(tmp_path, '''
        from flask import Blueprint
        def register(api):
            bp = Blueprint("pro", __name__)
            @bp.route("/pro-test")
            @api.login_required
            @api.pro_required("reports")
            def pro_test():
                return "pro"
            api.register_blueprint(bp)
            api.add_nav("report", "Test Pro", "pro.pro_test", "bi-star", i18n="x")
            api.add_command("Test Pro", "/pro-test", "bi-star", hint="h")
            api.add_status_provider("demo", lambda: {"n": 1})
            api.add_status_provider("broken", lambda: 1 / 0)
            api.provide("ai_enabled", True)
            api.describe("fake-pro", "9.9", ["reports"])
    ''')
    app = Flask("x")
    api = _load(app, paths=[(path, "test")], enabled=True)
    st = nw_extensions.STATE
    assert st["loaded"] and st["name"] == "fake-pro" and st["version"] == "9.9" and st["features"] == ["reports"]
    assert nw_extensions.has_feature("reports") and not nw_extensions.has_feature("ia")
    assert api.nav["report"][0]["endpoint"] == "pro.pro_test"
    assert api.commands[0]["url"] == "/pro-test"
    assert api.status_extra() == {"demo": {"n": 1}, "broken": None}   # un fournisseur cassé n'empêche pas les autres
    assert app.test_client().get("/pro-test").data == b"pro"
    with app.test_request_context("/"):
        ctx = {}
        for fn in app.template_context_processors[None]:
            ctx.update(fn())
        assert ctx["ai_enabled"] is True and ctx["pro_ext"]["loaded"] is True
        assert ctx["ext_nav"]["report"][0]["label"] == "Test Pro"
    assert "fake-pro 9.9" in nw_extensions.describe()


def test_broken_package_does_not_prevent_startup(tmp_path, _forget_fake_package):
    import sys
    sys.modules.pop("netwatch_pro", None)
    path = _fake_package(tmp_path, '''
        def register(api):
            api.add_nav("report", "Moitié", "pro.x", "bi-x")
            raise RuntimeError("boum")
    ''')
    app = Flask("x")
    api = _load(app, paths=[(path, "test")], enabled=True)
    st = nw_extensions.STATE
    assert st["loaded"] is False and "RuntimeError: boum" in st["error"]
    assert api.nav["report"] == []   # rien de ce qu'elle a déclaré à moitié ne fuit
    assert "erreur de chargement" in nw_extensions.describe()
    assert app.test_client().get("/nope").status_code == 404


def test_unknown_nav_section_is_refused():
    api = nw_extensions.ExtensionAPI(Flask("x"), login_required=_noop, admin_required=_noop,
                                     pro_required=_pro_required, config=None)
    with pytest.raises(ValueError):
        api.add_nav("nope", "x", "x", "bi-x")


# ── Extension pro/ du dépôt, chargée par app.py ───────────────────────────

def test_intree_extension_is_loaded(app_module):
    st = nw_extensions.STATE
    assert st["loaded"] and st["name"] == "netwatch-pro"
    assert set(st["features"]) == {"ia", "reports", "compliance"}
    assert "pro/" in st["source"]


def test_intree_routes_and_menu(logged_in):
    assert logged_in.get("/compliance").status_code == 200
    assert logged_in.get("/reports").status_code == 200
    assert logged_in.get("/reports/download/..%2F..%2F.env").status_code in (400, 404)
    html = logged_in.get("/hostgroups").get_data(as_text=True)
    assert 'href="/compliance"' in html and 'href="/reports"' in html
    assert "Conformité" in html and "Rapports PDF" in html
    assert '"url": "/compliance"' in html   # palette de commandes (ext_commands | tojson)


def test_status_page_renders_extension_cards(logged_in, monkeypatch):
    from netwatch import health as nw_health
    monkeypatch.setattr(nw_health, "check_all", lambda *a, **k: ([], "down"))
    resp = logged_in.get("/status")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "netwatch-pro" in html          # ligne « Extension Pro » de la carte Licence
    assert "Assistant IA — usage" not in html   # édition Core : aucun appel IA journalisé → carte masquée
