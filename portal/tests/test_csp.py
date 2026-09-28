"""Content-Security-Policy du portail : en-tête, nonce par requête, modes, conventions des templates."""
import re
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parents[1] / "templates"


def _csp(resp):
    return resp.headers.get("Content-Security-Policy", "")


def test_csp_header_present_and_strict(client):
    csp = _csp(client.get("/login"))
    assert "default-src 'self'" in csp
    assert re.search(r"script-src 'self' 'nonce-[A-Za-z0-9_-]{16,}'", csp)
    assert "'unsafe-eval'" not in csp
    assert "script-src 'self' 'unsafe-inline'" not in csp
    for directive in ("frame-ancestors 'none'", "form-action 'self'", "base-uri 'self'",
                      "object-src 'none'", "report-uri /csp-report"):
        assert directive in csp


def test_csp_nonce_matches_inline_scripts_and_rotates(logged_in):
    client = logged_in
    resp = client.get("/hostgroups")  # page complète (base.html : script de thème anticipé + navigation)
    assert resp.status_code == 200
    nonce = re.search(r"'nonce-([A-Za-z0-9_-]+)'", _csp(resp)).group(1)
    html = resp.get_data(as_text=True)
    inline = re.findall(r"<script(?![^>]*\bsrc=)([^>]*)>", html)
    assert inline, "la page doit contenir au moins un script inline (thème anticipé)"
    for attrs in inline:
        if 'type="application/json"' in attrs:
            continue
        assert f'nonce="{nonce}"' in attrs, attrs
    assert nonce != re.search(r"'nonce-([A-Za-z0-9_-]+)'", _csp(client.get("/hostgroups"))).group(1)


def test_csp_on_error_pages(client):
    resp = client.get("/cette-page-n-existe-pas")
    assert resp.status_code == 404
    assert "script-src 'self' 'nonce-" in _csp(resp)


def test_csp_report_only_and_off(client, app_module, monkeypatch):
    monkeypatch.setattr(app_module.config, "CSP_MODE", "report-only")
    resp = client.get("/login")
    assert "Content-Security-Policy" not in resp.headers
    assert "script-src 'self' 'nonce-" in resp.headers["Content-Security-Policy-Report-Only"]
    monkeypatch.setattr(app_module.config, "CSP_MODE", "off")
    resp = client.get("/login")
    assert "Content-Security-Policy" not in resp.headers
    assert "Content-Security-Policy-Report-Only" not in resp.headers


def test_csp_report_endpoint_is_public_and_tolerant(client):
    body = {"csp-report": {"document-uri": "https://sonde/", "blocked-uri": "inline",
                           "effective-directive": "script-src"}}
    assert client.post("/csp-report", json=body).status_code == 204
    assert client.post("/csp-report", data="pas du json").status_code == 204
    assert client.post("/csp-report", data="x" * 100_000).status_code == 204


def test_templates_have_no_inline_handlers_and_scripts_carry_nonce():
    """Interdits par la CSP : onclick= & co ; obligatoire : nonce sur chaque <script> inline exécutable."""
    for tpl in sorted(TEMPLATES.glob("*.html")):
        text = tpl.read_text(encoding="utf-8")
        for i, line in enumerate(text.splitlines(), 1):
            assert not re.search(r'\son[a-z]+="', line), f"{tpl.name}:{i} — gestionnaire inline"
            assert "javascript:" not in line, f"{tpl.name}:{i} — URL javascript:"
        for attrs in re.findall(r"<script(?![^>]*\bsrc=)([^>]*)>", text):
            if 'type="application/json"' in attrs:
                continue
            assert 'nonce="{{ csp_nonce }}"' in attrs, f"{tpl.name} — <script{attrs}> sans nonce"
