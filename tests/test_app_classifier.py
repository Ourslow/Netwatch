"""
Garde-fous sur la table port → application de scripts/automation/app-classifier.py.

Le dict Python absorbe silencieusement les clés répétées (la dernière gagne),
donc on inspecte le SOURCE via `ast` : chaque port et chaque service Zeek ne
doivent apparaître qu'une fois, sinon la classification dépend de l'ordre
d'écriture. Le module est ensuite importé pour vérifier les libellés visibles
dans le portail (/applications, /app-map).
"""
import ast
import importlib.util
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CLASSIFIER = ROOT / "scripts" / "automation" / "app-classifier.py"

CATEGORIES = {"web", "remote-access", "file-share", "email", "database",
              "collaboration", "streaming", "infrastructure", "security"}


def _dict_literal(name: str) -> ast.Dict:
    """Retourne le littéral `{...}` affecté à `name` dans le source du classifieur."""
    tree = ast.parse(CLASSIFIER.read_text(encoding="utf-8"))
    for node in tree.body:
        target = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target = node.target.id
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
        if target == name and isinstance(node.value, ast.Dict):
            return node.value
    pytest.fail(f"{name} : littéral dict introuvable dans {CLASSIFIER.name}")


@pytest.fixture(scope="module")
def classifier():
    spec = importlib.util.spec_from_file_location("app_classifier", CLASSIFIER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("name", ["PORT_APP_MAP", "ZEEK_SERVICE_MAP"])
def test_source_has_no_repeated_keys(name):
    literal = _dict_literal(name)
    keys = [k.value for k in literal.keys if isinstance(k, ast.Constant)]
    assert len(keys) == len(literal.keys), f"{name} : clé non littérale"
    repeated = {k: (line, n) for k, n in Counter(keys).items() if n > 1
                for line in [next(kk.lineno for kk in literal.keys if kk.value == k)]}
    assert not repeated, f"{name} : clés répétées (la dernière gagne en silence) → {repeated}"


def test_port_map_entries_are_well_formed(classifier):
    assert len(classifier.PORT_APP_MAP) >= 400
    for port, (app, cat) in classifier.PORT_APP_MAP.items():
        assert isinstance(port, int) and 0 < port <= 65535, port
        assert app and app != "Unknown", port
        assert cat in CATEGORIES, f"port {port} : catégorie inconnue {cat!r}"
    for svc, (app, cat) in classifier.ZEEK_SERVICE_MAP.items():
        assert svc == svc.strip().lower(), svc
        assert cat in CATEGORIES, f"service {svc} : catégorie inconnue {cat!r}"


@pytest.mark.parametrize("port,expected", [
    (443,  ("HTTPS", "web")),
    (22,   ("SSH", "remote-access")),
    (53,   ("DNS", "infrastructure")),
    (161,  ("SNMP", "infrastructure")),
    (514,  ("Syslog", "infrastructure")),
    (8080, ("HTTP-Proxy", "web")),
    (8443, ("HTTPS-Alt2", "web")),
    (9200, ("Elasticsearch", "database")),
])
def test_common_ports_get_generic_labels(classifier, port, expected):
    """Ports courants en PME : libellé générique, pas un produit précis."""
    assert classifier.lookup_port(port) == expected


def test_lookup_fallbacks(classifier):
    assert classifier.lookup_port(None) == ("Unknown", "unknown")
    assert classifier.lookup_port(65000) == ("Unknown", "unknown")
    assert classifier.lookup_zeek_service("SSL") == ("HTTPS", "web")
    assert classifier.lookup_zeek_service(None, 22) == ("SSH", "remote-access")
    assert classifier.lookup_zeek_service("nope", None) == ("Unknown", "unknown")
