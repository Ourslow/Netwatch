"""
Chargement des extensions du portail — point d'ancrage de l'édition Pro.

Le portail Community (ce dépôt, AGPL v3) est complet seul. Les fonctions de
l'édition Pro vivent dans un paquet Python séparé `netwatch_pro` (dépôt privé
`netwatch-pro` ; pendant la phase de validation, le paquet est dans `pro/` à la
racine du dépôt). Au démarrage, le portail le cherche et, s'il est présent,
appelle `netwatch_pro.register(api)` : l'extension enregistre ses blueprints,
ses entrées de menu, ses cartes de statut et ses variables de template via
l'objet `ExtensionAPI`. Absent → édition Community, sans aucune erreur.

Recherche du paquet, dans l'ordre :
  1. NETWATCH_PRO=off            → jamais chargé (tests, démo Community)
  2. NETWATCH_PRO_PATH=<dossier> → ajouté à sys.path (ex. /opt/netwatch-pro)
  3. <racine du dépôt>/pro       → copie de travail pendant la validation
  4. paquet installé (pip install netwatch-pro)

Contrat : l'extension s'exécute dans le processus du portail, avec `portal/`
sur sys.path ; elle peut importer `config` et `netwatch.*`. Une exception
dans `register()` est journalisée et le portail continue en Community : une
extension ne doit jamais empêcher la sonde de démarrer.
"""
import importlib
import logging
import os
import sys

log = logging.getLogger("netwatch.extensions")

PACKAGE = "netwatch_pro"
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
INTREE_PATH = os.path.join(ROOT, "pro")

# Sections du menu latéral (base.html) dans lesquelles une extension peut insérer des liens.
NAV_SECTIONS = ("obs", "sec", "report", "infra")


class ExtensionAPI:
    """Ce que le portail met à disposition d'une extension (`register(api)`)."""

    def __init__(self, app, *, login_required, admin_required, pro_required, config):
        self.app = app
        self.config = config
        self.login_required = login_required
        self.admin_required = admin_required
        self.pro_required = pro_required
        self.name = None
        self.version = None
        self.features = []            # clés de netwatch.license.PRO_FEATURES fournies par l'extension
        self.nav = {s: [] for s in NAV_SECTIONS}
        self.commands = []            # entrées de la palette de commandes (Ctrl+K)
        self.partials = {}            # slot → [template] (ex. "status" → carte LLMOps)
        self.status_providers = {}    # nom → callable() ; résultat exposé en `ext.<nom>` sur /status
        self.globals = {}             # variables de template fournies par l'extension

    # ── Déclaration ────────────────────────────────────────────────────────
    def describe(self, name, version, features=()):
        self.name, self.version, self.features = name, version, list(features)

    def register_blueprint(self, bp, **options):
        self.app.register_blueprint(bp, **options)

    def add_nav(self, section, label, endpoint, icon, *, i18n=None, admin_only=False, blank=False):
        if section not in self.nav:
            raise ValueError(f"section de menu inconnue : {section} (attendu : {', '.join(NAV_SECTIONS)})")
        self.nav[section].append({"label": label, "endpoint": endpoint, "icon": icon,
                                  "i18n": i18n, "admin_only": admin_only, "blank": blank})

    def add_command(self, label, url, icon, hint="", key=None):
        self.commands.append({"icon": icon, "label": label, "url": url, "hint": hint, "key": key})

    def add_partial(self, slot, template):
        self.partials.setdefault(slot, []).append(template)

    def add_status_provider(self, name, fn):
        self.status_providers[name] = fn

    def provide(self, name, value):
        """Variable de template (globale) — ex. ai_enabled."""
        self.globals[name] = value

    # ── Lecture (portail) ─────────────────────────────────────────────────
    def status_extra(self):
        """Appelle chaque fournisseur de statut ; une erreur n'en masque pas un autre."""
        out = {}
        for name, fn in self.status_providers.items():
            try:
                out[name] = fn()
            except Exception as exc:   # noqa: BLE001 — l'extension ne doit pas casser /status
                log.warning("extension %s : fournisseur de statut %s en erreur : %s", self.name, name, exc)
                out[name] = None
        return out


# État exposé au reste du portail (page Statut, make license-status, tests).
STATE = {"loaded": False, "name": None, "version": None, "features": [], "source": None, "error": None}
_API = None


def api():
    return _API


def _candidate_paths():
    env_path = os.getenv("NETWATCH_PRO_PATH", "").strip()
    if env_path:
        yield env_path, "NETWATCH_PRO_PATH"
    if os.path.isdir(os.path.join(INTREE_PATH, PACKAGE)):
        yield INTREE_PATH, "pro/ (copie de travail)"


def _import_package(paths=None):
    """Importe netwatch_pro depuis les chemins candidats puis sys.path. Retourne (module, source)."""
    for path, source in (paths if paths is not None else _candidate_paths()):
        if path not in sys.path:
            sys.path.insert(0, path)
        try:
            return importlib.import_module(PACKAGE), source
        except ModuleNotFoundError as exc:
            if exc.name != PACKAGE:
                raise
    try:
        return importlib.import_module(PACKAGE), "paquet installé"
    except ModuleNotFoundError as exc:
        if exc.name != PACKAGE:
            raise
    return None, None


def load(app, *, login_required, admin_required, pro_required, config, enabled=None, paths=None):
    """Charge l'extension (si présente) et branche le contexte Jinja. Toujours sans exception."""
    global _API
    api_obj = ExtensionAPI(app, login_required=login_required, admin_required=admin_required,
                           pro_required=pro_required, config=config)
    _API = api_obj
    STATE.update({"loaded": False, "name": None, "version": None, "features": [], "source": None, "error": None})

    if enabled is None:
        enabled = os.getenv("NETWATCH_PRO", "auto").strip().lower() != "off"
    if enabled:
        try:
            module, source = _import_package(paths)
            if module is None:
                STATE["source"] = "aucun paquet trouvé"
                log.info("extension %s absente : édition Community", PACKAGE)
            else:
                module.register(api_obj)
                STATE.update({"loaded": True, "name": api_obj.name or PACKAGE,
                              "version": api_obj.version or getattr(module, "__version__", None),
                              "features": list(api_obj.features), "source": source})
                log.info("extension %s %s chargée (%s) : %s", STATE["name"], STATE["version"] or "",
                         source, ", ".join(STATE["features"]) or "aucune fonction déclarée")
        except Exception as exc:   # noqa: BLE001 — une extension cassée ne doit pas empêcher le démarrage
            STATE["error"] = f"{type(exc).__name__}: {exc}"
            log.exception("extension %s : échec du chargement, portail en édition Community", PACKAGE)
            # On repart d'un objet vierge : rien de ce que l'extension a pu déclarer à moitié ne doit fuir.
            api_obj = ExtensionAPI(app, login_required=login_required, admin_required=admin_required,
                                   pro_required=pro_required, config=config)
            _API = api_obj
    else:
        STATE["source"] = "désactivée (NETWATCH_PRO=off)"

    @app.context_processor
    def _inject_extension():
        return {"ai_enabled": False, **api_obj.globals,
                "ext_nav": api_obj.nav, "ext_commands": api_obj.commands,
                "ext_partials": api_obj.partials, "pro_ext": dict(STATE)}

    return api_obj


def has_feature(name):
    return STATE["loaded"] and name in STATE["features"]


def probe():
    """Trouve le paquet sans l'enregistrer (CLI, make license-status) : (version, source) ou (None, None)."""
    try:
        module, source = _import_package()
    except Exception as exc:   # noqa: BLE001
        return f"erreur : {type(exc).__name__}: {exc}", None
    if module is None:
        return None, None
    return getattr(module, "__version__", "?"), source


def describe():
    """Une ligne pour la CLI / make license-status."""
    if STATE["loaded"]:
        return "Extension Pro : %s %s (%s) — %s" % (STATE["name"], STATE["version"] or "", STATE["source"],
                                                    ", ".join(STATE["features"]) or "aucune fonction")
    if STATE["error"]:
        return "Extension Pro : erreur de chargement — %s" % STATE["error"]
    if STATE["source"]:
        return "Extension Pro : absente (%s)" % STATE["source"]
    if os.getenv("NETWATCH_PRO", "auto").strip().lower() == "off":
        return "Extension Pro : désactivée (NETWATCH_PRO=off)"
    version, source = probe()   # hors portail (CLI) : rien n'a encore été chargé
    if source:
        return "Extension Pro : %s %s trouvée (%s) — chargée au démarrage du portail" % (PACKAGE, version, source)
    return "Extension Pro : absente (édition Community)"
