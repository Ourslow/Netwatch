"""
Authentification du portail : compte d'amorçage, rôles, journal.

Édition Community : un seul compte, PORTAL_USERNAME / PORTAL_PASSWORD du .env,
administrateur. Édition Pro : l'extension netwatch_pro.rbac enregistre ici un
« magasin » de comptes nominatifs (set_store) — portal/data/users.json, mots de
passe hachés, rôles, page /admin/users. Les fonctions de lecture ci-dessous
interrogent d'abord ce magasin s'il est présent, puis le compte d'amorçage, qui
reste un administrateur valide tant que PORTAL_PASSWORD est renseigné (secours
si tous les comptes sont perdus). Un compte stocké portant le même nom prend
le pas sur lui.

Rôles, du moins au plus étendu :
  viewer    lecture seule — toutes les pages, aucune action (POST/PUT/PATCH/DELETE refusés)
  operator  exploitation — seuils, hostgroups, rapports, disposition, actions VM…
  admin     tout, plus la licence et (Pro) la gestion des comptes

Journal des connexions et des actions d'administration : portal/data/auth.log
(une ligne JSON par événement, jamais de mot de passe) — dans les deux éditions.

Contrat du magasin (module ou objet) : has(username) → bool ; get(username) →
compte public (sans hash) ou None ; verify(username, password) → compte ou None ;
list_users() → comptes publics ; touch_login(username).
"""
import hmac
import json
import os
from datetime import datetime, timezone

import config

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
AUTH_LOG_PATH = os.path.join(DATA_DIR, "auth.log")

ROLES = ("viewer", "operator", "admin")
ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}
ROLE_LABELS = {"viewer": "Lecture", "operator": "Opérateur", "admin": "Administrateur"}
AUTH_LOG_MAX_LINES = 5000

_STORE = None


def set_store(store):
    """Magasin de comptes nominatifs (édition Pro) ; None = compte d'amorçage seul."""
    global _STORE
    _STORE = store


def store():
    return _STORE


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def env_admin():
    """Compte d'amorçage défini par le .env (None si PORTAL_PASSWORD est vide)."""
    if config.PORTAL_USERNAME and config.PORTAL_PASSWORD:
        return {"username": config.PORTAL_USERNAME, "role": "admin", "disabled": False,
                "source": "env", "created_at": None, "last_login": None}
    return None


# ── Lecture ──────────────────────────────────────────────────────────────────

def list_users():
    """Tous les comptes (le compte d'amorçage en premier s'il n'est pas remplacé)."""
    out = []
    env = env_admin()
    if env and not (_STORE and _STORE.has(env["username"])):
        out.append(env)
    if _STORE:
        out.extend(_STORE.list_users())
    return out


def get_user(username):
    if _STORE and _STORE.has(username):
        return _STORE.get(username)
    env = env_admin()
    return env if env and env["username"] == username else None


def get_active(username):
    u = get_user(username)
    return u if u and not u.get("disabled") else None


def verify(username, password):
    """Identifiants valides → compte (sans hash) ; sinon None. Temps constant sur le compte d'amorçage."""
    if _STORE and _STORE.has(username):
        return _STORE.verify(username, password)
    env = env_admin()
    if env is None:
        return None
    ok_u = hmac.compare_digest(username.encode(), config.PORTAL_USERNAME.encode())
    ok_p = hmac.compare_digest(password.encode(), config.PORTAL_PASSWORD.encode())
    return env if ok_u and ok_p else None


def touch_login(username):
    if _STORE:
        _STORE.touch_login(username)


# ── Journal ──────────────────────────────────────────────────────────────────

def log_event(kind, username=None, ip=None, detail=""):
    """Ajoute une ligne JSON au journal d'authentification (jamais de mot de passe)."""
    os.makedirs(DATA_DIR, exist_ok=True)
    line = json.dumps({"ts": _now(), "kind": kind, "user": username or "", "ip": ip or "", "detail": detail},
                      ensure_ascii=False)
    try:
        with open(AUTH_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        _rotate_if_needed()
    except OSError:
        pass


def _rotate_if_needed():
    try:
        if os.path.getsize(AUTH_LOG_PATH) < 1_000_000:
            return
        with open(AUTH_LOG_PATH, encoding="utf-8") as f:
            lines = f.readlines()[-AUTH_LOG_MAX_LINES:]
        tmp = AUTH_LOG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.writelines(lines)
        os.replace(tmp, AUTH_LOG_PATH)
    except OSError:
        pass


def list_events(limit=50):
    """Derniers événements, le plus récent en premier."""
    try:
        with open(AUTH_LOG_PATH, encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
