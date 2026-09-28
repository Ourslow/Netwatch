"""
Comptes nominatifs et rôles du portail.

Stockage : portal/data/users.json (sauvegardé par scripts/backup.sh avec le reste
de portal/data), mots de passe hachés (werkzeug, scrypt). Journal des connexions et
des actions d'administration : portal/data/auth.log (une ligne JSON par événement).

Rôles, du moins au plus étendu :
  viewer    lecture seule — toutes les pages, aucune action (POST/PUT/PATCH/DELETE refusés)
  operator  exploitation — seuils, hostgroups, rapports, disposition, actions VM…
  admin     tout, plus la gestion des comptes (/admin/users)

Compte d'amorçage : PORTAL_USERNAME / PORTAL_PASSWORD du .env restent un
administrateur valide tant que PORTAL_PASSWORD est renseigné (installation sans
étape supplémentaire, secours si tous les comptes sont perdus). Un compte stocké
portant le même nom prend le pas sur lui.
"""
import hmac
import json
import os
import re
from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

import config

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
USERS_PATH = os.path.join(DATA_DIR, "users.json")
AUTH_LOG_PATH = os.path.join(DATA_DIR, "auth.log")

ROLES = ("viewer", "operator", "admin")
ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}
ROLE_LABELS = {"viewer": "Lecture", "operator": "Opérateur", "admin": "Administrateur"}
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
MIN_PASSWORD = 12
AUTH_LOG_MAX_LINES = 5000


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load():
    try:
        with open(USERS_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return {u["username"]: u for u in data.get("users", []) if u.get("username")}
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return {}


def _save(users):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = USERS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"users": list(users.values())}, f, ensure_ascii=False, indent=2)
    os.replace(tmp, USERS_PATH)
    try:
        os.chmod(USERS_PATH, 0o600)
    except OSError:
        pass


def _env_admin():
    """Compte d'amorçage défini par le .env (None si PORTAL_PASSWORD est vide)."""
    if config.PORTAL_USERNAME and config.PORTAL_PASSWORD:
        return {"username": config.PORTAL_USERNAME, "role": "admin", "disabled": False,
                "source": "env", "created_at": None, "last_login": None}
    return None


def _public(u):
    return {k: v for k, v in u.items() if k != "password_hash"}


# ── Lecture ──────────────────────────────────────────────────────────────────

def list_users():
    """Tous les comptes (le compte d'amorçage en premier s'il n'est pas remplacé)."""
    users = _load()
    out = []
    env = _env_admin()
    if env and env["username"] not in users:
        out.append(env)
    out.extend(_public(u) | {"source": "store"} for u in sorted(users.values(), key=lambda u: u["username"]))
    return out


def get_user(username):
    users = _load()
    if username in users:
        return _public(users[username]) | {"source": "store"}
    env = _env_admin()
    return env if env and env["username"] == username else None


def get_active(username):
    u = get_user(username)
    return u if u and not u.get("disabled") else None


def verify(username, password):
    """Identifiants valides → compte (sans hash) ; sinon None. Temps constant sur le compte d'amorçage."""
    users = _load()
    u = users.get(username)
    if u is not None:
        if u.get("disabled") or not check_password_hash(u.get("password_hash", ""), password):
            return None
        return _public(u) | {"source": "store"}
    env = _env_admin()
    if env is None:
        return None
    ok_u = hmac.compare_digest(username.encode(), config.PORTAL_USERNAME.encode())
    ok_p = hmac.compare_digest(password.encode(), config.PORTAL_PASSWORD.encode())
    return env if ok_u and ok_p else None


def active_admin_count():
    users = _load()
    n = sum(1 for u in users.values() if u.get("role") == "admin" and not u.get("disabled"))
    env = _env_admin()
    if env and env["username"] not in users:
        n += 1
    return n


# ── Écriture ─────────────────────────────────────────────────────────────────

def _validate_username(username):
    if not USERNAME_RE.match(username or ""):
        raise ValueError("Identifiant invalide : 2 à 32 caractères, minuscules, chiffres, « . _ - », "
                         "commençant par une lettre ou un chiffre.")


def _validate_password(password):
    if len(password or "") < MIN_PASSWORD:
        raise ValueError(f"Mot de passe trop court : {MIN_PASSWORD} caractères minimum.")


def _validate_role(role):
    if role not in ROLES:
        raise ValueError(f"Rôle inconnu : {role}.")


def create_user(username, password, role, actor=None):
    _validate_username(username)
    _validate_password(password)
    _validate_role(role)
    users = _load()
    if username in users:
        raise ValueError(f"Le compte « {username} » existe déjà.")
    users[username] = {"username": username, "password_hash": generate_password_hash(password),
                       "role": role, "disabled": False, "created_at": _now(), "created_by": actor,
                       "last_login": None}
    _save(users)
    log_event("user_created", actor, detail=f"{username} ({role})")
    return _public(users[username]) | {"source": "store"}


def _stored(username):
    users = _load()
    if username not in users:
        env = _env_admin()
        if env and env["username"] == username:
            raise ValueError("Le compte d'amorçage est défini par PORTAL_USERNAME / PORTAL_PASSWORD dans .env : "
                             "il se modifie ou se retire là, pas ici.")
        raise ValueError(f"Compte inconnu : {username}.")
    return users


def _guard_last_admin(users, username, will_be_admin_active):
    if users[username].get("role") == "admin" and not users[username].get("disabled") and not will_be_admin_active:
        if active_admin_count() <= 1:
            raise ValueError("Impossible : ce compte est le dernier administrateur actif.")


def set_role(username, role, actor=None):
    _validate_role(role)
    users = _stored(username)
    _guard_last_admin(users, username, role == "admin")
    users[username]["role"] = role
    _save(users)
    log_event("user_role", actor, detail=f"{username} → {role}")


def set_password(username, password, actor=None):
    _validate_password(password)
    users = _stored(username)
    users[username]["password_hash"] = generate_password_hash(password)
    _save(users)
    log_event("user_password", actor, detail=username)


def set_disabled(username, disabled, actor=None):
    users = _stored(username)
    if disabled:
        _guard_last_admin(users, username, False)
    users[username]["disabled"] = bool(disabled)
    _save(users)
    log_event("user_disabled" if disabled else "user_enabled", actor, detail=username)


def delete_user(username, actor=None):
    users = _stored(username)
    _guard_last_admin(users, username, False)
    del users[username]
    _save(users)
    log_event("user_deleted", actor, detail=username)


def touch_login(username):
    users = _load()
    if username in users:
        users[username]["last_login"] = _now()
        _save(users)


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
