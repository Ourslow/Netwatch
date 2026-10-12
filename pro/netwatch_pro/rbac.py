"""
Comptes nominatifs et rôles (édition Pro) — magasin de comptes et page /admin/users.

Stockage : portal/data/users.json (sauvegardé par scripts/backup.sh avec le reste de
portal/data), mots de passe hachés (werkzeug, scrypt). Ce module est enregistré
auprès du portail comme magasin de comptes (netwatch.users.set_store) : la
connexion, le chargement de session et /auth/check passent par lui pour les comptes
stockés, et retombent sur le compte d'amorçage du .env sinon. Rôles, journal et
garde-fou « rôle lecture » sont dans le portail Community (netwatch.users).
"""
import json
import os
import re

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user
from werkzeug.security import check_password_hash, generate_password_hash

from netwatch import users as nw_users

DATA_DIR = nw_users.DATA_DIR
USERS_PATH = os.path.join(DATA_DIR, "users.json")

ROLES = nw_users.ROLES
ROLE_LABELS = nw_users.ROLE_LABELS
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
MIN_PASSWORD = 12


def _now():
    return nw_users._now()


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


def _public(u):
    return {k: v for k, v in u.items() if k != "password_hash"} | {"source": "store"}


# ── Contrat du magasin (netwatch.users) ──────────────────────────────────────

def has(username):
    return username in _load()


def get(username):
    u = _load().get(username)
    return _public(u) if u else None


def verify(username, password):
    u = _load().get(username)
    if u is None or u.get("disabled") or not check_password_hash(u.get("password_hash", ""), password):
        return None
    return _public(u)


def list_users():
    return [_public(u) for u in sorted(_load().values(), key=lambda u: u["username"])]


def touch_login(username):
    users = _load()
    if username in users:
        users[username]["last_login"] = _now()
        _save(users)


def active_admin_count():
    users = _load()
    n = sum(1 for u in users.values() if u.get("role") == "admin" and not u.get("disabled"))
    env = nw_users.env_admin()
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
    nw_users.log_event("user_created", actor, detail=f"{username} ({role})")
    return _public(users[username])


def _stored(username):
    users = _load()
    if username not in users:
        env = nw_users.env_admin()
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
    nw_users.log_event("user_role", actor, detail=f"{username} → {role}")


def set_password(username, password, actor=None):
    _validate_password(password)
    users = _stored(username)
    users[username]["password_hash"] = generate_password_hash(password)
    _save(users)
    nw_users.log_event("user_password", actor, detail=username)


def set_disabled(username, disabled, actor=None):
    users = _stored(username)
    if disabled:
        _guard_last_admin(users, username, False)
    users[username]["disabled"] = bool(disabled)
    _save(users)
    nw_users.log_event("user_disabled" if disabled else "user_enabled", actor, detail=username)


def delete_user(username, actor=None):
    users = _stored(username)
    _guard_last_admin(users, username, False)
    del users[username]
    _save(users)
    nw_users.log_event("user_deleted", actor, detail=username)


# ── Page d'administration ────────────────────────────────────────────────────

def register(bp, api):
    import sys
    api.set_user_store(sys.modules[__name__])

    @bp.route("/admin/users")
    @api.login_required
    @api.admin_required
    @api.pro_required("rbac")
    def admin_users():
        return render_template("pro/admin_users.html", users=nw_users.list_users(), events=nw_users.list_events(50),
                               roles=ROLES, role_labels=ROLE_LABELS, min_password=MIN_PASSWORD)

    @bp.route("/admin/users", methods=["POST"])
    @api.login_required
    @api.admin_required
    @api.pro_required("rbac")
    def admin_users_create():
        try:
            u = create_user(request.form.get("username", "").strip(), request.form.get("password", ""),
                            request.form.get("role", "viewer"), actor=current_user.username)
            flash(f"Compte « {u['username']} » créé ({ROLE_LABELS[u['role']]}).", "success")
        except ValueError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("pro.admin_users"))

    @bp.route("/admin/users/<username>", methods=["POST"])
    @api.login_required
    @api.admin_required
    @api.pro_required("rbac")
    def admin_users_update(username):
        action = request.form.get("action", "")
        try:
            if action in ("disable", "delete", "role") and username == current_user.username:
                raise ValueError("Vous ne pouvez pas désactiver, supprimer ni rétrograder votre propre compte.")
            if action == "role":
                set_role(username, request.form.get("role", ""), actor=current_user.username)
            elif action == "password":
                set_password(username, request.form.get("password", ""), actor=current_user.username)
            elif action in ("disable", "enable"):
                set_disabled(username, action == "disable", actor=current_user.username)
            elif action == "delete":
                delete_user(username, actor=current_user.username)
            else:
                raise ValueError("Action inconnue.")
            flash(f"Compte « {username} » mis à jour.", "success")
        except ValueError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("pro.admin_users"))

    api.add_nav("infra", "Comptes et rôles", "pro.admin_users", "bi-people", i18n="nav_users", admin_only=True)
