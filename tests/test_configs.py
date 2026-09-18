"""
Tests de cohérence des fichiers de configuration du stack (pas de Docker
requis) : JSON/YAML valides et conventions du projet (CLAUDE.md).
"""
import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent

COMPOSE_FILES = sorted(ROOT.glob("docker-compose*.yml"))
DASHBOARDS = sorted((ROOT / "grafana" / "dashboards").glob("*.json"))
YAML_FILES = sorted(
    list((ROOT / "grafana" / "provisioning").rglob("*.y*ml"))
    + list((ROOT / "prometheus").rglob("*.yml"))
    + list((ROOT / "filebeat").glob("*.yml"))
    + [ROOT / "suricata" / "suricata.yaml"]
)


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda p: p.name)
def test_grafana_dashboard_is_valid(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data.get("title"), f"{path.name} : titre manquant"
    assert data.get("uid"), f"{path.name} : uid manquant"
    assert isinstance(data.get("panels"), list)


def test_grafana_dashboard_uids_are_unique():
    uids = [json.loads(p.read_text(encoding="utf-8"))["uid"] for p in DASHBOARDS]
    assert len(uids) == len(set(uids)), "uid de dashboard dupliqué"


@pytest.mark.parametrize("path", YAML_FILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_yaml_is_valid(path):
    with path.open(encoding="utf-8") as f:
        assert yaml.safe_load(f) is not None


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_compose_containers_are_prefixed(path):
    with path.open(encoding="utf-8") as f:
        compose = yaml.safe_load(f)
    services = compose.get("services") or {}
    assert services, f"{path.name} : aucun service"
    for name, svc in services.items():
        cname = (svc or {}).get("container_name")
        assert cname, f"{path.name} : service {name} sans container_name"
        assert cname.startswith("netwatch-"), f"{path.name} : {name} → {cname} (préfixe netwatch- attendu)"


def test_compose_files_do_not_hardcode_secrets():
    """Les mots de passe passent par ${VAR} depuis .env, jamais en clair."""
    suspicious = re.compile(r"(PASSWORD|SECRET|TOKEN)\s*[=:]\s*['\"]?[A-Za-z0-9]{8,}", re.I)
    for path in COMPOSE_FILES:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if suspicious.search(line) and "${" not in line and not line.lstrip().startswith("#"):
                pytest.fail(f"{path.name}:{lineno} ressemble à un secret en clair : {line.strip()}")


def test_env_example_has_no_real_secrets():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "DRY_RUN=true" in text
    for lineno, line in enumerate(text.splitlines(), 1):
        if re.match(r"^\s*[A-Z_]*(PASSWORD|SECRET|TOKEN)[A-Z_]*=(.+)$", line):
            value = line.split("=", 1)[1].strip()
            assert value in ("", "changeme") or "change" in value.lower() or "votre" in value.lower(), \
                f".env.example:{lineno} contient une valeur qui ressemble à un vrai secret"


def _sids(path):
    return [int(s) for s in re.findall(r"\bsid\s*:\s*(\d+)", path.read_text(encoding="utf-8"))]


def test_snort_custom_sids_in_range():
    sids = _sids(ROOT / "snort" / "local.rules")
    assert sids, "aucune règle Snort custom"
    assert all(1000001 <= s <= 1000999 for s in sids), sorted(s for s in sids if not 1000001 <= s <= 1000999)
    assert len(sids) == len(set(sids)), "SID Snort dupliqué"


def test_suricata_custom_sids_in_range():
    sids = _sids(ROOT / "suricata" / "local.rules")
    assert sids, "aucune règle Suricata custom"
    assert all(2000001 <= s <= 2000999 for s in sids), sorted(s for s in sids if not 2000001 <= s <= 2000999)
    assert len(sids) == len(set(sids)), "SID Suricata dupliqué"


def _compose(path):
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


@pytest.mark.parametrize("name", ["docker-compose.yml", "docker-compose.data.yml"], ids=str)
def test_caddy_is_opt_in_and_gets_every_caddyfile_variable(name):
    """Chaque {$VAR} du Caddyfile doit être fourni par le service caddy, et le
    proxy ne doit jamais démarrer sans le profil « proxy » (labo inchangé)."""
    caddyfile = (ROOT / "caddy" / "Caddyfile").read_text(encoding="utf-8")
    wanted = set(re.findall(r"\{\$([A-Z_]+)", caddyfile))
    assert wanted, "aucune variable dans le Caddyfile ?"
    caddy = _compose(ROOT / name)["services"]["caddy"]
    assert caddy.get("profiles") == ["proxy"]
    assert caddy.get("network_mode") == "host"
    provided = {e.split("=", 1)[0] for e in caddy["environment"]}
    assert wanted <= provided, f"{name} : variables manquantes pour Caddy : {sorted(wanted - provided)}"


@pytest.mark.parametrize("name,expected", [
    ("docker-compose.yml", ["${NETWATCH_PUBLIC_URL:+/grafana/}", "GF_AUTH_PROXY_ENABLED=${NETWATCH_PUBLIC_URL:+true}",
                            "SERVER_BASEPATH=${NETWATCH_PUBLIC_URL:+/kibana}", "--http-prefix=${NETWATCH_PUBLIC_URL:+/ntopng}",
                            "BASE_PATH=${NETWATCH_PUBLIC_URL:+netbox/}", "ARKIME__webBasePath=${ARKIME_WEB_BASE_PATH:-/}"]),
    ("docker-compose.data.yml", ["${NETWATCH_PUBLIC_URL:+/grafana/}", "GF_AUTH_PROXY_ENABLED=${NETWATCH_PUBLIC_URL:+true}",
                                 "SERVER_BASEPATH=${NETWATCH_PUBLIC_URL:+/kibana}", "BASE_PATH=${NETWATCH_PUBLIC_URL:+netbox/}"]),
    ("docker-compose.sensors.yml", ["--http-prefix=${NETWATCH_PUBLIC_URL:+/ntopng}", "ARKIME__webBasePath=${ARKIME_WEB_BASE_PATH:-/}"]),
], ids=lambda v: v if isinstance(v, str) else "")
def test_proxy_settings_are_conditional(name, expected):
    """Les sous-chemins et l'auth proxy n'existent que si NETWATCH_PUBLIC_URL
    est renseignée (${VAR:+…}) : le labo (variable vide) reste strictement inchangé."""
    text = (ROOT / name).read_text(encoding="utf-8")
    for token in expected:
        assert token in text, f"{name} : {token} absent"


def test_version_is_semver_and_in_changelog():
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), version
    assert f"## {version}" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def test_install_generates_every_required_compose_secret():
    """Chaque variable exigée par compose (${VAR:?}) et chaque secret du portail
    doit être généré par install.sh — sinon l'installation en une commande casse."""
    required = set()
    for path in COMPOSE_FILES:
        required |= set(re.findall(r"\$\{([A-Z_]+):\?", path.read_text(encoding="utf-8")))
    required |= {"FLASK_SECRET_KEY", "PORTAL_PASSWORD", "AUTOBLOCK_WEBHOOK_SECRET", "KIBANA_ENCRYPTION_KEY"}
    install = (ROOT / "install.sh").read_text(encoding="utf-8")
    generated = set(re.findall(r"env_set (?:\.env|portal/\.env)\s+([A-Z_]+)\s+\"\$\(gen_", install))
    assert required <= generated, f"non générés par install.sh : {sorted(required - generated)}"


def test_es_snapshot_repository_is_wired():
    """backup.sh/restore.sh utilisent un dépôt fs : le chemin doit être déclaré
    en path.repo et monté sur le volume es-snapshots dans les deux compose ES."""
    backup = (ROOT / "scripts" / "backup.sh").read_text(encoding="utf-8")
    restore = (ROOT / "scripts" / "restore.sh").read_text(encoding="utf-8")
    (repo_path,) = set(re.findall(r'ES_REPO_PATH="([^"]+)"', backup)) | set(re.findall(r'ES_REPO_PATH="([^"]+)"', restore))
    for name in ("docker-compose.yml", "docker-compose.data.yml"):
        es = _compose(ROOT / name)["services"]["elasticsearch"]
        assert f"path.repo={repo_path}" in es["environment"], name
        assert f"es-snapshots:{repo_path}" in es["volumes"], name
        assert "es-snapshots" in _compose(ROOT / name)["volumes"], name


def test_zeek_logs_are_json():
    zeek_scripts = list((ROOT / "zeek").rglob("*.zeek"))
    assert any("LogAscii::use_json" in p.read_text(encoding="utf-8") and "= T" in p.read_text(encoding="utf-8")
               for p in zeek_scripts), "LogAscii::use_json = T introuvable dans zeek/"
