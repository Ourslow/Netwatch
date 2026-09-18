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


def test_zeek_logs_are_json():
    zeek_scripts = list((ROOT / "zeek").rglob("*.zeek"))
    assert any("LogAscii::use_json" in p.read_text(encoding="utf-8") and "= T" in p.read_text(encoding="utf-8")
               for p in zeek_scripts), "LogAscii::use_json = T introuvable dans zeek/"
