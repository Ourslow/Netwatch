"""
Le dépôt est celui d'un produit : aucune mention d'employeur, d'école, de client
ni de numéro de ticket de la phase labo ne doit y réapparaître (site, portail,
docs, code). Les documents internes vivent dans private/ (ignoré par git).
"""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN = re.compile(
    r"Axians|Vinci Energies|SideQuest|École 2600|ecole2600|BP2i|\bT_0\d{2}\b|agents-deck",
    re.IGNORECASE,
)
TEXT_SUFFIXES = {".py", ".html", ".js", ".css", ".sh", ".md", ".yml", ".yaml", ".json",
                 ".zeek", ".txt", ".ini", ".toml", ".lua", ".rules", ".cfg", ""}


def _tracked_files():
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
        return [ROOT / p for p in out.decode("utf-8", "replace").split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        skip = {".git", "private", "venv", ".venv", "node_modules", "__pycache__", "scratchpad", ".claude"}
        return [p for p in ROOT.rglob("*") if p.is_file() and not skip & set(p.parts)]


def test_no_employer_school_or_ticket_traces():
    offenders = []
    for path in _tracked_files():
        if path.suffix.lower() not in TEXT_SUFFIXES or not path.is_file():
            continue
        if "private" in path.parts or "vendor" in path.parts or path.name == "test_neutrality.py":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if FORBIDDEN.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{i}: {line.strip()[:100]}")
    assert not offenders, "Traces non neutres dans le dépôt produit :\n" + "\n".join(offenders[:40])


BRAND_FILES = [ROOT / "README.md", ROOT / "site" / "index.html", ROOT / "portal" / "app.py",
               ROOT / "portal" / "static" / "js" / "netwatch.js"] + sorted((ROOT / "portal" / "templates").glob("*.html"))
BAD_BRAND = re.compile(r"NetWatch (Portal|v[0-9]\b)|Net Watch|Netwatch\b(?![-./])")


def test_brand_naming_is_consistent():
    """Le produit s'appelle « NetWatch » (brand/README.md) : pas de « Portal », pas de « v2 » accolé au nom."""
    offenders = []
    for path in BRAND_FILES:
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "Ourslow/Netwatch" in line or "ourslow.github.io/Netwatch" in line:
                continue  # URL du dépôt / du site : casse imposée par GitHub
            if BAD_BRAND.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{i}: {line.strip()[:100]}")
    assert not offenders, "Nommage incohérent :\n" + "\n".join(offenders[:40])
