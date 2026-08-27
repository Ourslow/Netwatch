"""
Hostgroups — import et filtrage par groupes d'hôtes.

Format d'entrée : export CSV type NetScout nGeniusONE (colonnes Name,
Description, Enabled, Bandwidth In, Bandwidth Out, Hosts, Member hostgroups,
Tags). La colonne "Hosts" contient des IP uniques, des plages "start-end" ou
des CIDR ; "Member hostgroups" permet d'imbriquer des groupes (résolu
récursivement à la lecture).
"""
import csv
import ipaddress
import json
import os

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
STORE_PATH = os.path.join(DATA_DIR, "hostgroups.json")

_EMPTY_MARKERS = ("", "-", "—", None)


def _parse_host_token(token):
    """IP unique, plage 'start-end' ou CIDR -> (start_int, end_int, version) | None."""
    token = token.strip()
    if not token:
        return None
    try:
        if "/" in token:
            net = ipaddress.ip_network(token, strict=False)
            start, end = net.network_address, net.broadcast_address
        elif "-" in token:
            # Aucune adresse IPv4/IPv6 valide ne contient de '-' : split simple.
            start_s, end_s = token.split("-", 1)
            start = ipaddress.ip_address(start_s.strip())
            end = ipaddress.ip_address(end_s.strip())
        else:
            start = end = ipaddress.ip_address(token)
        if start.version != end.version:
            return None
        return [int(start), int(end), start.version]
    except ValueError:
        return None


def parse_csv(raw):
    """Parse un export CSV Hostgroups. raw: bytes|str. Retourne dict{name: group}."""
    text = raw.decode("utf-8-sig", errors="replace") if isinstance(raw, bytes) else raw
    # Les lignes de métadonnées d'export (#Version, #Data Type, ...) précèdent le header réel.
    data_lines = [l for l in text.splitlines() if not l.lstrip().startswith("#")]
    reader = csv.DictReader(data_lines)
    groups = {}
    for row in reader:
        name = (row.get("Name") or "").strip()
        if not name:
            continue
        ranges = []
        for tok in (row.get("Hosts") or "").split(","):
            parsed = _parse_host_token(tok)
            if parsed:
                ranges.append(parsed)
        members = [m.strip() for m in (row.get("Member hostgroups") or "").split(",") if m.strip()]
        groups[name] = {
            "name": name,
            "description": (row.get("Description") or "").strip(),
            "enabled": (row.get("Enabled") or "TRUE").strip().upper() != "FALSE",
            "ranges": ranges,
            "member_groups": members,
            "tags": (row.get("Tags") or "").strip(),
        }
    return groups


def load():
    if not os.path.exists(STORE_PATH):
        return {}
    try:
        with open(STORE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save(groups):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp_path = STORE_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(groups, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, STORE_PATH)


def resolve_ranges(name, groups, _seen=None):
    """Plages IP d'un groupe, sous-groupes membres inclus récursivement (anti-cycle)."""
    if _seen is None:
        _seen = set()
    if name in _seen or name not in groups:
        return []
    _seen.add(name)
    g = groups[name]
    ranges = list(g.get("ranges", []))
    for member in g.get("member_groups", []):
        ranges.extend(resolve_ranges(member, groups, _seen))
    return ranges


def ip_in_ranges(ip_str, ranges):
    if not ip_str or ip_str in _EMPTY_MARKERS:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    ip_int, version = int(ip), ip.version
    return any(rversion == version and start <= ip_int <= end for start, end, rversion in ranges)


def make_matcher(group_name, groups=None):
    """ip:str -> bool pour un groupe donné, ou None si le groupe n'existe pas."""
    if not group_name:
        return None
    if groups is None:
        groups = load()
    if group_name not in groups:
        return None
    ranges = resolve_ranges(group_name, groups)
    return lambda ip: ip_in_ranges(ip, ranges)


def list_groups():
    groups = load()
    out = [
        {
            "name": name,
            "description": g.get("description", ""),
            "enabled": g.get("enabled", True),
            "host_count": len(g.get("ranges", [])),
            "member_groups": g.get("member_groups", []),
            "tags": g.get("tags", ""),
        }
        for name, g in groups.items()
    ]
    out.sort(key=lambda g: g["name"].lower())
    return out


def filter_items_by_group(items, group_name, ip_keys):
    """Ne garde que les dicts de `items` dont au moins un champ de ip_keys est dans le groupe."""
    matcher = make_matcher(group_name)
    if matcher is None:
        return items
    return [it for it in items if any(matcher(it.get(k)) for k in ip_keys)]
