"""
NetBox — source de vérité inventaire / IPAM.

Deux usages dans le portail :
  - lookup_ip(ip)      : contexte métier d'une adresse (device, site, rôle, VLAN,
                         propriétaire) pour le pivot /ip/<ip> — des adresses nues
                         deviennent « srv-erp-01 · Datacenter Lyon · Prod ».
  - list_prefixes()    : préfixes IPAM → import en hostgroups (un groupe par
                         préfixe, nommé d'après sa description / site).

Tout est best-effort : NetBox absent ou token invalide → (None|[], error).
"""

import requests

import config
from .es_client import _ttl_cache
from . import hostgroups as nw_hostgroups

_TIMEOUT = 4


def configured():
    return bool(config.NETWATCH_NETBOX_URL and config.NETBOX_TOKEN)


def auth_header():
    """
    Header Authorization selon le format du token :
      - NETBOX_TOKEN_KEY + NETBOX_TOKEN  → v2 « Bearer nbt_<key>.<token> » (NetBox ≥ 4.6)
      - NETBOX_TOKEN commençant par nbt_ → v2 déjà complet, passé tel quel
      - sinon                            → v1 legacy « Token <token> »
    """
    token = config.NETBOX_TOKEN
    if not token:
        return {}
    if config.NETBOX_TOKEN_KEY:
        return {"Authorization": f"Bearer nbt_{config.NETBOX_TOKEN_KEY}.{token}"}
    if token.startswith("nbt_"):
        return {"Authorization": f"Bearer {token}"}
    return {"Authorization": f"Token {token}"}


def _get(path, params=None):
    r = requests.get(
        config.NETWATCH_NETBOX_URL.rstrip("/") + path,
        params=params or {},
        headers={**auth_header(), "Accept": "application/json"},
        timeout=_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def _name(obj, *keys):
    """Descend dans un objet imbriqué NetBox ({'name': …} ou {'label': …})."""
    for k in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(k)
    if isinstance(obj, dict):
        return obj.get("name") or obj.get("label") or obj.get("display")
    return obj


@_ttl_cache(120)
def lookup_ip(ip):
    """
    Retourne (ctx: dict|None, error: str|None).
    ctx = {address, dns_name, description, status, role, tenant, device,
           interface, prefix, site, vlan, prefix_role, url}
    """
    if not configured():
        return None, None
    try:
        ips = _get("/api/ipam/ip-addresses/", {"address": ip, "limit": 1}).get("results", [])
        pfx = _get("/api/ipam/prefixes/", {"contains": ip, "ordering": "-mask_length", "limit": 1}).get("results", [])
    except requests.exceptions.ConnectionError:
        return None, "NetBox non joignable"
    except requests.exceptions.HTTPError as e:
        return None, f"NetBox HTTP {e.response.status_code if e.response is not None else '?'}"
    except Exception as e:
        return None, str(e)[:120]

    if not ips and not pfx:
        return None, None

    ctx = {"address": ip, "url": None}
    if ips:
        a = ips[0]
        assigned = a.get("assigned_object") or {}
        ctx.update({
            "dns_name":    a.get("dns_name") or None,
            "description": a.get("description") or None,
            "status":      _name(a, "status"),
            "role":        _name(a, "role"),
            "tenant":      _name(a, "tenant"),
            "device":      _name(assigned, "device") or _name(assigned, "virtual_machine"),
            "interface":   assigned.get("name") if assigned else None,
            "url":         (config.NETWATCH_NETBOX_URL.rstrip("/") + f"/ipam/ip-addresses/{a.get('id')}/") if a.get("id") else None,
        })
    if pfx:
        p = pfx[0]
        vlan = p.get("vlan") or {}
        ctx.update({
            "prefix":      p.get("prefix"),
            "prefix_desc": p.get("description") or None,
            "site":        _name(p, "site") or _name(p, "scope"),
            "vlan":        (f"{vlan.get('name')} (VID {vlan.get('vid')})" if vlan else None),
            "prefix_role": _name(p, "role"),
        })
        ctx.setdefault("tenant", _name(p, "tenant"))
    return ctx, None


@_ttl_cache(300)
def list_prefixes(limit=500):
    """Préfixes IPAM actifs → [{prefix, description, site, role, vlan, tenant, status}]."""
    if not configured():
        return [], "NetBox non configuré (NETWATCH_NETBOX_URL / NETBOX_TOKEN)"
    try:
        results = _get("/api/ipam/prefixes/", {"limit": limit, "status": "active"}).get("results", [])
    except requests.exceptions.ConnectionError:
        return [], "NetBox non joignable"
    except Exception as e:
        return [], str(e)[:120]
    out = []
    for p in results:
        vlan = p.get("vlan") or {}
        out.append({
            "prefix":      p.get("prefix"),
            "description": p.get("description") or "",
            "site":        _name(p, "site") or _name(p, "scope") or "",
            "role":        _name(p, "role") or "",
            "vlan":        vlan.get("name") or "",
            "tenant":      _name(p, "tenant") or "",
            "status":      _name(p, "status") or "",
        })
    return out, None


def prefixes_to_hostgroups(prefixes):
    """
    Convertit des préfixes NetBox en hostgroups (même format que l'import CSV
    NetScout : ranges [[start, end, version]], description, tags).
    Nom = description du préfixe si présente, sinon « <site> · <prefix> ».
    """
    groups = {}
    for p in prefixes:
        parsed = nw_hostgroups._parse_host_token(p["prefix"] or "")
        if not parsed:
            continue
        name = p["description"].strip() or (f"{p['site']} · {p['prefix']}" if p["site"] else p["prefix"])
        if name in groups:                       # descriptions dupliquées → suffixe préfixe
            name = f"{name} ({p['prefix']})"
        tags = ", ".join(t for t in ["netbox", p["role"], p["vlan"], p["tenant"]] if t)
        groups[name] = {
            "description": f"{p['prefix']}" + (f" · {p['site']}" if p["site"] else ""),
            "enabled": True,
            "ranges": [parsed],
            "member_groups": [],
            "tags": tags,
        }
    return groups
