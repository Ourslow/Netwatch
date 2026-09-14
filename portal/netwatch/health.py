"""
Vérification de l'état des services NetWatch.
Chaque checker retourne un dict :
  {
    "name":    str,
    "url":     str,
    "status":  "up" | "degraded" | "down",
    "latency": float | None,   # ms
    "detail":  str | None,
  }
"""

import time
from concurrent.futures import ThreadPoolExecutor

import requests

TIMEOUT = 3  # secondes


def _check(name, url, parse_fn=None, headers=None):
    """Appel HTTP générique avec mesure de latence."""
    t0 = time.monotonic()
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False, headers=headers or {})
        latency = round((time.monotonic() - t0) * 1000)
        if r.status_code >= 500:
            return {"name": name, "url": url, "status": "down",
                    "latency": latency, "detail": f"HTTP {r.status_code}"}
        detail = None
        status = "up"
        if parse_fn:
            status, detail = parse_fn(r)
        return {"name": name, "url": url, "status": status,
                "latency": latency, "detail": detail}
    except requests.exceptions.ConnectionError:
        return {"name": name, "url": url, "status": "down",
                "latency": None, "detail": "Connexion refusée"}
    except requests.exceptions.Timeout:
        return {"name": name, "url": url, "status": "down",
                "latency": None, "detail": f"Timeout > {TIMEOUT}s"}
    except Exception as e:
        return {"name": name, "url": url, "status": "down",
                "latency": None, "detail": str(e)[:80]}


def _parse_es(r):
    """Cluster health Elasticsearch : green=up, yellow=degraded, red=down."""
    try:
        data = r.json()
        color = data.get("status", "red")
        indices = data.get("number_of_data_nodes", "?")
        shards  = data.get("active_shards", "?")
        detail  = f"status={color} · data_nodes={indices} · shards={shards}"
        if color == "green":
            return "up", detail
        if color == "yellow":
            return "degraded", detail
        return "down", detail
    except Exception:
        return "degraded", "Réponse non parseable"


def _parse_grafana(r):
    """Grafana /api/health : {"database": "ok"} → up."""
    try:
        data = r.json()
        db = data.get("database", "?")
        commit = data.get("commit", "")[:7]
        detail = f"db={db}" + (f" · commit={commit}" if commit else "")
        return ("up" if db == "ok" else "degraded"), detail
    except Exception:
        return "up", None   # Grafana renvoie parfois du HTML en mode no-auth


def _parse_prometheus(r):
    """Prometheus /-/healthy : "Prometheus Server is Healthy." → up."""
    body = r.text.strip()
    if "Healthy" in body or r.status_code == 200:
        return "up", "Prometheus Healthy"
    return "degraded", body[:60]


def _parse_autoblock(r):
    """AutoBlock Flask : /health ou / → JSON {"status": "ok", "dry_run": bool}."""
    try:
        data = r.json()
        dry = data.get("dry_run", True)
        mode = "DRY_RUN" if dry else "LIVE ⚠️"
        return "up", f"mode={mode}"
    except Exception:
        return "up", None


def _parse_ollama(r):
    """Ollama /api/tags : liste des modèles chargés."""
    try:
        models = [m.get("name", "?") for m in r.json().get("models", [])]
        detail = f"modèles: {', '.join(models)}" if models else "aucun modèle installé"
        return ("up" if models else "degraded"), detail
    except Exception:
        return "degraded", "Réponse non parseable"


# ── Services complémentaires (Blackbox, Kibana, ntopng, Arkime, NetBox) ──

def _parse_alive(r):
    """Toute réponse < 500 = vivant ; 401/403 = vivant derrière une auth."""
    if r.status_code in (401, 403):
        return "up", "auth requise"
    if "login" in (r.url or "").lower():   # redirigé vers un formulaire de connexion (Arkime authMode=form, NetBox)
        return "up", "page de connexion"
    return "up", f"HTTP {r.status_code}"


def _parse_kibana(r):
    """Kibana /api/status : status.overall.level = available | degraded | …"""
    try:
        level = r.json().get("status", {}).get("overall", {}).get("level", "?")
        return ("up" if level == "available" else "degraded"), f"status={level}"
    except Exception:
        return "up", None   # Kibana renvoie parfois une page HTML pendant le démarrage


def _parse_netbox(r):
    """NetBox /api/status/ : version + workers RQ."""
    if r.status_code in (401, 403):
        return "degraded", "token API refusé (NETBOX_TOKEN_KEY / NETBOX_TOKEN)"
    try:
        d = r.json()
        workers = d.get("rq-workers-running", "?")
        return "up", f"v{d.get('netbox-version', '?')} · workers={workers}"
    except Exception:
        return "up", None


def _parse_blackbox(r):
    return "up", "exporter Healthy"


def _parse_ntopng(r):
    return "up", "nDPI actif"


def extra_checks(blackbox_url=None, kibana_url=None, ntopng_url=None, arkime_url=None,
                 netbox_url=None, netbox_auth=None):
    """Checks des services complémentaires, uniquement ceux dont l'URL est
    renseignée. Marqués optional : leur absence dégrade l'état global mais ne
    le rend pas « down » et le triage de la home les remonte en avertissement.
    netbox_auth = header Authorization (nw_netbox.auth_header()) ; sans token,
    on se contente de la page de login. Chaque entrée : (name, url, parse_fn[, headers])."""
    out = []
    if blackbox_url:
        out.append(("Blackbox (sondes)", f"{blackbox_url}/-/healthy", _parse_blackbox))
    if kibana_url:
        out.append(("Kibana", f"{kibana_url}/api/status", _parse_kibana))
    if ntopng_url:
        out.append(("ntopng", f"{ntopng_url}/", _parse_ntopng))
    if arkime_url:
        out.append(("Arkime", f"{arkime_url}/", _parse_alive))
    if netbox_url:
        if netbox_auth:    # avec token : version + workers ; sans : page de login = vivant
            out.append(("NetBox", f"{netbox_url}/api/status/", _parse_netbox,
                        {**netbox_auth, "Accept": "application/json"}))
        else:
            out.append(("NetBox", f"{netbox_url}/login/", _parse_alive))
    return out


def check_all(es_url, grafana_url, prometheus_url, autoblock_url, ollama_url=None, extra=None):
    checks = [
        ("Elasticsearch", f"{es_url}/_cluster/health",   _parse_es),
        ("Grafana",       f"{grafana_url}/api/health",   _parse_grafana),
        ("Prometheus",    f"{prometheus_url}/-/healthy", _parse_prometheus),
        ("AutoBlock",     f"{autoblock_url}/health",     _parse_autoblock),
    ]
    if ollama_url:
        checks.append(("Assistant IA (Ollama)", f"{ollama_url}/api/tags", _parse_ollama))
    core_count = len(checks)
    checks += list(extra or [])

    # Checks HTTP en parallèle — en séquentiel, N services down/timeout à
    # TIMEOUT=3s chacun peuvent cumuler jusqu'à N*3s de latence sur /status.
    with ThreadPoolExecutor(max_workers=len(checks)) as pool:
        services = list(pool.map(lambda c: _check(*c), checks))
    for i, s in enumerate(services):
        s["optional"] = i >= core_count

    # Résumé global — les services optionnels ne peuvent pas rendre la stack « down »
    core = [s["status"] for s in services[:core_count]]
    statuses = [s["status"] for s in services]
    if all(s == "up" for s in statuses):
        global_status = "up"
    elif all(s == "down" for s in core):
        global_status = "down"
    else:
        global_status = "degraded"

    return services, global_status
