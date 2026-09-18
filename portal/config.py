import os
from pathlib import Path
from dotenv import load_dotenv

# Deux fichiers .env, sans doublon de configuration :
#   portal/.env  — propre au portail (FLASK_SECRET_KEY, PORTAL_*, PROXMOX_*)
#   ../.env      — celui du stack docker-compose (IFACE, NETBOX_*, ARKIME_*, NETWATCH_*_URL…)
# load_dotenv n'écrase jamais une variable déjà définie : portal/.env a priorité,
# puis le .env racine complète (c'est là que vivent les secrets partagés avec le stack).
load_dotenv()
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

PROXMOX_HOST     = os.getenv("PROXMOX_HOST", "")
ESXI_HOST        = os.getenv("ESXI_HOST",   "")
ESXI_USER        = os.getenv("ESXI_USER",   "root")
ESXI_PASSWORD    = os.getenv("ESXI_PASSWORD", "")
ESXI_VERIFY_SSL  = os.getenv("ESXI_VERIFY_SSL", "false").lower() == "true"

# Garder pour rétro-compatibilité (la vraie var est PROXMOX_HOST)

PROXMOX_USER     = os.getenv("PROXMOX_USER", "root@pam")
PROXMOX_PASSWORD = os.getenv("PROXMOX_PASSWORD", "")
# Auth par API token (recommandé en prod, évite de stocker le mot de passe root) :
# généré via `pveum user token add <user> <token_name>`. Si renseigné, prend le
# pas sur PROXMOX_PASSWORD dans proxmox/client.py.
PROXMOX_TOKEN_NAME  = os.getenv("PROXMOX_TOKEN_NAME", "")
PROXMOX_TOKEN_VALUE = os.getenv("PROXMOX_TOKEN_VALUE", "")
PROXMOX_NODE     = os.getenv("PROXMOX_NODE", "pve-netwatch")
PROXMOX_VERIFY_SSL = os.getenv("PROXMOX_VERIFY_SSL", "false").lower() == "true"

_secret = os.getenv("FLASK_SECRET_KEY", "")
if not _secret:
    raise RuntimeError(
        "FLASK_SECRET_KEY doit être défini dans .env — "
        "générer avec : python3 -c \"import secrets; print(secrets.token_hex(32))\""
    )
FLASK_SECRET_KEY = _secret
FLASK_DEBUG      = os.getenv("FLASK_DEBUG", "false").lower() == "true"
PORT             = int(os.getenv("PORT", 5050))

# Point d'entrée HTTPS unique (Caddy, profil « proxy ») : URL publique du portail
# telle que tapée dans le navigateur. Vide = accès direct par port (labo).
# Renseignée = le portail est derrière Caddy : en-têtes X-Forwarded-* de
# confiance, cookie Secure si https, liens vers les outils réécrits en
# /grafana/, /kibana/… (cf. app.browser_url), /auth/check pour Caddy.
PUBLIC_URL = os.getenv("NETWATCH_PUBLIC_URL", "").strip().rstrip("/")
PROXY_MODE = bool(PUBLIC_URL)

# Cookie de session en HTTPS uniquement — automatique derrière Caddy en https,
# sinon SESSION_COOKIE_SECURE=true pour tout autre reverse-proxy TLS.
SESSION_COOKIE_SECURE = (os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
                         or PUBLIC_URL.startswith("https://"))

# Credentials du portail (authentification)
PORTAL_USERNAME = os.getenv("PORTAL_USERNAME", "admin")
PORTAL_PASSWORD = os.getenv("PORTAL_PASSWORD", "")   # vide = portail désactivé si pas défini

# URLs des services NetWatch (pour la page /status)
ES_VERIFY_SSL           = os.getenv("ES_VERIFY_SSL", "false").lower() == "true"
NETWATCH_ES_URL         = os.getenv("NETWATCH_ES_URL",         "http://localhost:9200")
NETWATCH_GRAFANA_URL    = os.getenv("NETWATCH_GRAFANA_URL",    "http://localhost:3000")
NETWATCH_PROMETHEUS_URL = os.getenv("NETWATCH_PROMETHEUS_URL", "http://localhost:9090")
NETWATCH_AUTOBLOCK_URL  = os.getenv("NETWATCH_AUTOBLOCK_URL",  "http://localhost:5001")

# Services d'observabilité complémentaires — chaîne vide = désactivé (pas de
# check /status, pas de lien dans le menu). Défauts = stack docker-compose locale.
NETWATCH_BLACKBOX_URL = os.getenv("NETWATCH_BLACKBOX_URL", "http://localhost:9115")
NETWATCH_KIBANA_URL   = os.getenv("NETWATCH_KIBANA_URL",   "http://localhost:5601")
NETWATCH_NTOPNG_URL   = os.getenv("NETWATCH_NTOPNG_URL",   "http://localhost:3001")
NETWATCH_ARKIME_URL   = os.getenv("NETWATCH_ARKIME_URL",   "http://localhost:8005")
NETWATCH_NETBOX_URL   = os.getenv("NETWATCH_NETBOX_URL",   "http://localhost:8000")
# API NetBox (enrichissement IP, import préfixes). Token v2 (NetBox ≥ 4.6) = KEY (12) + TOKEN (40)
# → « Bearer nbt_KEY.TOKEN » ; sans KEY, NETBOX_TOKEN est traité comme token v1 (« Token … »)
# ou comme token v2 complet s'il commence par nbt_.
NETBOX_TOKEN_KEY      = os.getenv("NETBOX_TOKEN_KEY", "")
NETBOX_TOKEN          = os.getenv("NETBOX_TOKEN", "")

# Assistant IA local (Ollama) — explication des alertes, résumé exécutif
# 100% on-prem, aucune donnée envoyée hors du SI.
# Édition : OLLAMA_URL vide dans .env = édition Core (fonctions ✨ masquées,
# Ollama absent de /status) ; absent du .env = défaut localhost (édition IA).
OLLAMA_URL   = os.getenv("OLLAMA_URL",   "http://localhost:11434")
AI_ENABLED   = bool(OLLAMA_URL)
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral")
# Timeout (s) des appels de génération Ollama. L'inférence CPU (sans GPU) est lente :
# 120 s laisse le temps au modèle de se charger + générer. Réduire si GPU dispo.
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))

# SLA targets — compliance thresholds (T_027)
SLA_HTTP_TARGET_MS  = int(os.getenv("SLA_HTTP_TARGET_MS", "200"))
SLA_DNS_TARGET_MS   = int(os.getenv("SLA_DNS_TARGET_MS", "50"))
SLA_RTT_TARGET_MS   = int(os.getenv("SLA_RTT_TARGET_MS", "50"))
SLA_TARGET_PCT      = float(os.getenv("SLA_TARGET_PCT", "99.0"))

# Topologie réseau (/api/topology) — pas de SPAN/SNMP réel en place pour l'instant,
# donc on force topology-discover.py en mode --demo (données synthétiques).
# Mettre à false quand du SNMP réel sera disponible sur les sondes.
TOPOLOGY_DEMO = os.getenv("TOPOLOGY_DEMO", "false").lower() == "true"

# Alertes sur seuil (/thresholds) — webhook optionnel notifié à chaque nouveau
# franchissement (n8n, Slack incoming webhook...). Vide = pas de notification
# externe, les événements restent consultables dans le portail.
THRESHOLD_WEBHOOK_URL   = os.getenv("THRESHOLD_WEBHOOK_URL", "")
THRESHOLD_CHECK_SECONDS = int(os.getenv("THRESHOLD_CHECK_SECONDS", "120"))
