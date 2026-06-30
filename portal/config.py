import os
from dotenv import load_dotenv

load_dotenv()

PROXMOX_HOST     = os.getenv("PROXMOX_HOST", "")
ESXI_HOST        = os.getenv("ESXI_HOST",   "")
ESXI_USER        = os.getenv("ESXI_USER",   "root")
ESXI_PASSWORD    = os.getenv("ESXI_PASSWORD", "")
ESXI_VERIFY_SSL  = os.getenv("ESXI_VERIFY_SSL", "false").lower() == "true"

# Garder pour rétro-compatibilité (la vraie var est PROXMOX_HOST)

PROXMOX_USER     = os.getenv("PROXMOX_USER", "root@pam")
PROXMOX_PASSWORD = os.getenv("PROXMOX_PASSWORD", "")
PROXMOX_NODE     = os.getenv("PROXMOX_NODE", "pve")
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

# Cookie de session en HTTPS uniquement (mettre true derrière un reverse-proxy TLS)
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"

# Credentials du portail (authentification)
PORTAL_USERNAME = os.getenv("PORTAL_USERNAME", "admin")
PORTAL_PASSWORD = os.getenv("PORTAL_PASSWORD", "")   # vide = portail désactivé si pas défini

# URLs des services NetWatch (pour la page /status)
ES_VERIFY_SSL           = os.getenv("ES_VERIFY_SSL", "false").lower() == "true"
NETWATCH_ES_URL         = os.getenv("NETWATCH_ES_URL",         "http://localhost:9200")
NETWATCH_GRAFANA_URL    = os.getenv("NETWATCH_GRAFANA_URL",    "http://localhost:3000")
NETWATCH_PROMETHEUS_URL = os.getenv("NETWATCH_PROMETHEUS_URL", "http://localhost:9090")
NETWATCH_AUTOBLOCK_URL  = os.getenv("NETWATCH_AUTOBLOCK_URL",  "http://localhost:5001")

# Assistant IA local (Ollama) — explication des alertes, résumé exécutif
# 100% on-prem, aucune donnée envoyée hors du SI
OLLAMA_URL   = os.getenv("OLLAMA_URL",   "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral")
# Timeout (s) des appels de génération Ollama. L'inférence CPU (sans GPU) est lente :
# 120 s laisse le temps au modèle de se charger + générer. Réduire si GPU dispo.
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))
