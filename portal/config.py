import os
from dotenv import load_dotenv

load_dotenv()

PROXMOX_HOST     = os.getenv("PROXMOX_HOST", "")
PROXMOX_USER     = os.getenv("PROXMOX_USER", "root@pam")
PROXMOX_PASSWORD = os.getenv("PROXMOX_PASSWORD", "")
PROXMOX_NODE     = os.getenv("PROXMOX_NODE", "pve")
PROXMOX_VERIFY_SSL = os.getenv("PROXMOX_VERIFY_SSL", "false").lower() == "true"

FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "")
FLASK_DEBUG      = os.getenv("FLASK_DEBUG", "false").lower() == "true"
PORT             = int(os.getenv("PORT", 5050))

# Credentials du portail (authentification)
PORTAL_USERNAME = os.getenv("PORTAL_USERNAME", "admin")
PORTAL_PASSWORD = os.getenv("PORTAL_PASSWORD", "")   # vide = portail désactivé si pas défini

# URLs des services NetWatch (pour la page /status)
NETWATCH_ES_URL         = os.getenv("NETWATCH_ES_URL",         "http://localhost:9200")
NETWATCH_GRAFANA_URL    = os.getenv("NETWATCH_GRAFANA_URL",    "http://localhost:3000")
NETWATCH_PROMETHEUS_URL = os.getenv("NETWATCH_PROMETHEUS_URL", "http://localhost:9090")
NETWATCH_AUTOBLOCK_URL  = os.getenv("NETWATCH_AUTOBLOCK_URL",  "http://localhost:5001")
