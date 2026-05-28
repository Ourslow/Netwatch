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
