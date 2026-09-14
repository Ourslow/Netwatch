#!/bin/bash
# Données de démonstration NetBox — un site, trois préfixes, trois adresses nommées —
# pour que « Contexte NetBox » (/ip/<ip>) et « Importer depuis NetBox » (/hostgroups)
# aient quelque chose à montrer. Idempotent : les objets déjà présents sont ignorés.
# Lit NETBOX_TOKEN_KEY / NETBOX_TOKEN dans .env (jamais affichés).
set -euo pipefail
cd "$(dirname "$0")/../.."
[ -f .env ] || { echo "ERREUR : .env introuvable (cp .env.example .env)"; exit 1; }
set -a; . ./.env; set +a
NB="${NETWATCH_NETBOX_URL:-http://localhost:8000}"
: "${NETBOX_TOKEN_KEY:?NETBOX_TOKEN_KEY manquant dans .env}"; : "${NETBOX_TOKEN:?NETBOX_TOKEN manquant dans .env}"
AUTH="Authorization: Bearer nbt_${NETBOX_TOKEN_KEY}.${NETBOX_TOKEN}"

api() { curl -sf -m 20 -H "$AUTH" -H "Content-Type: application/json" -H "Accept: application/json" "$@"; }
# ensure <chemin API> <filtre existence> <json création> → affiche l'id (créé ou existant)
ensure() {
  local path="$1" filter="$2" json="$3" id
  id=$(api "$NB/api/$path?$filter&limit=1" | python3 -c "import sys,json;r=json.load(sys.stdin)['results'];print(r[0]['id'] if r else '')")
  if [ -n "$id" ]; then echo "  = $path ($filter) existe, id=$id" >&2
  else id=$(api -X POST "$NB/api/$path" -d "$json" | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])"); echo "  + $path créé, id=$id" >&2; fi
  echo "$id"
}

echo "NetBox $(api "$NB/api/status/" | python3 -c "import sys,json;print(json.load(sys.stdin)['netbox-version'])") — $NB"
SITE=$(ensure dcim/sites/ "slug=dc-lyon" '{"name":"Datacenter Lyon","slug":"dc-lyon","status":"active"}')
RP=$(ensure ipam/roles/ "slug=production"   '{"name":"Production","slug":"production"}')
RU=$(ensure ipam/roles/ "slug=utilisateurs" '{"name":"Utilisateurs","slug":"utilisateurs"}')
V10=$(ensure ipam/vlans/ "vid=10" '{"vid":10,"name":"SERVEURS","status":"active"}')
V20=$(ensure ipam/vlans/ "vid=20" '{"vid":20,"name":"POSTES","status":"active"}')
ensure ipam/prefixes/ "prefix=192.168.1.0/24" "{\"prefix\":\"192.168.1.0/24\",\"status\":\"active\",\"description\":\"LAN Datacenter Lyon\",\"scope_type\":\"dcim.site\",\"scope_id\":$SITE,\"role\":$RP,\"vlan\":$V10}" >/dev/null
ensure ipam/prefixes/ "prefix=10.0.3.0/24"    "{\"prefix\":\"10.0.3.0/24\",\"status\":\"active\",\"description\":\"Serveurs Prod\",\"scope_type\":\"dcim.site\",\"scope_id\":$SITE,\"role\":$RP,\"vlan\":$V10}" >/dev/null
ensure ipam/prefixes/ "prefix=10.0.20.0/22"   "{\"prefix\":\"10.0.20.0/22\",\"status\":\"active\",\"description\":\"Postes utilisateurs\",\"scope_type\":\"dcim.site\",\"scope_id\":$SITE,\"role\":$RU,\"vlan\":$V20}" >/dev/null
ensure ipam/ip-addresses/ "address=192.168.1.1/24" '{"address":"192.168.1.1/24","status":"active","dns_name":"gw-lyon.netwatch.local","description":"Passerelle / DNS interne","role":"anycast"}' >/dev/null
ensure ipam/ip-addresses/ "address=10.0.3.14/24"   '{"address":"10.0.3.14/24","status":"active","dns_name":"srv-erp-01.netwatch.local","description":"ERP (SAP) — prod"}' >/dev/null
ensure ipam/ip-addresses/ "address=10.0.3.20/24"   '{"address":"10.0.3.20/24","status":"active","dns_name":"srv-ad-01.netwatch.local","description":"Contrôleur de domaine"}' >/dev/null
echo "Terminé — ouvrir http://localhost:5050/ip/10.0.3.14 puis « Importer depuis NetBox » sur /hostgroups."
