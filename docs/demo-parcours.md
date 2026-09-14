# Parcours de démonstration — NetWatch v2 (≈ 10 minutes)

Un fil conducteur pour présenter NetWatch à un client ou un jury : **une question métier par étape**, la page qui y répond, et la phrase à dire. Tout se passe depuis le portail (`http://localhost:5050`, `admin` / `netwatch`) ; les autres outils s'ouvrent depuis ses boutons contextuels.

> Préparation (une fois) : `make start` → `make observability` → `make arkime-init` → `make kibana-setup` → `make demo-netbox`, puis laisser tourner 15 minutes pour avoir du trafic. Vérifier avec `make health` que `/status` est vert. Pour du volume : `make sim-fast` ou `./replay-pcap.sh pcap/<fichier>.pcap`.

| # | Question du client | Page | Ce qu'on montre | Ce qu'on dit |
|---|---|---|---|---|
| 1 | *« Le réseau va bien, là, maintenant ? »* | **Home** `/` | Bandeau de triage (ok / attention / critique) avec ses points d'attention cliquables ; KPIs avec sparklines et tendance vs période précédente ; strip des services en bas. Changer la plage globale (1 h → 30 j) : toute la page suit. | « Une seule ligne répond à la question. Chaque chip est un lien vers la preuve. » |
| 2 | *« Qui consomme, et est-ce que ça rame ? »* | **Flux & performance** `/flows` | Top talkers / ports, ART p50-p95-p99 par service, santé TCP (RTT, retransmissions, zero-window). Clic sur une IP → pivot. Bouton **ntopng** : classification nDPI temps réel (300+ protocoles). | « Passif : aucun agent, aucune sonde à poser sur les serveurs. » |
| 3 | *« C'est quoi cette adresse ? »* | **Pivot IP** `/ip/10.0.3.14` | Carte **Contexte NetBox** : `srv-erp-01 · ERP (SAP) · Datacenter Lyon · VLAN SERVEURS · Production`. Mêmes widgets de performance que la home, mais pour ce seul hôte. Boutons **Kibana** (logs Zeek de l'adresse) et **PCAP** (sessions Arkime). | « L'inventaire est la source de vérité : une adresse devient un serveur, un site, un propriétaire. » |
| 4 | *« Et si le lien tombe à 3 h du matin ? »* | **SLA** `/sla` | En bas : **SLA actifs — sondes Blackbox** (disponibilité, latence, DOWN en rouge). Ajouter une cible dans `prometheus/blackbox-targets.yml` : elle apparaît en 30 s sans redémarrage. Une sonde KO remonte en *critique* sur la home. | « Le passif voit le trafic qui existe ; l'actif vérifie que le service répond, même quand personne ne l'utilise. » |
| 5 | *« Il s'est passé quoi exactement, paquet par paquet ? »* | Pivot IP → **PCAP** (Arkime `:8005`) | Sessions capturées en continu sur `IFACE`, filtrées `ip == <adresse>` ; ouvrir une session, exporter le PCAP. | « Full packet capture indexée dans l'Elasticsearch existant — pas de deuxième base. » |
| 6 | *« On est attaqués ? »* | **Alertes** `/alerts` → **Incidents** `/incidents` | Flux temps réel (SSE) des 3 moteurs, filtres sévérité/moteur ; incidents = fenêtres de 5 min corrélées avec la chaîne MITRE ATT&CK. Bouton **✨ IA** : explication de l'alerte par Mistral, 100 % local. | « Trois moteurs sur le même trafic, une IA qui explique — sans qu'une donnée ne sorte du SI. » |
| 7 | *« Montrez-moi le log brut »* | **Analyse Zeek** `/zeek` → **Kibana** (`:5601`) | Discover s'ouvre directement sur la data view Zeek (conn, dns, http, ssl) sur les 15 dernières minutes. | « Grafana pour regarder, Kibana pour fouiller. » |
| 8 | *« Tout ça, c'est fiable ? »* | **Statut** `/status` | 10 services + sondes 7/7 en vert, latences ; services optionnels marqués comme tels (ils ne mettent jamais la stack en *down*). | « L'outil se surveille lui-même avec les mêmes sondes que celles qu'il propose au client. » |
| 9 | *« Vous me laissez quoi à la fin ? »* | **Rapport** `/report` → PDF | Rapport exécutif imprimable (posture, KPIs, incidents, SLA) généré à la demande. **Hostgroups** `/hostgroups` → « Importer depuis NetBox » : un groupe par préfixe IPAM, filtre global immédiat. | « Un rapport que la direction lit, un découpage réseau qui vient de l'inventaire, pas d'un tableur. » |

## Variantes selon l'audience

- **Direction / RSSI (5 min)** : étapes 1 → 6 → 9 (`/exec` en bonus : score IOC composite, escalade n8n).
- **Équipe réseau (15 min)** : 1 → 2 → 3 → 4 → 5, puis `/pcap-analysis` (narration IA d'une conversation TCP) et `/topology`.
- **Jury / technique** : ajouter `/status`, `docker compose ps`, un `git log --oneline | head`, et le tableau *open-source vs commercial* du README.

## Ce qu'il ne faut pas oublier de dire

1. **0 € de licence, 100 % on-prem** — l'IA comprise (Ollama). Rien ne sort du réseau.
2. **Passif + actif** — Zeek/Snort/Suricata voient le trafic, Blackbox vérifie la disponibilité, Arkime garde la preuve.
3. **L'inventaire au centre** — NetBox donne du sens aux adresses ; les hostgroups en découlent.
4. **Une seule console** — les cinq outils complémentaires s'ouvrent depuis le portail, au bon endroit, avec le bon filtre.

## Pièges connus en démo

- Home en *attention* après un redémarrage d'Elasticsearch : c'est la disponibilité de la sonde ES sur 24 h (< 99 %), ça se résorbe seul.
- Machine ≤ 8 Go : mettre `ES_HEAP=-Xms1g -Xmx1g` dans `.env` avant `make start`, sinon Arkime peut être tué (OOM).
- Arkime est **sans login en labo** (`ARKIME_AUTH_MODE=anonymous`, viewer lié à `127.0.0.1`) — en prod, `form` derrière le reverse-proxy HTTPS.
- Identifiants de démo : portail `admin`/`netwatch`, NetBox `admin`/`<NETBOX_SUPERUSER_PASSWORD>`, Grafana `admin`/`<GRAFANA_ADMIN_PASSWORD>`. Kibana, ntopng, Blackbox : pas d'auth (localhost).
