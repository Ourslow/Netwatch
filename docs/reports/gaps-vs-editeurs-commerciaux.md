# NetWatch — Lacunes techniques face aux éditeurs commerciaux (TCP Zero Window, dictionnaire applicatif)

Point soulevé en réunion du 2026-07-10 par Jerem : jusqu'où NetWatch va-t-il
par rapport à Netscout/Riverbed/Gigamon/Allegro, et à quel moment doit-on
basculer sur un autre outil ? Deux lacunes concrètes ont été citées comme
exemples. Recherche et proposition ci-dessous.

## 1. TCP Zero Window

**Définition.** Le "TCP Zero Window" est un indicateur de congestion côté
récepteur : quand le buffer de réception d'un hôte est saturé, celui-ci
annonce une fenêtre TCP (`window size`) à 0 dans ses paquets ACK, signalant
à l'émetteur de suspendre l'envoi. C'est un signe classique de
sous-dimensionnement applicatif (serveur trop lent à consommer les
données, CPU saturé, disque lent) ou de configuration réseau (buffers
socket trop petits, latence élevée type WAN/satellite empêchant le scaling
de fenêtre). C'est une métrique-clé du triage "réseau vs application" dans
le troubleshooting NPM.

**Comment les commerciaux l'exposent.** Netscout (nGeniusONE, via DPI sur
les sondes InfiniStreamNG/Edge) et Riverbed calculent la fréquence et la
durée des événements zero-window par connexion, les agrègent par
serveur/application, et les affichent comme un indicateur de santé TCP
dédié (souvent avec seuils d'alerte et corrélation au temps de réponse
applicatif — "retransmission delay" et "zero window duration" figurent
parmi les métriques standard du TCP/IP triage).

**Ce que Zeek fait déjà.** Bonne nouvelle : Zeek détecte nativement
l'événement. Le champ `history` de `conn.log` contient déjà la lettre
**`w`** (minuscule = responder, majuscule `W` = originator) pour "paquet
avec annonce de fenêtre zéro", avec une notation logarithmique (2e
occurrence = vu ≥10 fois, 3e = ≥100 fois, etc.). NetWatch a donc déjà la
donnée brute — elle est juste noyée dans une chaîne peu exploitable telle
quelle (`w`/`ww`/`www`) et non exposée comme métrique.

**Proposition.** Pas besoin de nouveau capteur ni de plugin Zeek complexe :
un script Zeek (`event connection_state_remove` ou parsing du champ
`history` déjà loggé) peut extraire la présence de `w`/`W`, calculer un
ratio "connexions avec zero-window / total" par host ou par application, et
le pousser en champ dédié dans Elasticsearch (ex. `tcp.zero_window_detected:
bool`, `tcp.zero_window_severity`). Pour aller plus loin, le hook
`tcp_packet` (accès à `window` en direct) permettrait de mesurer la *durée*
des épisodes zero-window, pas seulement leur occurrence — effort plus
lourd (script Zeek custom, tests de perf). Étape 1 réaliste : dashboard
Grafana/Kibana filtrant `conn.log` sur `history` contenant `w`/`W`, avec
alerting simple. **Effort estimé : faible à moyen**, quasi "gratuit" car la
donnée existe déjà.

## 2. Dictionnaire applicatif / import applicatif

**Définition.** Un "dictionnaire applicatif" chez Netscout/Riverbed est une
base de signatures qui classe le trafic par **application métier** (Office
365, SAP, Salesforce, Zoom...) plutôt que par simple port. Riverbed
revendique plus de 1300 signatures (AppFlow/AFE) combinant classification
par port, matching de signature applicative, dissection protocolaire, et
classification comportementale (pour les applications qui changent de
port). Netscout fait de même via DPI sur ses sondes matérielles.

**Comment ils enrichissent.** Trois briques principales : (1) signatures
DPI propriétaires (empreintes de payload/protocole), (2) listes d'IP/CDN
connues (plages Microsoft 365, AWS, Google, Salesforce publiées et mises à
jour), (3) fingerprinting TLS (SNI, et de plus en plus JA3/JA4) pour
classer le trafic chiffré sans déchiffrement.

**Ce que NetWatch a déjà et pourrait ajouter.** NetWatch a déjà 425 ports
mappés statiquement, et Zeek expose nativement le **SNI TLS** (`ssl.log`)
et les **noms de domaine visités** (`dns.log`, `http.log`) — exactement la
matière première du point (3) ci-dessus. Proposition concrète : construire
une table de correspondance domaine/SNI → application métier (ex.
`*.office.com`, `*.sharepointonline.com` → "Office 365" ; `*.salesforce.com`
→ "Salesforce"), stockable en JSON/YAML côté portail Flask ou en index
Elasticsearch, enrichie à l'ingestion (pipeline Logstash/Elasticsearch
ingest node ou script Zeek `ssl_extension`). Complément possible et peu
coûteux : intégrer des listes IP publiques de CDN/SaaS (Microsoft, AWS,
Google publient leurs ranges) pour couvrir le trafic sans SNI visible. Le
DPI profond "à la Riverbed" (1300+ signatures propriétaires) reste hors de
portée réaliste à court terme — mais un mapping SNI/domaine enrichi couvre
déjà 70-80% des cas d'usage réels (la majorité du SaaS moderne utilise TLS
avec SNI en clair).

## Recommandation de priorité

**Le dictionnaire applicatif basé sur le SNI/domaine est le plus rentable à
implémenter en premier** : la donnée (SNI, DNS) est déjà loggée par Zeek
sans modification, il ne reste qu'à écrire une table de correspondance et
un enrichissement au niveau Elasticsearch/Flask — travail de
configuration/mapping, pas de développement Zeek. Le zero-window vient en
second : la détection existe aussi déjà (champ `history`), mais sa
valorisation utile (dashboard, alerting, éventuellement mesure de durée)
demande un peu plus de travail de script et de visualisation pour être
présentable comme "feature" face à un client. **Les deux sont réalisables
rapidement en s'appuyant sur l'existant** — aucun des deux ne nécessite de
nouvelle sonde ou changement d'architecture.

## Sources

- [conn.log — Book of Zeek](https://docs.zeek.org/en/lts/logs/conn.html)
- [base/protocols/conn/main.zeek — Book of Zeek](https://docs.zeek.org/en/lts/scripts/base/protocols/conn/main.zeek.html)
- [nGeniusONE TCP/IP Triage — NETSCOUT](https://www.netscout.com/resources/data-sheets/ngeniusone-tcp-ip-triage)
- [Deep Packet Inspection (DPI) — NETSCOUT](https://www.netscout.com/deep-packet-inspection)
- [NPM Classification APIs v3.2 — Riverbed](https://support.riverbed.com/apis/npm.classification/3.2/service.html)
- [List of Recognized Applications — Riverbed](https://support.riverbed.com/bin/support/static/7ge237o42j2b1q1arhosl5h15i/html/s7lhbrmkp1vu6a76uj8oervuu0/sh_ex_4.5_ug_html/sh_ex_4.5_ug/app_qos_apps.18.2.html)
