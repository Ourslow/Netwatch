# NetWatch — Un labo NPM/NDR open-source au service des équipes Axians

Présentation interne — Nicolas Malok, alternant Analyste Observabilité NPM, Axians / Vinci Energies
École 2600, promotion 2024-2027 — Projet SideQuest MVP (S2 2025-2026)
Dépôt : github.com/Ourslow/netwatch — Licence AGPL v3

---

## Positionnement en une phrase

NetWatch n'est ni un concurrent ni un produit destiné à être vendu à un client final. C'est un **outil interne** développé pendant mon alternance pour comprendre, démontrer et qualifier — en complément direct des offres commerciales que nous intégrons chez nos clients : **Netscout nGeniusONE, Gigamon et Riverbed**.

Trois usages concrets pour l'équipe :
- **Formation interne** : faire monter en compétence les analystes juniors sur les fondamentaux NPM/NDR (NetFlow, SNMP, IDS, scoring qualité) avec du code source ouvert et inspectable, plutôt que sur une boîte noire propriétaire.
- **Avant-vente / qualification rapide** : construire un démonstrateur fonctionnel gratuit pour objectiver un besoin client avant d'engager une licence commerciale ou un PoC coûteux.
- **Labo de validation technique** : tester des règles de détection, des seuils d'alerte, des scénarios avant un déploiement en environnement client, sans risque et sans coût de licence.

---

## Le constat métier qui a motivé le projet

Notre activité d'intégration de solutions NPM commerciales fait face à trois contraintes récurrentes, observées directement en mission :

- **Coût de qualification élevé** : évaluer précisément un besoin client en NPM nécessite souvent un PoC avec licence temporaire, engageant un budget avant même la décision d'achat. Les solutions commerciales de référence (Netscout, Gigamon, Riverbed) représentent un budget de **10 000 à plus de 100 000 € par an** selon le périmètre.
- **Montée en compétence lente** : les analystes juniors découvrent les mécanismes NPM/NDR directement sur des outils propriétaires fermés, ce qui ralentit la compréhension des fondamentaux — calcul MOS, projection de capacité, classification applicative, logique de scoring.
- **Absence de labo de validation interne** : il n'existe aujourd'hui aucun environnement interne permettant de tester une règle de détection, un seuil d'alerte ou un scénario avant un déploiement chez un client.

Ce constat a motivé la construction d'un équivalent open-source documenté, avec un objectif assumé : explorer objectivement les limites réelles de l'open-source face au commercial, sans enjoliver.

---

## Vue d'ensemble technique du projet

NetWatch v2 fait tourner **trois moteurs d'analyse en parallèle sur le même trafic réseau** (Zeek, Snort, Suricata), complétés par un pipeline NPM dédié (NetFlow/IPFIX/sFlow + SNMP) et un pipeline sécurité comportementale, le tout unifié dans un portail web Flask.

**Chiffres clés du projet :**

| Indicateur | Valeur |
|---|---|
| Services Docker orchestrés | **14** (contre 4 en v1 de mars 2026) |
| Dashboards Grafana provisionnés | **13** |
| Pages du portail Flask | **9** (`/dashboard`, `/exec`, `/flows`, `/graph`, `/topology`, `/sla`, `/report`, `/audit`, `/agents`) |
| Ports applicatifs mappés (classification NetFlow) | **425** |
| Règles Snort custom | **17** (SID 1000001–1000017), toutes annotées MITRE ATT&CK |
| Référentiels de conformité couverts | **4** (NIS2, NIST CSF 2.0, ANSSI, ISO 27001) |
| Déploiement complet | **moins de 30 minutes** sur une VM Ubuntu 22.04 |
| Coût de licence | **0 €** (AGPL v3) vs 10 000–100 000+ €/an en commercial |

Le projet a été développé en méthodologie itérative : une v1 (mars 2026, socle 4 services) puis une v2 en **sept phases incrémentales** livrées entre juin et fin juin 2026, chacune testable indépendamment (ajout progressif de Snort/Suricata/Prometheus, puis GoFlow2, SNMP, capacity planning, VoIP, ITSM).

---

## Architecture du pipeline

```
Trafic réseau (SPAN / PCAP)
        │
    ┌───┼───┐
    ▼   ▼   ▼
  Zeek Snort Suricata        ← 3 moteurs, même trafic, 3 perspectives
    └───┬───┘
        ▼
    Filebeat 8.13             ← collecte unifiée, index par moteur
        ▼
 Elasticsearch 8.13           ← zeek-* / snort-* / suricata-* / netflow-*
        ▼
 Grafana 10.4 + Portail Flask ← visualisation, IA locale, PDF
```

En complément du pipeline sécurité, un second pipeline **NPM (performance réseau)** a été ajouté à partir de la phase 5 : **GoFlow2** collecte les flux NetFlow v9/IPFIX/sFlow v5 sur les ports UDP standards (2055, 4739, 6343) et les indexe dans `netflow-*` ; le **SNMP Exporter** interroge l'IF-MIB des équipements réseau (débit, saturation, statut opérationnel) et alimente Prometheus.

**Choix techniques justifiés :**
- Zeek plutôt que tcpdump/Wireshark en frontal : logs JSON structurés directement exploitables par Elasticsearch, sans étape de parsing fragile.
- Trois moteurs IDS en parallèle plutôt qu'un seul : permet de comparer la couverture de détection (signatures vs comportemental vs protocolaire) sur le même trafic.
- Score composite IOC plutôt qu'une source de réputation unique : réduit la dépendance à un seul fournisseur de threat intelligence.

**Infrastructure cible** : un serveur Shuttle Proxmox VE (Xeon, 16 Go RAM) avec une architecture 2 VMs — VM Sensors (Zeek/Snort/Suricata, 4 vCPU/6 Go) et VM Data (Elasticsearch/Grafana, 4 vCPU/10 Go) — reliées par un port SPAN sur switch manageable. Une carte réseau Intel i350-T2 (pilote igb, af-packet natif) est prévue pour la capture physique en v3.

---

## Les 3 moteurs de détection en détail

| Moteur | Version | Rôle | Spécificités techniques |
|---|---|---|---|
| **Zeek** | 6.2 | Analyse protocolaire complète | Logs JSON natifs (conn, dns, http, ssl, ssh, intel, notice) ; fingerprinting JA3/JA3S (TLS) et HASSH (SSH) ; Intel Framework avec watchlists IP/domaines ; 2 scripts custom (port-scan, entropie DNS Shannon) |
| **Snort** | 3.3.5 | IDS par signatures | Build from source (libdaq + tcmalloc pour la performance) ; 17 règles custom SID 1000001–1000017 avec métadonnées MITRE ATT&CK ; sortie `alert_json` vers Filebeat |
| **Suricata** | 7.0 | IDS/NSM | Règles Emerging Threats Open avec mise à jour automatique quotidienne (`suricata-update` + reload à chaud via SIGUSR2) ; sortie EVE JSON + Community ID pour corréler avec les autres moteurs ; SID custom 2000001–2000999 |

**Exemples concrets de règles custom Snort/Suricata mappées MITRE ATT&CK :**
- SID 1000001 : ICMP Ping Sweep (seuil 10 pings/60s) → T1595 (Reconnaissance)
- SID 1000002 : SSH Brute Force (5 tentatives/60s) → T1110
- SID 1000003–1000006 : DNS vers TLD suspects (.xyz, .info, .top, .biz) → T1568
- SID 1000008 : détection d'exfiltration potentielle (gros upload) → T1048
- SID 1000013–1000017 : accès non autorisé au serveur surveillé (HTTP/HTTPS/SSH/FTP, scan de ports) → T1190, T1021, T1046

**Détection comportementale — beacon-detect (RITA-lite)**, analyse toutes les 15 minutes sur `zeek-*` :
- **Beaconing C2** : coefficient de variation des intervalles de connexion < 0,25 avec au moins 8 connexions entre une même paire src/dst → score `beacon_score` 0–1
- **Connexions longues** : durée > 1h (indice de reverse shell, tunnel, exfiltration lente)
- **DNS Tunneling** : sous-domaine > 40 caractères OU plus de 100 requêtes vers le même domaine

---

## Volet NPM — ce que NetWatch couvre côté performance réseau

C'est le volet le plus directement pertinent pour l'équipe observabilité NPM : NetWatch reproduit six briques fonctionnelles typiques d'un outil comme nGeniusONE.

### Capacity planning — formule concrète

La métrique `netwatch:iface_days_to_saturation` répond à la question : *"si le trafic continue à croître au rythme des 7 derniers jours, dans combien de jours cette interface sera-t-elle saturée ?"* Calcul PromQL basé sur `ifHighSpeed` (capacité), `rate(ifHCInOctets[5m])` (débit actuel) et `deriv(...[7d:5m])` (pente de croissance sur 7 jours).

**Exemple concret documenté** : une interface Gigabit Ethernet à 1 Gbps (capacité 125 000 000 bytes/s), débit actuel 80 000 000 bytes/s (64 % d'utilisation), croissance constatée +500 000 bytes/s/jour → **90 jours avant saturation**.

Seuils de criticité sur le dashboard Grafana :

| Couleur | Délai avant saturation | Action |
|---|---|---|
| Rouge | < 7 jours | Urgent — commander un uplink ou redistribuer le trafic immédiatement |
| Orange | 7 à 30 jours | Planifier une augmentation de capacité |
| Vert | > 30 jours | Surveillance normale |

### Qualité VoIP — score MOS

Basé sur le modèle **E-model G.107** appliqué aux logs Zeek SIP/RTP, avec classification en 5 niveaux : Excellent / Good / Fair / Poor / Bad.

### Conformité SLA

Page `/sla` du portail : taux de conformité **HTTP/DNS/RTT calculés sur les percentiles Elasticsearch p95**, sur une fenêtre de 7 jours, avec distinction Business Hours vs Off-hours et gauges à 270°.

### Topologie réseau et supervision SNMP

Découverte automatique par SNMP LLDP-MIB + table ARP Zeek, rendue en graphe D3.js force-directed (routeurs, switchs, firewalls, hôtes). Le SNMP Exporter interroge l'IF-MIB (`ifHCOctets`, `ifOperStatus`) pour la supervision débit/saturation/statut des interfaces.

### Analyse de flux NetFlow / IPFIX / sFlow

Collecte via **GoFlow2** (NetFlow v9 port UDP 2055, IPFIX port 4739, sFlow v5 port 6343), indexation dans `netflow-*` avec rétention ILM de 30 jours. Page `/flows` : top talkers, top applications par catégorie, temps de réponse applicatif (ART), santé TCP.

### Classification applicative

**425 ports mappés** (base statique + résolution du nom de service Zeek) pour catégoriser automatiquement les flux (base de données, web, mail, VoIP, etc.), avec mise à jour par lot des 50 ports les plus consommateurs de bande passante dans Elasticsearch.

---

## Tableau de comparaison complet — NetWatch vs solutions commerciales Axians

| Fonctionnalité | NetWatch v2 | Équivalent commercial de référence |
|---|---|---|
| Capture et analyse réseau | Zeek 6.2 (analyse protocolaire) | Corelight, nGenius Probe |
| Détection par signatures | Snort 3.3.5 + Suricata 7 (ET Open) | Suricata OEM, Snort Enterprise |
| Fingerprinting TLS/SSH | JA3 / JA3S / HASSH (Zeek) | DPI natif (ExtraHop, Corelight) |
| Détection comportementale | RITA-lite (beacon-detect) | Darktrace AI, ExtraHop Reveal(x) |
| Réponse automatique | AutoBlock webhook → iptables | Cisco Stealthwatch + NAC, Palo Alto XSOAR |
| MITRE ATT&CK | EVE JSON Suricata + métadonnées Snort | Darktrace, Vectra AI |
| Threat Intelligence | Zeek Intel Framework (Feodo Tracker + URLhaus) | Anomali, ThreatConnect, MISP |
| **Analyse NetFlow / IPFIX / sFlow** | **GoFlow2 → ES netflow-*** | **Netscout nGeniusONE, Gigamon, Riverbed** |
| **Supervision interfaces SNMP** | **SNMP Exporter + IF-MIB** | **Netscout, SolarWinds NPM** |
| **Topologie réseau L2/L3** | **LLDP-MIB + ARP Zeek → D3.js** | **Riverbed NetIM, SolarWinds NTM** |
| **Capacity planning** | **`predict_linear` Prometheus** | **Netscout, PRTG, ManageEngine** |
| **Qualité VoIP** | **MOS E-model G.107 (Zeek)** | **Netscout InfiniStreamNG, Empirix** |
| **Compliance SLA** | **Percentiles ES p95 → gauges** | **Netscout nGeniusONE, Riverbed** |
| Corrélation multi-sources | Dashboard multi-moteurs | nGeniusONE Service Triage |
| Intégration ITSM | ServiceNow + JIRA (itsm-sync.py via n8n) | Intégrations natives éditeur |
| Rapport de conformité | PDF automatique (portail Flask) | SIEM intégré |
| **Coût** | **Gratuit (AGPL v3)** | **10 000 – 100 000+ €/an** |

---

## Le portail web unifié — 9 pages, 1 interface

| Page | Ce qu'elle apporte concrètement |
|---|---|
| `/alerts` | Alertes temps réel multi-moteurs, sparklines, auto-refresh 30s, filtres moteur/sévérité |
| `/exec` | Dashboard RSSI/direction : KPIs exécutifs, **score IOC composite**, escalade automatique via n8n |
| `/flows` | Débit réseau (GoFlow2), temps de réponse applicatif, santé TCP, top applications par catégorie |
| `/topology` | Carte réseau L2/L3 auto-générée en D3.js (routeurs, switchs, firewalls, hôtes) |
| `/sla` | Compliance SLA — HTTP/DNS/RTT sur 7 jours, Business Hours vs Off-hours |
| `/graph` | Graphe IOC interactif D3.js — IPs, règles, TTPs MITRE, enrichissement AbuseIPDB |
| `/audit` | Constats de sécurité priorisés automatiquement, score de posture /100 |
| `/compliance` | Matrices NIS2 · NIST CSF 2.0 · ANSSI · ISO 27001/27002 |
| `/report` | Rapport de conseil PDF généré automatiquement (bandeau, KPI cards, sections numérotées) |

Interface disponible en **FR / EN**, et une IA locale (**Ollama/Mistral, 100% on-prem**) explique les alertes en langage naturel sans qu'aucune donnée ne quitte l'infrastructure — un point important pour des clients sensibles à la confidentialité.

### Le scoring IOC composite — exemple chiffré

Le score de risque (0–100) combine : nombre d'alertes, somme pondérée des sévérités par moteur, bonus de +15 points par moteur distinct ayant détecté la même IP (jusqu'à +45 pour 3 moteurs), +8 points par technique MITRE unique, et une contribution optionnelle du score AbuseIPDB (`/10`).

**Exemple réel documenté** : l'IP `185.220.101.46` (nœud de sortie Tor connu) obtient un score de **80/100 (niveau critical)** : 4 alertes, 2 moteurs distincts (Snort + Suricata, +30), 2 techniques MITRE uniques T1090/T1573 (+16), sévérité cumulée (+30) — plafonné à 100.

---

## Enrichissement IOC et threat intelligence

Le graphe IOC est enrichi automatiquement via **AbuseIPDB** (score d'abus 0–100, ISP, type d'usage, nombre de signalements) avec fallback gratuit sur **ipinfo.io** (pays, ASN, hostname PTR) si aucune clé n'est configurée. Les plages RFC 1918 et loopback sont systématiquement exclues des appels API.

**Résultat mesuré sur des données live** (572 alertes, 51 nœuds de graphe) : 21 IPs privées ignorées, 8 IPs publiques enrichies, dont un nœud Tor identifié (`185.220.101.1`) et un hébergeur suspect à Hong Kong (`117.18.0.55`, AS152194 CTG Server Limited).

---

## Intégration ITSM et automatisation

- **ServiceNow** : création automatique d'incidents via l'API REST `/api/now/table/incident`, avec mapping de priorité (critical → urgency 1, high → 2, medium → 3, low → 4), déclenchée toutes les **10 minutes** par un workflow n8n.
- **JIRA** : création d'issues avec labels et description au format ADF, même cadence de déclenchement.
- **Rapport hebdomadaire automatique** : cron n8n le lundi 08h00, agrège 7 jours d'alertes Elasticsearch et pousse une Teams Adaptive Card.
- Les workflows n8n parsent le stdout du script `itsm-sync.py`, extraient les numéros de ticket créés (regex `INC\d+` ou `[A-Z]+-\d+`) et notifient Teams uniquement si au moins un ticket a été créé.
- Sécurité : credentials jamais loggés en clair (masqués `user:***` en mode verbose), rôle ServiceNow `itil` en lecture/écriture minimale sur la table incidents uniquement.

---

## Conformité réglementaire couverte

| Référentiel | Couverture | Détail |
|---|---|---|
| **NIS2** (Art. 21.2) | Couvert | Surveillance réseau, détection, réponse aux incidents |
| **NIST CSF 2.0** | Couvert | Fort sur les fonctions Detect (DE) et Respond (RS) |
| **ANSSI** | Partiel | Hygiène informatique + PA-022 supervision réseau |
| **ISO 27001:2022** | Couvert | A.8.15 (logs), A.8.16 (surveillance), A.8.23 (filtrage) |

Les matrices sont générées automatiquement dans le portail (`/compliance`) avec statut couvert / partiel / hors périmètre.

---

## Démonstration proposée en direct

Parcours de démo recommandé pour la présentation :

1. **`/status`** — vue d'ensemble des 14 services Docker en temps réel (Elasticsearch, Grafana, Prometheus, AutoBlock, IA locale)
2. **`/exec`** — vue synthétique décideur : score de risque composite, tendance, escalade
3. **`/flows`** — débit réseau temps réel, santé TCP, top applications (425 ports classifiés)
4. **`/topology`** — carte réseau auto-générée (SNMP LLDP + ARP)
5. **`/sla`** — taux de conformité 7 jours, heures ouvrées vs non ouvrées
6. **`/graph`** — graphe IOC interactif avec score composite et enrichissement AbuseIPDB

Un simulateur de trafic (`simulate-traffic.py --hours 24 --intensity medium --attack`) permet de générer en quelques minutes 24h de trafic réaliste avec scénarios d'attaque (scan de ports, DGA, exfiltration, beaconing) pour alimenter la démo sans dépendre d'un vrai flux réseau.

---

## Ce que NetWatch ne remplace pas — limites assumées

Il est essentiel de garder cette section transparente : NetWatch a une maturité fonctionnelle crédible mais une maturité opérationnelle qui reste, par nature, en retrait des solutions commerciales établies.

- **Aucun support éditeur ni SLA contractuel** — en cas de panne, c'est un projet personnel, pas un contrat de service.
- **Scalabilité multi-sites / multi-Tbps non validée en production** — testé jusqu'ici en environnement de lab, pas à l'échelle d'un opérateur ou d'un grand compte.
- **Écosystème d'intégrations tierces restreint** — deux connecteurs ITSM (ServiceNow, JIRA) contre des dizaines d'intégrations natives chez les éditeurs commerciaux.
- **Certifications produit et conformité réglementaire du logiciel lui-même non établies** — contrairement aux solutions commerciales certifiées, seule la couverture fonctionnelle des référentiels (NIS2, ISO 27001...) a été démontrée, pas une certification du produit.
- **Maintenance non garantie** — projet personnel développé en alternance ; une adoption plus large nécessiterait de statuer sur une gouvernance (temps dédié, fork interne).
- **Un audit de sécurité et de qualité mené volontairement sur l'ensemble du code a identifié 25 anomalies classées P0 à P3**, dont 11 corrigées en priorité (exemples : route `/health` exposée sans authentification, score IOC composite retournant systématiquement zéro à cause d'une erreur silencieuse de subprocess, perte de contenu lors de fusions Git multi-agents). Cet audit illustre une démarche rigoureuse, mais aussi que le code n'a pas le niveau de durcissement d'un produit commercial audité en continu.

---

## Ce que ça apporte concrètement à Axians

- Un **support de formation réutilisable** : les analystes juniors peuvent inspecter le code source pour comprendre précisément comment se calcule un score MOS, une projection de capacité ou une classification applicative — impossible sur un outil commercial fermé.
- Un **argument différenciant en avant-vente** : pouvoir dire "nous comprenons ce que nous vous vendons" à un prospect, en s'appuyant sur une démonstration fonctionnelle gratuite avant d'engager une licence.
- Une **base de test sans risque** pour valider des scénarios de détection, des seuils d'alerte ou des règles avant un déploiement en environnement client réel.
- Une **vitrine de compétence interne** en observabilité réseau, avec une méthodologie de développement documentée (itérative, orchestration multi-agents IA avec revue humaine systématique, audit de sécurité).
- **Investissement quasi nul** : licence gratuite (AGPL v3), infrastructure d'une VM standard (6 vCPU / 8 Go RAM / 60 Go disque), déploiement en moins de 30 minutes. Le seul coût réel est le temps de montée en compétence, déjà investi.

---

## Prochaines étapes proposées

1. **Présentation à l'équipe observabilité** pour recueillir un retour d'usage terrain et challenger le positionnement.
2. **Test en labo sur infrastructure Axians** — déploiement physique sur Shuttle Proxmox avec port SPAN dédié et carte réseau Intel i350-T2 (roadmap v3).
3. **Évaluation formelle comme support de formation interne** pour les nouveaux analystes NPM.
4. **Décision de la hiérarchie** sur un élargissement éventuel à l'avant-vente, sur un périmètre de dossiers ciblés, avec en perspective une comparaison côte à côte en conditions réelles face à Netscout, Gigamon et Riverbed.

---

## Questions ?

**Nicolas Malok** — Alternant Analyste Observabilité NPM, Axians / Vinci Energies
`github.com/Ourslow/netwatch` — Licence AGPL v3
