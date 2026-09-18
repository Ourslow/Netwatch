# NetWatch — Positionnement produit

> Ce document acte le passage de NetWatch de « SideQuest école / labo de
> comparaison » à **produit commercialisable**. Il remplace
> `scope-jusquou-va-netwatch.md` (cadrage Axians, juillet 2026) comme
> référence de cap. Tout ce qui est marqué *hypothèse* doit être validé sur le
> terrain avant d'être codé.

Date : 2026-09-18 · Auteur : Nicolas Malok · Statut : **décision de cap, à
challenger après la phase de validation (§ 8)**

---

## 1. Décision en une page

| | |
|---|---|
| **Ce qu'on vend** | Une sonde d'observabilité réseau **NPM + NDR dans une seule boîte**, self-hosted, pour les PME et les MSP francophones qui n'ont ni SOC ni budget Netscout. |
| **Modèle** | **Community** (AGPL v3, gratuit, complet pour une sonde qui fonctionne) + **Pro** (abonnement, clé de licence, fonctions qui font gagner du temps à celui qui paie). Pas de SaaS hébergé en phase 1. |
| **Licence** | Community reste **AGPL v3** tel quel. Le code Pro vit dans un dépôt **privé** (`netwatch-pro`) sous licence commerciale, chargé comme extension par le portail. Pas de dual-licensing du même code. |
| **Marché** | PME 50-500 postes (1 à 3 sites) et MSP / intégrateurs régionaux qui veulent une offre « supervision + sécurité réseau » à revendre. France d'abord, francophonie ensuite. |
| **Différenciation** | (1) NPM et NDR réunis — Security Onion / Malcolm / Clear NDR sont sécurité-only ; (2) IA locale on-prem, zéro donnée qui sort ; (3) français, souverain par transparence du code ; (4) prix PME, pas prix grand compte. |
| **Ce qu'on ne fait pas** | Multi-tenant hébergé, SLA 24/7, qualification ANSSI, capture 40 Gb/s, DPI propriétaire. Assumé, écrit, répété. |
| **Prochaine étape** | **Valider avant de coder** : landing page + 10 conversations MSP/DSI en 6 semaines (§ 8). Le découpage technique Core/Pro ne démarre qu'après un premier signal. |

---

## 2. D'où on part, où on va

**Aujourd'hui** : 24 services Docker, 3 moteurs IDS, 13 dashboards Grafana,
un portail Flask de 22 pages (~6 000 lignes Python), une édition IA
optionnelle, 20+ docs, un parcours de démo. Tout ça a été construit comme
*banc d'essai commercial vs open-source* et présenté à Axians comme outil de
formation / avant-vente interne (`docs/presentation/axians-report.md`).

**Ce qui n'est pas vendable en l'état** : le stack lui-même. Zeek, Suricata,
Snort, Elasticsearch, Grafana, Arkime, ntopng, NetBox sont des briques que
Security Onion et Malcolm assemblent gratuitement depuis dix ans, avec des
communautés que NetWatch n'aura jamais.

**Ce qui est à nous et que personne ne donne** :

1. **Le portail unifié NPM + NDR** — alertes, flux, hostgroups, seuils, SLA,
   VoIP, capacity planning, zero-window, dictionnaire applicatif, topologie,
   pivot `/ip/<ip>` qui agrège tout. C'est la couche « Netscout-like » que les
   projets sécurité-only n'ont pas.
2. **La couche IA locale** — explication d'alerte, narration PCAP, résumé
   exécutif, agents (`llm_client.py`, `llmops.py`, `agents-deck/`).
3. **Le packaging** — éditions Core/IA, répartition 2 VMs, `make health` sur
   24 services, plan Shuttle, install en 30 minutes.
4. **Le regard NPM** — le projet est né chez un analyste observabilité qui
   connaît les vraies demandes clients (SLA heures ouvrées, MOS VoIP,
   retransmissions, import hostgroups « à la NetScout »). C'est ce qui
   manque aux projets nés dans des SOC.

**Où on va** : un produit dont la valeur est dans le portail, l'IA, le
packaging et le support — pas dans les moteurs. Le stack open-source reste le
socle gratuit qui amène les utilisateurs ; on monétise ce qui est au-dessus.

---

## 3. Cibles

### 3.1 Cible principale — la PME sans SOC

- 50 à 500 postes, 1 à 3 sites, un DSI ou un « responsable info » seul ou
  avec 1-2 personnes, souvent un prestataire pour la sécurité.
- Douleurs : « je ne sais pas ce qui passe sur mon réseau », NIS2 qui arrive
  (obligation de détection pour les entités importantes), un devis Netscout ou
  Darktrace à 5 chiffres qu'ils ont refusé, un audit ANSSI/assureur qui
  demande « une capacité de détection réseau ».
- Ce qu'ils achètent : une boîte qui s'installe sur un port SPAN, un tableau
  de bord compréhensible, un rapport mensuel qu'on peut montrer à la
  direction ou à l'assureur, quelqu'un à appeler.

### 3.2 Cible de distribution — le MSP / intégrateur régional

- 10 à 50 clients PME, cherche une brique « supervision + sécurité réseau »
  à revendre en récurrent sans former un SOC.
- Douleurs : les éditeurs NDR ne veulent pas de leurs petits clients, les
  outils gratuits demandent trop de temps d'exploitation, ils ont besoin
  d'une vue multi-clients.
- Ce qu'ils achètent : une licence par sonde déployée chez leurs clients, une
  console centrale (phase 2), une marge.

C'est **le canal qui fait passer d'un produit à un business** : un MSP qui
signe déploie 10 sondes, une PME en déploie une.

### 3.3 Cibles secondaires (ne pas construire pour elles, mais les accepter)

- **Formation / écoles** : édition Community, gratuite, visibilité.
- **Audit ponctuel / avant-vente d'intégrateurs** : l'usage actuel chez
  Axians. Community suffit ; Pro si rapports et IA.

---

## 4. Proposition de valeur

> **NetWatch — voir et protéger son réseau, sans SOC et sans budget grand
> compte.** Une sonde qui réunit supervision de la performance (NPM) et
> détection des menaces (NDR), 100 % sur site, avec une IA locale qui
> explique ce qu'elle voit. Open-source, français, prix PME.

Trois promesses vérifiables, dans cet ordre :

1. **En 30 minutes je vois mon réseau** — top talkers, applications,
   interfaces saturées, alertes, tout dans un seul portail.
2. **Rien ne sort de mon réseau** — capture, analyse, IA : tout est on-prem.
   Argument souveraineté / RGPD / secteurs sensibles.
3. **Je peux le montrer à ma direction** — rapports PDF, matrices
   NIS2/ISO 27001/ANSSI, SLA heures ouvrées.

---

## 5. Concurrence et différenciation

| Solution | Ce que c'est | Prix | Où NetWatch se place |
|---|---|---|---|
| **Security Onion** (US) | NSM/SIEM complet, Zeek + Suricata + Elastic, très mature | Gratuit + support Pro | Sécurité-only, lourd, anglais, orienté SOC. NetWatch : NPM en plus, plus léger, français. |
| **Malcolm** (US/CISA) | Zeek + Arkime + OpenSearch dockerisés, l'équivalent le plus proche | Gratuit | Pas de portail unifié, pas d'IA, pas de NPM, pas de support. NetWatch : la couche au-dessus. |
| **Clear NDR Community / Stamus** (FR-US) | Suricata + Scirius + Arkime, open-core, 10 ans | Gratuit + Clear NDR commercial (grand compte) | Le cousin direct sur le NDR, mieux doté en détection. NetWatch ne l'attaque pas frontalement : NPM + PME + IA locale. **Partenaire possible** (rulesets Stamus). |
| **Gatewatcher, Custocy, Sesame IT** (FR) | NDR souverains propriétaires, qualifiés ANSSI | 5-6 chiffres/an | OIV/ETI/grands comptes. NetWatch est le « souverain accessible » en dessous — ne pas prétendre au même niveau. |
| **Netscout, Riverbed, Gigamon** | NPM commerciaux de référence | 10-100 k€/an | La référence fonctionnelle que NetWatch reproduit à 70-80 %. Leur non-marché (PME) est notre marché. |
| **Centreon, Zabbix, PRTG** | Supervision par métriques/SNMP | Open-core / licence | Complémentaires (pas de capture de flux). Export vers Centreon = argument intégrateur. |
| **Darktrace, Vectra, ExtraHop** | NDR IA cloud | 5-6 chiffres/an | Hors budget PME, données dans le cloud. NetWatch = l'anti-Darktrace : local, explicable, abordable. |

**La phrase à retenir** : *les gratuits sont sécurité-only et sans support ;
les commerciaux sont hors budget PME ; les souverains visent les OIV.
NetWatch est le seul à réunir NPM + NDR + IA locale, en français, au prix
d'une PME.*

---

## 6. Modèle économique

### 6.1 Pourquoi pas un SaaS hébergé (phase 1)

- Les **sondes doivent être sur le LAN du client** (port SPAN). Le SaaS ne
  peut porter que la console, pas la capture.
- Un multi-tenant hébergé tenu par une personne en CDI = astreinte, RGPD
  (les PCAP contiennent des données personnelles), sécurité d'une plateforme
  qui centralise le trafic de tous les clients. Pas tenable seul.
- **Piège licence** : Elasticsearch 8.13 est sous SSPL / Elastic License 2.0
  qui interdit de l'offrir en service managé. Héberger ES pour des clients
  impose ES ≥ 8.16 (option AGPL) ou OpenSearch. À traiter *avant* toute
  phase 2.

### 6.2 Le modèle retenu — sonde on-prem + abonnement

| Édition | Prix (*hypothèse à tester*) | Contenu |
|---|---|---|
| **Community** | 0 € | Tout ce qu'il faut pour une sonde complète et utile en production : les 3 moteurs, les dashboards, le portail de base, la doc complète. Sans limite de durée ni de volume. |
| **Pro** | 99-149 €/mois/sonde, engagement annuel | IA locale, rapports et conformité, intégrations métier, feeds curés, RBAC/SSO, support par e-mail J+1, mises à jour prioritaires. |
| **Pro MSP** | tarif dégressif par sonde + console centrale (phase 2) | Multi-clients, marque blanche légère, support prioritaire. |

Ordres de grandeur : 20 sondes Pro = ~30 k€/an, ce qui finance du temps
réel sur le projet. 100 sondes = un salaire. Ce n'est pas un business de
licorne, c'est un produit soutenable par une personne puis deux.

### 6.3 Principes du découpage Community / Pro

Le principe qui tranche chaque cas :

- **Community** = tout ce qui est nécessaire pour que la sonde **fonctionne et
  détecte**. Un utilisateur Community ne doit jamais avoir l'impression
  d'un produit bridé — c'est lui qui fait la réputation.
- **Pro** = ce qui fait **gagner du temps ou rassure celui qui paie** :
  synthèse, rapports, intégrations dans ses outils, IA, gestion multi-sites,
  et l'humain derrière.
- **Jamais payant** : la documentation (c'est le canal d'acquisition), les
  correctifs de sécurité, les moteurs et leurs règles publiques, les
  dashboards Grafana, `make health`, l'installation.

### 6.4 Découpage feature par feature (état actuel du dépôt)

| Fonctionnalité | Community | Pro | Note |
|---|:-:|:-:|---|
| 3 moteurs IDS (Zeek, Snort, Suricata) + règles ET Open / community | ● | | Socle. |
| beacon-detect, DNS tunneling, JA3/HASSH, Zeek Intel (feeds publics) | ● | | Socle détection. |
| AutoBlock, CrowdSec | ● | | Réponse de base. |
| 13 dashboards Grafana | ● | | Jamais payant. |
| Portail : alertes, flux, top talkers, Zeek logs, geomap, status, `/ip/<ip>` | ● | | Le produit doit être utile gratuit. |
| NetFlow/IPFIX, SNMP interfaces, topologie, capacity planning | ● | | C'est l'argument NPM, il doit être visible en Community. |
| VoIP MOS, zero-window, conversations PCAP, sondes Blackbox | ● | | Idem. |
| Hostgroups (import CSV), seuils, dashboard personnalisable | ● | | |
| Kibana, Arkime, ntopng, NetBox intégrés | ● | | Briques OSS, on ne les vend pas. |
| Dictionnaire applicatif SNI — base | ● | | |
| Dictionnaire applicatif — **étendu et maintenu** (mises à jour mensuelles) | | ● | Valeur = la maintenance. |
| Audit trail du portail | ● | | Sécurité de base, pas une feature Pro. |
| Login local | ● | | |
| **RBAC multi-utilisateurs, SSO (OIDC/LDAP)** | | ● | Besoin MSP/PME structurée. |
| **IA locale** : explication d'alerte, résumé exécutif, narration PCAP, agents | | ● | Différenciateur principal. |
| **Rapports PDF planifiés, rapport hebdo direction** | | ● | « Montrer à ma direction ». |
| **Matrices de conformité NIS2 / ISO 27001 / ANSSI / NIST CSF** | | ● | Pack conformité, mis à jour avec les référentiels. |
| **SLA heures ouvrées / off-hours, engagements par service** | | ● | Le SLA brut reste Community ; la modélisation métier est Pro. |
| **Intégrations ITSM** (ServiceNow, JIRA), n8n workflows packagés, Teams/Slack | | ● | Intégration dans les outils du client. |
| **Enrichissement IOC** (AbuseIPDB, ipinfo) + scoring composite | | ● | Coût d'API, feed curé. |
| **Feed d'intel NetWatch curé** (IP/domaines, règles custom maintenues) | | ● | Valeur = la maintenance. |
| **Multi-sites / console centrale** | | ● | Phase 2. |
| Import hostgroups depuis NetBox | ● | | |
| Gestion VMs Proxmox/ESXi, catalogue de déploiement | | | **À trancher** : c'est l'héritage « labo ». Soit édition Lab séparée, soit feature Pro MSP (déploiement de sondes), soit retiré du produit. Voir § 10. |
| Support e-mail J+1, mises à jour prioritaires, accès aux versions LTS | | ● | L'humain derrière. |

---

## 7. Ce qu'il manque pour être vendable (l'écart labo → produit)

Rien de ceci n'est de la « feature ». C'est ce qui distingue une démo qui
impressionne d'un produit qu'un client paie et sur lequel il compte.

| Chantier | État | Requis pour |
|---|---|---|
| **Installation en une commande** sur Ubuntu 22.04/24.04 (script + ISO/OVA plus tard) | `make install` existe, dépend de docker déjà présent et d'un `.env` à la main | Pilote 1 |
| **Mise à jour sans perte** (`netwatch upgrade`, migration des index, changelog) | Aucun chemin de mise à jour | Pilote 1 |
| **Sauvegarde / restauration** (config, hostgroups, seuils, rapports, index ES) | Aucun | Pilote 1 |
| **TLS partout, reverse proxy unique** (un seul port 443 devant portail/Grafana/Kibana/Arkime) | Portail en HTTP, 8 ports exposés | Pilote 1 |
| **Auth unifiée** (le portail authentifie, Grafana/Kibana derrière lui) | Login portail seul ; Grafana/Kibana/Arkime chacun leur auth | Pilote 1 |
| **Mécanisme de licence** (clé signée hors ligne, pas de « phone home » obligatoire — argument souveraineté) | Aucun | Première vente |
| **Versioning et releases** (semver, tags, images publiées, changelog) | Pas de tag, images construites localement | Pilote 1 |
| **Tests automatisés** minimum (portail, health, replay PCAP en CI) | Pas de CI | Avant le split |
| **Rétention et dimensionnement** documentés (ILM Elasticsearch, disque PCAP) | ILM absent, capacity-planning.md partiel | Pilote 1 |
| **Télémétrie opt-in** (versions, santé — jamais de données réseau) | Aucune | Phase 2 |
| **Canal de support** (adresse, portail de tickets, base de connaissances) | GitHub issues | Première vente |
| **Statut juridique, CGV, EULA Pro, DPA** (RGPD sous-traitant) | Aucun | Première vente |

**Ordre** : tests + CI → reverse proxy/TLS/auth → install/upgrade/backup →
licence → split Pro. Le split arrive **en dernier** des chantiers techniques
parce qu'il n'a de valeur que sur une base qui tient.

---

## 8. Valider avant de coder

Le risque n°1 n'est pas technique : c'est de passer six mois à découper
Core/Pro pour un marché qui ne paie pas. Six semaines de validation avant
d'ouvrir le chantier technique.

### 8.1 Ce qu'on fait

1. **Landing page** (une page, français) : promesse § 4, trois captures du
   portail, prix hypothèse, formulaire « demander une démo » / « rejoindre la
   bêta Pro ». Coût : un week-end.
2. **10 conversations** de 30 minutes, dans cet ordre de priorité : 4 MSP /
   intégrateurs régionaux, 4 DSI de PME 50-500 postes, 2 RSSI externalisés /
   consultants NIS2. Réseau perso, LinkedIn, meetups monitoring-fr,
   Campus Cyber. **Pas Axians ni ses clients** (§ 9).
3. **Une question par conversation** : « Vous payez combien aujourd'hui pour
   savoir ce qui passe sur votre réseau, et qu'est-ce qui vous ferait payer
   100 €/mois pour ça ? »
4. **Un pilote gratuit** chez le contact le plus chaud, sur le Shuttle,
   3 semaines, en échange d'un retour écrit et d'un témoignage si concluant.

### 8.2 Critères de décision (à la fin des 6 semaines)

| Signal | Décision |
|---|---|
| ≥ 3 interlocuteurs veulent le pilote et ≥ 1 accepterait de payer le prix hypothèse | **Go** : chantiers § 7 puis split Pro. |
| Intérêt mais « seulement si c'est gratuit » | Rester Community + monétiser le service (audit, intégration, formation). Pas de split Pro. |
| Intérêt seulement de la part des MSP | Prioriser la console multi-clients avant l'IA. |
| Personne ne mord | NetWatch reste un projet portfolio/communauté. C'est un résultat, pas un échec. |

---

## 9. Prérequis non techniques — à régler avant le premier euro

1. **Propriété intellectuelle vis-à-vis d'Axians.** NetWatch a été développé
   pendant l'alternance, présenté en interne comme outil de formation /
   avant-vente, et discuté en réunion d'équipe. En droit français, le
   logiciel créé par un salarié *dans l'exercice de ses fonctions ou d'après
   les instructions de l'employeur* appartient à l'employeur (art. L113-9
   CPI). Il faut donc : (a) relire le contrat d'alternance (clause PI,
   exclusivité, non-concurrence) ; (b) pouvoir démontrer que le développement
   s'est fait hors temps, hors matériel et hors données Axians (l'historique
   git public en est une preuve partielle) ; (c) **obtenir une clarification
   écrite** de la hiérarchie : NetWatch est un projet personnel, Axians peut
   en être utilisateur ou partenaire, pas propriétaire. Sans (c), ne pas
   facturer.
2. **Ne pas vendre aux clients Axians ni concurrencer l'offre Axians** tant
   que le contrat court. Le positionnement « complémentaire, pas concurrent »
   du rapport interne reste vrai et protège.
3. **Statut** : micro-entreprise suffit pour les premières factures ; SASU si
   un MSP demande un contrat cadre.
4. **Contrats** : CGV + EULA Pro (une page, honnête sur les limites du § 1),
   et un DPA type parce qu'une sonde qui capture du trafic traite des
   données personnelles (le client est responsable de traitement, NetWatch
   n'accède jamais aux données — à écrire noir sur blanc).
5. **Licences tierces** : on distribue des fichiers Compose qui référencent
   des images tierces, on ne redistribue pas leur code. Zeek (BSD), Suricata
   et Snort (GPLv2), Grafana (AGPL), Arkime et NetBox (Apache 2), ntopng
   (GPLv3), Elasticsearch/Kibana (SSPL/ELv2 — OK en self-hosted, pas en
   service managé). Le code Pro n'embarque aucune de ces briques.

---

## 10. Questions ouvertes

- **Gestion Proxmox/ESXi et catalogue d'outils** : vestige du « lab
  multi-outils ». Proposition : sortir du produit et garder dans une édition
  *Lab* documentée à part, sauf si les MSP en font une demande explicite
  (déploiement de sondes chez leurs clients).
- **Nom** : « NetWatch » est très générique (collisions probables avec des
  marques existantes). À vérifier à l'INPI avant la landing page ; prévoir
  un nom de secours.
- **Ollama en Pro** : l'IA locale exige 4-5 Go de RAM en plus et un modèle
  à télécharger. Sur des sondes PME à 8 Go, ce sera l'obstacle n°1 au
  déploiement de Pro. Étudier un modèle plus petit (3B quantisé) ou un
  mode « IA sur poste admin » plutôt que sur la sonde.
- **OpenSearch vs Elasticsearch** : sans conséquence en phase 1 ; à trancher
  avant toute console hébergée (§ 6.1).

---

## 11. Ce qui change dès maintenant dans le dépôt

- Le README abandonne « SideQuest MVP » et « banc d'essai » au profit du
  positionnement § 4 (édition Community), avec un encart « Pro : bientôt,
  inscription à la bêta ».
- `CLAUDE.md` référence ce document comme cap ; la roadmap v3 devient la
  roadmap § 7.
- Aucune fonctionnalité n'est retirée ni bridée tant que la phase de
  validation n'est pas terminée.
