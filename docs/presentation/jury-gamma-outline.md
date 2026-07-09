# NetWatch v2 — Soutenance École 2600

### Stack d'observabilité réseau open-source multi-moteurs (NDR + NPM)

**Nicolas Malok** — Alternant Analyste Observabilité NPM chez Axians / Vinci Energies
École 2600, promotion 2024-2027 — SideQuest MVP, semestre 2 (2025-2026)
Dépôt public : `github.com/Ourslow/netwatch` — Licence AGPL v3

---

## 1. Contexte et problématique

En alternance chez **Axians**, filiale de **Vinci Energies**, je suis positionné comme analyste observabilité NPM (Network Performance Monitoring). Axians revend et intègre des solutions commerciales de référence sur ce marché : **Netscout nGeniusONE**, **Gigamon** et **Riverbed**. Ce sont des outils puissants, mais qui présentent deux limites concrètes observées sur le terrain :

- **Un coût élevé et opaque** : selon le périmètre fonctionnel et le nombre de sondes, ces solutions coûtent entre **10 000 € et plus de 100 000 € par an**, souvent sans que les équipes utilisatrices comprennent réellement les mécanismes internes de détection ou de calcul des métriques.
- **Un effet "boîte noire"** : la logique de scoring, de fingerprinting ou de calcul de qualité de service n'est pas exposée, ce qui limite la montée en compétence réelle des équipes qui les exploitent au quotidien.

**Problématique retenue pour le SideQuest MVP :** est-il possible de reproduire, avec des briques 100% open-source, les fonctionnalités clés d'un outil NPM/NDR commercial, en conservant une qualité de service et une couverture fonctionnelle crédibles ?

Ce projet est évalué par le jury École 2600 autant sur la **démarche méthodologique** que sur le résultat technique livré.

---

## 2. Objectifs pédagogiques

| Objectif | Compétence visée | Concrétisation dans le projet |
|---|---|---|
| Comprendre en profondeur le fonctionnement interne d'un NPM/NDR | Analyse protocolaire, métriques réseau, calculs statistiques | Lecture et implémentation des formules mêmes (MOS E-model, `predict_linear`, score composite IOC) plutôt que consommation d'un outil clé en main |
| Manipuler des moteurs IDS/NSM en conditions réelles | Administration Zeek, Snort, Suricata en environnement conteneurisé | Compilation de Snort 3 depuis les sources, écriture de règles custom mappées MITRE ATT&CK |
| Construire une chaîne d'observabilité complète et opérationnelle | Ingestion, stockage, visualisation (ELK, Prometheus, Grafana) | 14 services orchestrés, 13 dashboards provisionnés automatiquement |
| Automatiser la réponse à incident et l'escalade | SOAR léger (n8n, webhook, scripts Python) | 5 workflows n8n dont un mécanisme d'escalade à 3 actions (blocage, ticket, notification) |
| Conduire un projet dans la durée avec méthode | Gestion de projet itérative, documentation, audit | v1 puis v2 en 7 phases incrémentales, audit de sécurité interne du code produit |

---

## 3. Concept NetWatch — NDR + NPM open-source

Le principe central du projet est de faire tourner **3 moteurs d'analyse en parallèle sur exactement le même flux de trafic réseau** (capture SPAN ou rejeu PCAP), afin de comparer objectivement leurs forces et faiblesses respectives plutôt que de se reposer sur un seul outil :

```
Trafic réseau (SPAN / PCAP)
        │
    ┌───┼───┐
    ▼   ▼   ▼
  Zeek Snort Suricata     ← 3 perspectives sur le même trafic
    └───┬───┘
        ▼
    Filebeat 8.13 → Elasticsearch 8.13 → Grafana 10.4 + Portail Flask
```

À ce socle sécurité (NDR) s'ajoute, à partir de la phase 5 de la v2, un **second pipeline dédié à la supervision de performance réseau (NPM)** : collecte NetFlow/IPFIX/sFlow via GoFlow2, supervision d'interfaces SNMP, topologie réseau auto-découverte, capacity planning, qualité VoIP et conformité SLA — soit précisément les briques qui distinguent un outil NPM commercial (Netscout, Riverbed) d'un simple IDS.

Le résultat final est une stack de **14 services Docker orchestrés**, avec un portail web Flask (port 5050) qui centralise les deux volets (sécurité + performance) dans **9 pages** dédiées par profil d'utilisateur (analyste, RSSI, direction).

---

## 4. État de l'art — comparaison avec les solutions commerciales de référence

Cette comparaison, construite à partir de mon expérience terrain chez Axians, a directement guidé la priorisation fonctionnelle des phases 5 à 7 de la v2 (orientées NPM plutôt que uniquement sécurité) :

| Fonctionnalité | NetWatch v2 | Solutions commerciales de référence |
|---|---|---|
| Capture et analyse réseau | Zeek 6.2 (analyse protocolaire) | Corelight, nGenius Probe |
| Détection par signatures | Snort 3.3.5 + Suricata 7 (ET Open) | Suricata OEM, Snort Enterprise |
| Fingerprinting TLS/SSH | JA3, JA3S, HASSH (natifs Zeek 6.x) | DPI natif (ExtraHop, Corelight) |
| Détection comportementale | RITA-lite maison (beaconing, DNS tunneling) | Darktrace AI, ExtraHop Reveal(x) |
| Réponse automatique | AutoBlock → iptables (webhook Flask) | Cisco Stealthwatch + NAC, Palo Alto XSOAR |
| Analyse NetFlow / IPFIX / sFlow | GoFlow2 → Elasticsearch `netflow-*` | Netscout nGeniusONE, Gigamon |
| Supervision SNMP interfaces | SNMP Exporter + IF-MIB | Netscout, SolarWinds NPM |
| Topologie réseau L2/L3 | LLDP-MIB + ARP Zeek → D3.js force-directed | Riverbed NetIM, SolarWinds NTM |
| Capacity planning | `predict_linear` / `deriv` Prometheus | Netscout, PRTG, ManageEngine |
| Qualité VoIP | MOS E-model G.107 (calcul Zeek SIP/RTP) | Netscout InfiniStreamNG, Empirix |
| Conformité SLA | Percentiles Elasticsearch p95 | Netscout nGeniusONE, Riverbed |
| **Coût annuel** | **Gratuit (AGPL v3)** | **10 000 – 100 000+ €/an** |

Le constat assumé dans le mémoire : la maturité fonctionnelle est crédible sur un périmètre ciblé, mais la maturité opérationnelle (fiabilité en production à l'échelle, support éditeur) reste en retrait des solutions commerciales établies. Ce n'est pas un produit de substitution mais un outil de compréhension et de démonstration.

---

## 5. Démarche méthodologique

Le projet a été conduit selon une logique **itérative et incrémentale**, avec une livraison testable à chaque étape plutôt qu'un développement monolithique :

- **v1 (mars 2026)** : socle minimal fonctionnel — 4 services Docker (Zeek, Filebeat, Elasticsearch, Grafana), 4 dashboards, 2 scripts Zeek custom (détection de scan de ports, entropie DNS de Shannon), un simulateur de trafic Python.
- **v2 (juin 2026)** : montée en gamme progressive en **7 phases livrées successivement**, chaque phase apportant une capacité de détection ou de supervision nouvelle et démontrable indépendamment des autres.

**Choix méthodologique assumé — orchestration multi-agents IA :** j'ai utilisé un outil interne (*agents-deck*) pour paralléliser le développement selon quatre domaines fonctionnels — infrastructure, sécurité, automatisation, frontend — chacun avancé sur un **worktree Git dédié** avec une branche active. Ce choix a permis d'avancer sur plusieurs fronts simultanément, mais a imposé un contrôle humain strict et non négociable sur trois points :

1. **La relecture systématique de chaque livraison avant fusion** — aucun code d'agent n'est intégré sans validation humaine.
2. **La fiabilisation du processus de fusion Git lui-même**, après identification d'un défaut réel : des commits de fusion réduits à un seul parent (au lieu de deux) lorsque `MERGE_HEAD` était perdu avant le commit de résolution de conflit, entraînant une perte silencieuse de contenu.
3. **Un audit de sécurité et de qualité mené a posteriori** sur l'ensemble du code produit par les agents, indépendamment de leur production.

Cette organisation a permis de développer une compétence de **pilotage d'agents IA sur un projet réel**, distincte de la compétence de codage : cadrage précis des tâches, relecture critique systématique, validation d'intégration — une compétence directement transposable en environnement professionnel.

---

## 6. Les 7 phases de la v2 — détail des livrables

| Phase | Contenu livré |
|---|---|
| **1-3** | Passage de 4 à 12 services (ajout Snort 3, Suricata 7, Prometheus, beacon-detect, autoblock, CrowdSec, n8n) · graphe IOC interactif (NetworkX) · health-check consolidé 12 services · calibrage de 12 règles IDS · détection de mouvement latéral |
| **4** | Dashboard exécutif `/exec` pour profil RSSI/direction · score de risque IOC composite multi-sources · escalade automatisée intelligente via n8n (seuil configurable, anti-doublon TTL 4h) |
| **5** | Intégration GoFlow2 (NetFlow v9/IPFIX/sFlow v5) · page `/flows` · calcul du temps de réponse applicatif (ART) · santé des connexions TCP |
| **6** | SNMP Exporter + IF-MIB · topologie réseau auto-découverte en D3.js (`/topology`) · classification applicative sur **425 ports** et **100+ vendors réseau** (reconnaissance OUI) |
| **7** | Capacity planning (`predict_linear` Prometheus) · qualité VoIP (score MOS E-model G.107) · conformité SLA (`/sla`) · intégration ITSM ServiceNow/JIRA via n8n |

**Résultat cumulé de la v2 : 14 services Docker, 13 dashboards Grafana provisionnés automatiquement, 9 pages de portail Flask, 5 workflows n8n opérationnels.**

---

## 7. Architecture technique et choix justifiés

```
Trafic réseau (SPAN / PCAP)
        │
    ┌───┼───┐
    ▼   ▼   ▼
  Zeek Snort Suricata        ← 3 moteurs, même trafic
    └───┬───┘
        ▼
    Filebeat 8.13             ← collecte unifiée, index par moteur
        ▼
 Elasticsearch 8.13           ← zeek-* / snort-* / suricata-* / netflow-*
        ▼
 Grafana 10.4 + Portail Flask ← visualisation, IA locale Ollama, PDF
```

| Composant | Outil | Version |
|---|---|---|
| Analyse protocolaire | Zeek | 6.2 |
| IDS signatures | Snort | 3.3.5 (build from source, libdaq + tcmalloc) |
| IDS/NSM | Suricata | 7.0 (Emerging Threats Open, auto-update quotidien) |
| Transport de logs | Filebeat | 8.13 |
| Indexation | Elasticsearch | 8.13 (JVM heap 2 Go) |
| Visualisation | Grafana | 10.4 |
| Métriques système | Prometheus + node-exporter | 2.51 / 1.7 |
| Collecte NetFlow/IPFIX/sFlow | GoFlow2 | latest |
| Supervision SNMP | SNMP Exporter (prom/snmp-exporter) | latest |
| Portail web | Flask | 3.x |
| IA locale | Ollama / Mistral | on-prem, zéro fuite de données |
| IPS collaboratif | CrowdSec | 5 collections (linux, nginx, suricata, sshd, base-http-scenarios) |
| Automatisation | n8n | 2.x, 5 workflows |
| Orchestration agents IA | agents-deck (interne) | 2.0 |

**Trois choix d'architecture justifiés dans le mémoire :**

- **Zeek plutôt que tcpdump/Wireshark en frontal** : logs structurés nativement en JSON, directement exploitables par Elasticsearch sans étape de parsing intermédiaire fragile.
- **Trois moteurs IDS en parallèle plutôt qu'un seul** : condition nécessaire pour objectiver les forces/faiblesses respectives des approches signatures (Snort/Suricata) vs comportementale (RITA-lite) vs protocolaire (Zeek), plutôt qu'un choix arbitraire d'un seul outil.
- **Elasticsearch + Grafana plutôt qu'un SIEM commercial** : coût nul et écosystème mature, en contrepartie d'un travail de modélisation d'index et de templates nettement plus lourd qu'un outil clé en main (bug T_002 rencontré à ce sujet, voir slide difficultés).

**Infrastructure cible (v3)** : architecture 2 VMs sur Proxmox VE, serveur Shuttle Xeon 16 Go RAM — VM Sensors (4 vCPU / 6 Go, Zeek+Snort+Suricata+Filebeat) et VM Data (4 vCPU / 10 Go, ES+Grafana+Prometheus), carte réseau de capture dédiée **Intel i350-T2** (dual port, pilote igb, af-packet natif) alimentée par un port SPAN sur switch manageable.

---

## 8. Démonstration — Détection et supervision opérationnelle

- **`/dashboard`** : alertes temps réel avec sparklines, auto-refresh 30 secondes, filtres par moteur (Zeek/Snort/Suricata) et par sévérité, accès rapide aux trois moteurs.
- **`/status`** : supervision en temps réel de la santé des **14 services Docker** (Elasticsearch, Grafana, Prometheus, AutoBlock, IA locale Ollama), avec `make health` qui produit un rapport coloré ✓/⚠/✗ et un code de sortie exploitable en intégration continue.
- **`/agents`** : monitoring des agents IA en cours d'exécution — état, ticket en cours de traitement, dernière activité, rafraîchissement toutes les 15 secondes. Cette page illustre concrètement le pilotage de l'orchestration multi-agents évoquée en slide 5.
- **13 dashboards Grafana** couvrant : vue réseau, analyse DNS, HTTP/TLS, alertes par moteur (Zeek/Snort/Suricata), corrélation multi-moteurs sur un même axe temporel, santé de la VM, top talkers, fingerprints JA3/HASSH, détecteur de beaconing, interfaces SNMP, capacity planning.

---

## 9. Démonstration — Vue exécutive et volet NPM

- **`/exec`** : dashboard destiné à un profil RSSI ou direction — score de risque IOC composite (formule détaillée en slide 11), tendance dans le temps, escalade automatisée vers n8n en cas de dépassement de seuil.
- **`/flows`** : exploitation des flux GoFlow2 (NetFlow v9 port UDP 2055, IPFIX port 4739, sFlow v5 port 6343) — débit réseau, temps de réponse applicatif (ART), santé des connexions TCP, top applications par catégorie via la classification sur 425 ports. Rétention des index `netflow-*` gérée par une politique ILM à **30 jours**.
- **`/topology`** : cartographie réseau L2/L3 auto-découverte par combinaison SNMP LLDP-MIB et table ARP Zeek, rendue en D3.js force-directed (routeurs, switchs, firewalls, hôtes).
- **`/sla`** : taux de conformité SLA calculé sur des percentiles Elasticsearch p95 (HTTP, DNS, RTT) sur une fenêtre de 7 jours, avec distinction explicite heures ouvrées / heures non-ouvrées — un besoin métier réel côté NPM, absent des IDS classiques.
- **`/graph`** : graphe IOC interactif en D3.js — nœuds IP, règles, techniques MITRE, avec enrichissement de réputation en un clic.

---

## 10. Sécurité, scoring et conformité réglementaire

**Détection comportementale RITA-lite** (`beacon-detect`, analyse toutes les 15 minutes sur `zeek-*`) :

| Détection | Logique précise | Seuil |
|---|---|---|
| Beaconing C2 | Coefficient de variation (écart-type / moyenne) des intervalles entre connexions d'une même paire src/dst/port | CV < 0.25 et ≥ 8 connexions |
| Connexions longues | Durée de connexion issue de `conn.log` | > 3600 secondes (1h) |
| DNS Tunneling | Longueur de sous-domaine ou volume de requêtes vers un même domaine | > 40 caractères OU > 100 requêtes |

**Score de risque IOC composite** (`ioc-score.py`, exposé via `GET /api/ioc-scores`, cache TTL 5 min) — conçu pour réduire la dépendance à une seule source de réputation :

```
score = nb_alertes × 1
      + somme des poids de sévérité (Suricata 10/5/2/1, Snort 5/2/1, Zeek 2)
      + moteurs_distincts × 15   (jusqu'à 3 moteurs = +45)
      + abuseConfidenceScore / 10   (si AbuseIPDB disponible)
      + techniques MITRE uniques × 8
      → plafonné à 100
```

Exemple réel documenté : l'IP `185.220.101.46` (nœud Tor connu) atteint un **score de 80/100 (critical)** avec seulement 4 alertes, grâce au bonus multi-moteurs (Suricata + Snort, +30) et à 2 techniques MITRE uniques (T1090, T1573, +16). Sur un test en conditions live (572 alertes traitées, 51 nœuds de graphe dont 29 IP), l'enrichissement automatique a écarté 21 IPs privées (RFC 1918) et enrichi 8 IPs publiques via ipinfo.io, révélant notamment un nœud Tor allemand et un hébergeur suspect à Hong Kong.

**Conformité réglementaire** — matrices couvert/partiel exposées sur `/compliance` :

| Référentiel | Couverture | Détail |
|---|---|---|
| NIS2 (Art. 21.2) | Couvert | Surveillance réseau, détection, réponse aux incidents |
| NIST CSF 2.0 | Couvert | Fort sur les fonctions Detect (DE) et Respond (RS) |
| ANSSI | Partiel | Hygiène informatique + PA-022 supervision réseau |
| ISO 27001:2022 | Couvert | A.8.15 (logs), A.8.16 (surveillance), A.8.23 (filtrage) |

**Audit de sécurité interne mené sur le code du projet lui-même** (et non seulement sur ce qu'il détecte) : **25 anomalies identifiées, classées par criticité P0 à P3, dont 11 corrigées en priorité** — notamment une route d'administration `/health` exposée sans authentification et une vérification TLS désactivée par défaut sur certains appels sortants.

---

## 11. Difficultés rencontrées — analyse de cause racine et solution

| Difficulté | Cause racine | Solution technique apportée |
|---|---|---|
| Build Snort 3 échouant de façon intermittente | Compilation depuis les sources avec dépendances système fragiles (`libdaq`, `gperftools`/tcmalloc) | Dockerfile dédié isolant totalement la chaîne de compilation (~15 min de build isolé, reproductible) |
| Perte silencieuse de contenu lors des fusions Git multi-agents | Commits de fusion réduits à un seul parent lorsque `MERGE_HEAD` était perdu avant le commit de résolution de conflit | Fiabilisation du workflow : résolution de conflit et commit systématiquement effectués avant toute autre opération Git, garantissant un commit à deux parents |
| Score de risque IOC composite systématiquement nul | Appel à un script externe via un flag de ligne de commande inexistant, erreur silencieuse en sortie de `subprocess` | Remplacement par un fichier temporaire de sortie explicite, avec lecture du code de retour |
| Détection de beaconing C2 ne remontant aucune IP source | Lecture de champs Elasticsearch imbriqués (`id.orig_h`) traités à tort comme des clés à plat | Correction de l'accès aux champs nested dans les requêtes d'agrégation |
| Route d'administration `/health` exposée sans authentification | Oubli du décorateur d'authentification lors de l'ajout de la route (identifié lors de l'audit de sécurité) | Ajout systématique du contrôle d'authentification, revue de toutes les routes existantes |
| Tableau de bord agents-deck affichant un état obsolète | Le tableau de bord lit les fichiers d'état depuis le dépôt principal, pas depuis les worktrees d'agents actifs | Synchronisation systématique des fichiers d'état vers le dépôt principal après chaque fusion |
| Filebeat refusait de démarrer | Permissions du fichier de configuration incompatibles (`filebeat.yml` non détenu par root) | `chown root:root` + `chmod 644` documentés dans le guide de déploiement |
| Indexation Elasticsearch en échec (`data_stream must be enabled`) | Templates ES absents ou conflit data-stream (bug connu référencé T_002) | Script `setup-es.sh` dédié : recréation des templates d'index et du pipeline GeoIP avant tout démarrage de Filebeat |

Chaque bug a été l'occasion de comprendre un mécanisme technique plus en profondeur (fusion Git à deux parents, mapping nested Elasticsearch, cycle de vie des templates d'index) plutôt qu'un simple contournement.

---

## 12. Compétences développées

**Compétences techniques :**

- **Administration de moteurs IDS/NSM en environnement conteneurisé** : Zeek (Intel Framework, scripts custom Shannon), Snort 3 (build from source, règles SID 1000001-1000017 mappées MITRE ATT&CK), Suricata 7 (EVE JSON, Community ID, règles custom SID 2000001-2000007, threading multi-cœur af-packet).
- **Modélisation et exploitation d'une stack ELK complète** : conception d'index par moteur, pipelines d'ingestion GeoIP, requêtes d'agrégation Elasticsearch (percentiles p95, `terms` aggregations pour top talkers), gestion de politiques ILM (rétention 30 jours sur `netflow-*`).
- **Développement de services de supervision réseau** : Prometheus (recording rules, `predict_linear`, `deriv` pour la régression linéaire de tendance), SNMP (IF-MIB, LLDP-MIB, SNMPv3 authPriv), calculs statistiques appliqués — score MOS E-model G.107 pour la VoIP, coefficient de variation pour le beaconing.
- **Développement backend Python/Flask et sécurisation d'une application exposée** : en-têtes de sécurité, gestion des secrets (`.env`, jamais commités), vérification TLS, décorateurs d'authentification sur les routes sensibles, rate limiting sur les actions de blocage (`MAX_BLOCKS_PER_HOUR`).
- **Scripting d'automatisation et intégration d'API tierces** : classification applicative sur 425 ports et 100+ vendors, intégration ServiceNow (rôle `itil`, table `incident`) et JIRA (API token Atlassian, format ADF), workflows n8n avec anti-doublon TTL et parsing JSON en JavaScript.

**Compétences transverses :**

- **Conduite de projet en méthode itérative avec livraisons testables** : v1 puis 7 phases v2, chacune démontrable indépendamment.
- **Audit de code et priorisation de correctifs selon une grille de criticité P0 à P3** : 25 anomalies traitées, 11 corrigées en priorité.
- **Pilotage d'agents IA en développement parallèle** avec responsabilité de validation humaine systématique — cadrage des tâches, relecture critique, fiabilisation du processus de fusion.
- **Rédaction de documentation technique multi-publics** : README orienté utilisateur, guides de déploiement Proxmox/ESXi avec 10 erreurs fréquentes documentées, mémoire académique, présent support.

---

## 13. Bilan chiffré

| Indicateur | Valeur |
|---|---|
| Services Docker orchestrés | **14** |
| Dashboards Grafana provisionnés | **13** |
| Pages de portail web Flask | **9** |
| Phases livrées en v2 | **7** |
| Ports applicatifs classifiés | **425** |
| Vendors réseau reconnus (OUI) | **100+** |
| Workflows n8n opérationnels | **5** (alertes Teams, auto-tickets, rapport hebdomadaire, escalade intelligente, sync ITSM) |
| Règles IDS custom (Snort + Suricata) | **17 + 7 = 24**, mappées MITRE ATT&CK |
| Référentiels de conformité couverts | **4** (NIS2, NIST CSF 2.0, ANSSI, ISO 27001) |
| Anomalies identifiées à l'audit sécurité interne | **25**, dont **11 corrigées en priorité (P0/P1)** |
| Rétention index NetFlow (ILM) | **30 jours** |
| Licence | **AGPL v3**, dépôt public GitHub |

---

## 14. Perspectives — v3

- **Déploiement physique** sur infrastructure Shuttle Proxmox VE (Xeon, 16 Go RAM), avec un véritable **port SPAN** sur switch manageable et une carte réseau de capture dédiée **Intel i350-T2** (dual port, pilote igb, af-packet natif) — passage du lab virtualisé à une capture de trafic réel.
- **Portail de gestion de VMs** piloté par l'**API Proxmox**, pour provisionner et comparer différents outils depuis une interface unique.
- **Comparaison côte à côte, en conditions réelles**, avec les solutions commerciales utilisées par Axians (Netscout nGeniusONE, Gigamon, Riverbed) — objectiver précisément où l'open-source tient la comparaison et où il ne la tient pas.
- Pistes complémentaires évoquées : corrélation cross-moteurs plus poussée, scoring de risque contextuel enrichi (au-delà des sources actuelles AbuseIPDB/ipinfo.io).

---

## 15. Conclusion

NetWatch démontre qu'il est possible de **reproduire une part significative des fonctionnalités clés d'un NPM/NDR commercial** avec des briques 100% open-source — 14 services, 13 dashboards, 9 pages de portail, une couverture partielle de 4 référentiels de conformité — tout en conservant une **démarche projet rigoureuse** (itération par phases, documentation systématique) et une **qualité de code auditée** (25 anomalies tracées, 11 corrigées en priorité).

Au-delà du produit livré, la démarche méthodologique — itération, audit, documentation, pilotage d'agents IA en développement parallèle — constitue une compétence directement réinvestie dans mon alternance chez Axians.

---

## Questions ?

**Nicolas Malok**
`github.com/Ourslow/netwatch` — Licence AGPL v3
