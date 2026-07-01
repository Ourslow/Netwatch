# NetWatch v2 — Mémoire de projet SideQuest MVP

**Auteur :** Nicolas Malok
**Formation :** École 2600 — Promotion 2024-2027
**Contexte :** Alternance Analyste Observabilité NPM @ Axians / Vinci Energies
**Période :** S2 2025-2026
**Dépôt :** https://github.com/Ourslow/netwatch (licence AGPL v3)

---

## 1. Résumé

NetWatch est une stack d'observabilité réseau open-source qui reproduit les fonctionnalités clés d'un outil NPM/NDR commercial (type Netscout nGeniusONE) en s'appuyant exclusivement sur des briques open-source : Zeek, Snort, Suricata, la stack ELK, Prometheus/Grafana, GoFlow2 et un ensemble de scripts d'automatisation Python. Le projet a été développé en deux versions majeures (v1 puis v2 en sept phases incrémentales) et intègre à la fois un volet sécurité (détection d'intrusion, threat intelligence, réponse automatique) et un volet supervision de performance réseau (flux, topologie, capacité, qualité VoIP, conformité SLA).

## 2. Introduction et contexte

Dans le cadre de mon alternance chez Axians, filiale de Vinci Energies spécialisée notamment dans le déploiement et l'intégration de solutions NPM (Network Performance Monitoring) commerciales telles que Netscout nGeniusONE, Gigamon et Riverbed, j'ai été amené à constater un écart important entre le coût de ces solutions (de l'ordre de 10 000 à plus de 100 000 € par an selon le périmètre) et la compréhension réelle qu'ont souvent les équipes de ce qui se passe "sous le capot".

Ce constat a motivé le choix de mon SideQuest MVP : construire, comprendre et documenter un équivalent open-source, afin de :
- Développer une expertise technique fine sur les mécanismes internes d'un NPM/NDR ;
- Disposer d'un outil pédagogique réutilisable en contexte professionnel ;
- Explorer les limites réelles de l'open-source face au commercial, de façon objective.

## 3. Problématique et objectifs

**Problématique retenue :** Est-il possible de reproduire, avec des briques 100% open-source, les fonctionnalités clés d'un outil NPM commercial, en conservant une qualité de service et une couverture fonctionnelle crédibles ?

**Objectifs pédagogiques :**
1. Comprendre en profondeur le fonctionnement d'un pipeline NDR (capture → analyse → détection → réponse).
2. Manipuler des moteurs de détection réels en conditions représentatives (Zeek, Snort, Suricata).
3. Construire une chaîne d'observabilité complète et opérationnelle (ingestion, stockage, visualisation).
4. Automatiser la réponse à incident et l'escalade.
5. Conduire un projet dans la durée avec une méthodologie itérative et une documentation exploitable.

## 4. État de l'art — comparaison avec l'existant commercial

| Fonctionnalité | NetWatch v2 | Solutions commerciales de référence |
|---|---|---|
| Capture et analyse réseau | Zeek (analyse protocolaire) | Corelight, nGenius Probe |
| Détection par signatures | Snort 3 + Suricata 7 (ET Open) | Suricata OEM, Snort Enterprise |
| Fingerprinting TLS/SSH | JA3, HASSH, JA3S (Zeek) | DPI natif (ExtraHop, Corelight) |
| Détection comportementale | RITA-lite (beaconing, DNS tunneling) | Darktrace AI, ExtraHop Reveal(x) |
| Réponse automatique | AutoBlock → iptables | Cisco Stealthwatch + NAC, Palo Alto XSOAR |
| Analyse NetFlow/IPFIX/sFlow | GoFlow2 | Netscout nGeniusONE, Gigamon |
| Supervision SNMP | SNMP Exporter + IF-MIB | Netscout, SolarWinds NPM |
| Topologie réseau | LLDP-MIB + ARP Zeek → D3.js | Riverbed NetIM, SolarWinds NTM |
| Capacity planning | Prometheus `predict_linear` | Netscout, PRTG |
| Qualité VoIP | MOS E-model G.107 (Zeek) | Netscout InfiniStreamNG, Empirix |
| Conformité SLA | Percentiles Elasticsearch p95 | Netscout nGeniusONE, Riverbed |
| Coût | Gratuit | 10 000 – 100 000+ €/an |

Cette comparaison a guidé la priorisation fonctionnelle des phases 5 à 7 de la v2, orientées explicitement vers la reproduction de capacités NPM (et non plus seulement NDR/sécurité).

## 5. Méthodologie et démarche projet

Le projet a été conduit selon une logique **itérative et incrémentale**, avec des livraisons testables à chaque étape plutôt qu'un développement monolithique.

### 5.1 v1 (mars 2026)
Socle minimal fonctionnel : 4 services Docker (Zeek, Filebeat, Elasticsearch, Grafana), 4 dashboards, scripts Zeek custom (détection de scan de ports, entropie DNS), simulateur de trafic.

### 5.2 v2 — sept phases (juin 2026)
- **Phases 1-3** : passage à 12 services (ajout Snort, Suricata, Prometheus, beacon-detect, autoblock, CrowdSec, n8n), graphe IOC interactif, health-check consolidé.
- **Phase 4** : dashboard exécutif `/exec`, score IOC composite multi-sources, escalade automatisée via n8n.
- **Phase 5** : intégration GoFlow2 (NetFlow/IPFIX/sFlow), page `/flows`, temps de réponse applicatif.
- **Phase 6** : SNMP Exporter, topologie réseau auto-découverte (D3.js), classification applicative (425 ports).
- **Phase 7** : capacity planning, qualité VoIP (score MOS), conformité SLA, intégration ITSM (ServiceNow/JIRA).

### 5.3 Orchestration multi-agents IA

Un choix méthodologique assumé a été l'utilisation d'une orchestration multi-agents IA (outil interne *agents-deck*) pour paralléliser le développement selon quatre domaines : infrastructure, sécurité, automatisation, frontend — chacun sur un *worktree* Git dédié avec une branche active.

Ce choix a permis d'avancer sur plusieurs fronts fonctionnels simultanément, mais a nécessité de conserver un contrôle humain strict sur :
- La relecture de chaque livraison avant fusion ;
- La fiabilisation du processus de fusion Git (un défaut identifié où des commits de fusion à un seul parent perdaient silencieusement du contenu) ;
- Un audit de sécurité et de qualité mené a posteriori sur l'ensemble du code produit.

Cette expérience a été l'occasion de développer une compétence de pilotage d'agents IA sur un projet réel, distincte de la compétence de codage pur : cadrage des tâches, relecture critique, validation d'intégration.

## 6. Architecture et choix techniques

```
Trafic réseau (SPAN / PCAP)
        │
    ┌───┼───┐
    ▼   ▼   ▼
  Zeek Snort Suricata        ← 3 moteurs, même trafic
    └───┬───┘
        ▼
    Filebeat 8.13             ← collecte unifiée
        ▼
 Elasticsearch 8.13           ← zeek-* / snort-* / suricata-* / netflow-*
        ▼
 Grafana 10.4 + Portail Flask ← visualisation, IA locale, PDF
```

En complément du pipeline sécurité, un second pipeline NPM a été ajouté à partir de la phase 5 : GoFlow2 (collecte NetFlow/IPFIX/sFlow) et SNMP Exporter (supervision d'interfaces IF-MIB), tous deux alimentant Elasticsearch et Prometheus respectivement.

**Choix techniques notables et justification :**
- **Zeek plutôt que tcpdump/Wireshark en frontal** : logs structurés JSON directement exploitables par Elasticsearch, sans étape de parsing intermédiaire fragile.
- **Trois moteurs IDS en parallèle** plutôt qu'un seul : permet une comparaison de couverture et une redondance de détection, condition nécessaire pour objectiver les forces/faiblesses de chaque approche (signatures vs comportemental vs protocolaire).
- **Elasticsearch + Grafana** plutôt qu'un SIEM commercial : coût nul, écosystème mature, mais nécessite un travail de modélisation d'index et de templates plus important qu'un outil clé en main.
- **Score composite IOC** plutôt qu'une seule source de réputation : réduit les faux positifs/négatifs liés à la dépendance à un unique fournisseur de threat intelligence.

## 7. Réalisation détaillée

Le détail complet des livrables par phase, avec les fichiers et scripts concernés, est disponible dans le `README.md` du dépôt (sections "Fonctionnalités", "Structure du projet", "Roadmap"). Les éléments les plus significatifs :

- **14 services Docker** orchestrés via Docker Compose.
- **13 dashboards Grafana** provisionnés automatiquement (réseau, DNS, HTTP/TLS, alertes par moteur, corrélation multi-moteurs, santé VM, top talkers, JA3/HASSH, beacon detector, SNMP interfaces, capacity planning).
- **9 pages de portail Flask** (`/dashboard`, `/exec`, `/flows`, `/graph`, `/topology`, `/sla`, `/report`, `/audit`, `/agents`) offrant une interface unifiée par profil d'utilisateur (analyste, RSSI, direction).
- **Scripts d'automatisation Python** : classification applicative (425 ports mappés), découverte topologique SNMP/ARP, calcul de score MOS, sync ITSM, création de tickets, escalade d'alertes.

## 8. Résultats et tests

Le projet a été validé par :
- Un simulateur de trafic (`simulate-traffic.py`) injectant des scénarios réalistes incluant des attaques (scan de ports, DGA, exfiltration, beaconing).
- Un script de rejeu PCAP (`replay-pcap.sh`) sur les trois moteurs simultanément.
- Un health-check consolidé (`make health`) vérifiant l'état des 14 services avec code de sortie exploitable en CI.
- Un audit de sécurité et de qualité du code mené volontairement sur l'ensemble du projet, ayant permis d'identifier 25 anomalies classées par criticité (P0 à P3), dont 11 corrigées en priorité (voir section 9).

## 9. Difficultés rencontrées et solutions apportées

| Difficulté | Analyse | Solution |
|---|---|---|
| Build Snort 3 échouant de façon intermittente | Compilation depuis les sources, dépendances système fragiles (libdaq, tcmalloc) | Dockerfile dédié isolant totalement la chaîne de compilation |
| Perte silencieuse de contenu lors des fusions Git multi-agents | Commits de fusion réduits à un seul parent lorsque `MERGE_HEAD` était perdu avant le commit de résolution de conflit | Fiabilisation du processus : résolution de conflit et commit effectués avant toute autre opération Git, garantissant un commit à deux parents |
| Score de risque IOC composite systématiquement nul | Appel à un script externe via un flag de ligne de commande inexistant, erreur silencieuse en sortie de subprocess | Remplacement par un fichier temporaire de sortie, avec lecture explicite du code de retour |
| Détection de beaconing C2 ne remontant aucune IP | Lecture de champs Elasticsearch imbriqués (`id.orig_h`) comme s'ils étaient des clés à plat | Correction de l'accès aux champs nested |
| Route d'administration `/health` exposée sans authentification | Oubli de décorateur d'authentification lors de l'ajout de la route | Ajout du contrôle d'authentification, identifié lors de l'audit sécurité |
| Tableau de bord agents-deck affichant un état obsolète | Le tableau de bord lit les fichiers d'état depuis le dépôt principal, pas depuis les worktrees d'agents | Synchronisation systématique des fichiers d'état vers le dépôt principal après chaque fusion |

## 10. Compétences mobilisées et acquises

**Compétences techniques :**
- Administration et configuration de moteurs IDS/NSM (Zeek, Snort, Suricata) en environnement conteneurisé.
- Modélisation et exploitation d'une stack ELK (index, pipelines d'ingestion GeoIP, requêtes d'agrégation).
- Développement de services de supervision (Prometheus, SNMP, recording rules, `predict_linear`).
- Développement backend Python/Flask, sécurisation d'une application web exposée (en-têtes de sécurité, gestion des secrets, vérification TLS).
- Scripting d'automatisation (classification réseau, calculs statistiques appliqués à la téléphonie IP, intégration API tierces ServiceNow/JIRA).

**Compétences transverses :**
- Conduite de projet en méthode itérative avec livraisons testables.
- Audit de code et priorisation de correctifs selon une grille de criticité.
- Pilotage d'agents IA en développement parallèle, avec responsabilité de validation humaine systématique.
- Rédaction de documentation technique multi-publics (README, guides de déploiement, présent mémoire).

## 11. Bilan et perspectives

Le projet répond à la problématique initiale : il est possible de reproduire une part significative des fonctionnalités clés d'un NPM/NDR commercial avec des briques open-source, avec un niveau de maturité fonctionnelle crédible, bien que la maturité opérationnelle (fiabilité en production, support, à l'échelle) reste évidemment en retrait des solutions commerciales établies.

**Perspectives (v3) :**
- Déploiement physique sur infrastructure Shuttle Proxmox avec port SPAN et carte réseau dédiée (Intel i350-T2).
- Portail de gestion de VMs via l'API Proxmox.
- Comparaison côte à côte, en conditions réelles, avec les solutions commerciales utilisées par Axians (Netscout, Gigamon, Riverbed).

## 12. Conclusion

NetWatch a constitué un cadre d'apprentissage exigeant et représentatif des enjeux réels d'un poste d'analyste observabilité réseau. Au-delà du produit livré, la démarche méthodologique — itération, audit, documentation, pilotage d'agents IA — constitue une compétence directement réinvestie dans mon alternance chez Axians.

## Annexe — Glossaire

- **NDR** : Network Detection & Response
- **NPM** : Network Performance Monitoring
- **IDS/NSM** : Intrusion Detection System / Network Security Monitoring
- **JA3/HASSH** : empreintes de handshake TLS/SSH utilisées pour l'identification d'outils malgré le chiffrement
- **MOS (E-model G.107)** : Mean Opinion Score, méthode standardisée d'estimation de la qualité perçue d'un appel VoIP
- **IOC** : Indicator of Compromise
- **SLA** : Service Level Agreement
