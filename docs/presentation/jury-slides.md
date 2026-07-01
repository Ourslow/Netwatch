---
marp: true
theme: default
paginate: true
size: 16:9
---

# 🔭 NetWatch v2
### Stack d'observabilité réseau open-source multi-moteurs

**Nicolas Malok**
Analyste Observabilité NPM @ Axians / Vinci Energies
École 2600 — Promo 2024-2027 — SideQuest MVP (S2 2025-2026)

---

## Sommaire

1. Contexte & problématique
2. Objectifs pédagogiques
3. Concept & architecture
4. Démarche méthodologique
5. Réalisation (v1 → v2, 7 phases)
6. Démonstration
7. Sécurité & conformité
8. Difficultés rencontrées
9. Compétences développées
10. Bilan & perspectives

---

## 1. Contexte

- Alternant **Analyste Observabilité NPM** chez **Axians / Vinci Energies**
- Axians revend des solutions NPM/NDR commerciales : **Netscout nGeniusONE, Gigamon, Riverbed**
- Constat de terrain : ces outils sont **puissants mais coûteux** (10k–100k+ €/an) et **boîtes noires**
- École 2600 : SideQuest MVP — projet personnel évalué sur la démarche autant que le résultat

**Question de départ :** peut-on reproduire les fonctionnalités clés d'un NPM commercial avec des briques 100% open-source ?

---

## 2. Objectifs pédagogiques

| Objectif | Compétence visée |
|---|---|
| Comprendre le fonctionnement interne d'un NPM/NDR | Analyse protocolaire, métriques réseau |
| Manipuler des moteurs IDS/NSM en conditions réelles | Zeek, Snort, Suricata |
| Construire une chaîne d'observabilité complète | ELK, Prometheus, Grafana |
| Automatiser la réponse à incident | SOAR léger (n8n, autoblock) |
| Conduire un projet dans la durée avec méthode | Gestion de projet, itérations, documentation |

---

## 3. Concept NetWatch

**NDR + NPM open-source** qui fait tourner **3 moteurs d'analyse en parallèle** sur le même trafic :

```
Trafic réseau (SPAN / PCAP)
        │
    ┌───┼───┐
    ▼   ▼   ▼
  Zeek Snort Suricata     ← 3 perspectives sur le même trafic
    └───┬───┘
        ▼
    Filebeat → Elasticsearch → Grafana + Portail Flask
```

+ **volet NPM** : NetFlow/IPFIX/sFlow, SNMP, topologie, capacity planning, VoIP, SLA

---

## 4. Architecture technique

![width:1000px](../../docs/logos/zeek.webp)

- **Zeek 6.2** — analyse protocolaire (conn/dns/http/ssl/ssh, JA3/HASSH)
- **Snort 3.3.5** — IDS signatures, règles custom + MITRE ATT&CK
- **Suricata 7** — IDS/NSM, Emerging Threats Open, EVE JSON
- **Elasticsearch 8.13 + Grafana 10.4** — stockage et visualisation
- **GoFlow2 + SNMP Exporter** — brique NPM (flux, interfaces)
- **Portail Flask** — interface unifiée, IA locale (Ollama)

**14 services Docker orchestrés**

---

## 5. Démarche méthodologique

- Développement **itératif par phases** (pas de big-bang)
- v1 (mars 2026) : socle Zeek + dashboards de base — MVP fonctionnel
- v2 : montée en gamme progressive, **7 phases** livrées entre juin 2026
- Chaque phase = un **incrément testable** (nouvelle capacité de détection ou de supervision)
- Choix assumé : utiliser une **orchestration multi-agents IA** (agents-deck) pour paralléliser le développement infra / sécurité / automatisation / frontend

> Point clé pour le jury : la méthode de conduite de projet compte autant que le code produit

---

## 6. Les 7 phases de la v2

| Phase | Contenu |
|---|---|
| 1-3 | Socle 12 services, CrowdSec, n8n, graphe IOC D3.js, health-check |
| 4 | Dashboard RSSI `/exec`, score IOC composite, escalade automatisée |
| 5 | GoFlow2 (NetFlow/IPFIX/sFlow), page `/flows`, ART applicatif |
| 6 | SNMP + topologie réseau D3.js, classification applicative (425 ports) |
| 7 | Capacity planning, qualité VoIP (MOS), compliance SLA, intégration ITSM |

**Résultat : 14 services, 13 dashboards Grafana, 9 pages portail**

---

## 7. Démonstration — Dashboard opérationnel

![width:900px](../screenshots/portal-dashboard.png)

Alertes temps réel, KPIs, accès rapide aux 3 moteurs

---

## 8. Démonstration — Statut des services

![width:900px](../screenshots/portal-status.png)

Supervision temps réel des 14 services (ES, Grafana, Prometheus, AutoBlock, IA locale)

---

## 9. Démonstration — Vue exécutive & NPM

- **`/exec`** : dashboard RSSI, score de risque composite, tendance
- **`/flows`** : débit réseau, temps de réponse applicatif, santé TCP
- **`/topology`** : cartographie réseau auto-découverte (SNMP LLDP + ARP)
- **`/sla`** : taux de conformité SLA (HTTP/DNS/RTT), heures ouvrées vs non-ouvrées

*(démo live si le temps le permet)*

---

## 10. Sécurité & conformité

- Détection comportementale **RITA-lite** : beaconing C2, DNS tunneling, connexions longues
- Réponse automatique : **AutoBlock** (webhook → iptables), déclenché par Grafana
- Fingerprinting **JA3/HASSH** pour identifier des outils C2 malgré le chiffrement
- Couverture partielle de 4 référentiels : **NIS2, NIST CSF 2.0, ANSSI, ISO 27001**
- **Audit sécurité interne** mené sur le code du projet lui-même (25 bugs identifiés, 11 corrigés en priorité P0/P1)

---

## 11. Difficultés rencontrées

| Difficulté | Résolution |
|---|---|
| Build Snort 3 depuis les sources (dépendances) | Dockerfile dédié, ~15 min de build isolé |
| Perte de contenu lors des merges Git multi-agents | Diagnostic : commits à 1 parent → fiabilisation du workflow de merge |
| Champs Zeek imbriqués mal lus depuis Elasticsearch | Correction de l'accès aux champs nested (`id.orig_h`) |
| Score IOC composite jamais calculé | Bug d'appel subprocess (flag CLI inexistant) → fichier temporaire |
| Filebeat refusait de démarrer | Permissions fichier de config (`chown root`) |

---

## 12. Compétences développées

**Techniques**
- Administration Zeek/Snort/Suricata, stack ELK, Prometheus/Grafana
- Scripting Python (parsing logs, ES bulk API, SNMP, calculs MOS/predict_linear)
- Docker Compose, orchestration multi-services
- Sécurisation d'une application Flask (headers, secrets, TLS verify)

**Transverses**
- Conduite de projet en méthode itérative
- Audit de code et priorisation de correctifs (P0→P3)
- Pilotage d'agents IA en parallèle sur un projet réel
- Documentation technique et vulgarisation (ce support)

---

## 13. Bilan chiffré

- **14 services** Docker orchestrés
- **13 dashboards** Grafana
- **9 pages** de portail web
- **7 phases** livrées en v2
- **425 ports** applicatifs classifiés
- **100+ vendors** réseau reconnus (OUI)
- **25 bugs** identifiés en audit, **11 corrigés** (P0/P1 en priorité)
- Licence **AGPL v3**, dépôt public GitHub

---

## 14. Perspectives — v3

- Déploiement **physique** sur infrastructure Shuttle Proxmox (port SPAN, carte i350-T2)
- Portail de gestion de VMs (API Proxmox)
- Comparaison **côte à côte** open-source vs outils commerciaux Axians
- Ajout possible : corrélation cross-moteurs, scoring de risque contextuel enrichi

---

## Conclusion

NetWatch démontre qu'il est possible de **reproduire les fonctions clés d'un NPM/NDR commercial** avec des briques open-source, en conservant une **démarche projet rigoureuse** et une **qualité de code auditée**.

Le projet a permis une montée en compétence directement réinvestie dans mon alternance chez Axians.

---

## Questions ?

**Nicolas Malok**
`github.com/Ourslow/netwatch`
