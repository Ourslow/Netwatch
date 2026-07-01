---
marp: true
theme: default
paginate: true
size: 16:9
---

# 🔭 NetWatch
### Un démonstrateur NPM/NDR open-source au service des équipes Axians

**Nicolas Malok** — Alternant Observabilité NPM
Axians / Vinci Energies

---

## En une phrase

**NetWatch n'est pas un concurrent de nos solutions commerciales.**
C'est un outil interne pour **comprendre, démontrer et qualifier** avant de vendre du Netscout, du Gigamon ou du Riverbed.

---

## Le constat métier

- Nos clients découvrent souvent Netscout/Gigamon/Riverbed **sans comprendre ce qu'il y a dedans**
- Qualifier un besoin NPM chez un prospect nécessite parfois un **PoC coûteux** en licence
- Nos équipes juniors montent en compétence NPM **sur des outils propriétaires fermés**, donc lentement
- Aucun labo interne pour **tester une signature de détection avant un déploiement client**

---

## La proposition NetWatch

Un labo réseau **100% open-source, gratuit, rejouable** qui reproduit les fonctions clés d'un NPM/NDR commercial :

- Analyse protocolaire, IDS, détection comportementale
- **Flux réseau (NetFlow/IPFIX/sFlow), SNMP, topologie**
- **Capacity planning, qualité VoIP (MOS), conformité SLA**
- Portail web unifié avec IA locale d'aide à la décision

**Déployable en moins de 30 minutes sur une VM.**

---

## 3 cas d'usage concrets pour Axians

| Cas d'usage | Bénéfice |
|---|---|
| **Formation interne** | Onboarding NPM pour juniors sur un outil transparent, code source ouvert |
| **Avant-vente / PoC rapide** | Démonstrateur low-cost pour qualifier un besoin client avant d'engager une licence commerciale |
| **Labo de validation** | Tester des scénarios de détection, des seuils, des règles avant un déploiement en prod client |

---

## Ce que NetWatch couvre déjà (aperçu NPM)

| Fonctionnalité | Équivalent commercial |
|---|---|
| Flux NetFlow/IPFIX/sFlow (GoFlow2) | Netscout nGeniusONE, Gigamon |
| Supervision SNMP interfaces | Netscout, SolarWinds NPM |
| Topologie réseau auto-découverte | Riverbed NetIM, SolarWinds NTM |
| Capacity planning (prévision saturation) | Netscout, PRTG, ManageEngine |
| Qualité VoIP (score MOS) | Netscout InfiniStreamNG, Empirix |
| Conformité SLA (HTTP/DNS/RTT) | Netscout nGeniusONE, Riverbed |

---

## Démonstration

- **`/exec`** — vue synthétique pour un décideur : score de risque, tendance
- **`/flows`** — débit réseau, santé TCP, top applications
- **`/topology`** — carte réseau auto-générée
- **`/sla`** — taux de conformité 7 jours, heures ouvrées vs non ouvrées

*(démo live)*

---

## Ce que NetWatch ne remplace pas

- Support éditeur, SLA contractuel, garantie de disponibilité
- Scalabilité multi-sites / multi-Tbps validée en production
- Écosystème d'intégrations tierces mature
- Certifications et conformité réglementaire du produit lui-même

→ **NetWatch est un outil de compréhension et de démonstration, pas un produit à vendre au client final.**

---

## Ce que ça apporte concrètement à Axians

- Un **support de formation** réutilisable pour les nouveaux analystes
- Un **argument différenciant en avant-vente** : "on comprend ce qu'on vous vend"
- Une **base de test** pour valider des scénarios de détection avant client
- Une **vitrine de compétence interne** en observabilité réseau, portable en interne

**Coût : nul (open-source, AGPL v3). Investissement : le temps de montée en compétence, déjà réalisé.**

---

## Prochaines étapes proposées

1. Présentation à l'équipe observabilité pour retour d'usage
2. Test en labo sur une infrastructure Axians (Proxmox physique, port SPAN)
3. Évaluation comme support de formation interne
4. Décision : élargir l'usage en avant-vente sur des dossiers ciblés

---

## Questions ?

**Nicolas Malok**
`github.com/Ourslow/netwatch`
