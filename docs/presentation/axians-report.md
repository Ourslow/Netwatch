# NetWatch — Rapport de présentation Axians

**Auteur :** Nicolas Malok, alternant Analyste Observabilité NPM
**Destinataire :** Équipe observabilité réseau / hiérarchie Axians
**Objet :** Présentation d'un démonstrateur NPM/NDR open-source développé en alternance, et proposition d'usages internes

---

## Résumé exécutif

NetWatch est une stack d'observabilité réseau open-source que j'ai développée pour reproduire les fonctionnalités clés des outils NPM/NDR commerciaux que nous déployons chez nos clients (Netscout nGeniusONE, Gigamon, Riverbed). **Ce n'est pas un produit destiné à être vendu ou déployé chez un client final** : c'est un outil interne à vocation pédagogique, de démonstration et de qualification de besoin. Ce rapport présente le positionnement, la valeur ajoutée potentielle pour Axians, les fonctionnalités couvertes, et des propositions concrètes de prochaines étapes.

## 1. Contexte métier

Notre activité d'intégration de solutions NPM commerciales fait face à trois contraintes récurrentes :

1. **Coût de qualification** — évaluer précisément un besoin client en NPM nécessite souvent un PoC avec licence temporaire, engageant un budget avant même la décision d'achat.
2. **Montée en compétence lente** — les analystes juniors découvrent les mécanismes NPM/NDR directement sur des outils propriétaires fermés, ce qui ralentit la compréhension des fondamentaux (NetFlow, SNMP, IDS, scoring de qualité).
3. **Absence de labo de validation interne** — il n'existe pas aujourd'hui d'environnement interne permettant de tester une règle de détection, un seuil d'alerte ou un scénario avant un déploiement chez un client.

## 2. Positionnement de NetWatch

**NetWatch est complémentaire, pas concurrent**, à notre offre commerciale. Ce point est central et doit être maintenu dans toute communication, y compris en interne :

- Aucune garantie de support éditeur, de SLA contractuel ou de scalabilité validée en production à grande échelle.
- Aucun écosystème d'intégrations tierces comparable à un produit commercial mature.
- Vocation strictement interne : formation, avant-vente (qualification), labo de test.

## 3. Fonctionnalités couvertes (axe NPM)

| Fonctionnalité NetWatch | Équivalent commercial de référence |
|---|---|
| Collecte NetFlow / IPFIX / sFlow (GoFlow2) | Netscout nGeniusONE, Gigamon |
| Supervision SNMP des interfaces (IF-MIB) | Netscout, SolarWinds NPM |
| Topologie réseau auto-découverte (LLDP + ARP) | Riverbed NetIM, SolarWinds NTM |
| Capacity planning (projection de saturation) | Netscout, PRTG, ManageEngine |
| Score de qualité VoIP (modèle MOS E-model G.107) | Netscout InfiniStreamNG, Empirix |
| Conformité SLA (HTTP/DNS/RTT, heures ouvrées) | Netscout nGeniusONE, Riverbed |

À cela s'ajoute un volet sécurité (NDR) : trois moteurs de détection en parallèle (Zeek, Snort, Suricata), détection comportementale (beaconing C2, tunneling DNS), réponse automatique, et un portail web unifié avec assistance IA locale.

## 4. Cas d'usage proposés pour Axians

### 4.1 Formation interne
Support d'onboarding pour les nouveaux analystes observabilité : le code source étant ouvert, il est possible de montrer précisément ce qui se cache derrière chaque métrique (calcul MOS, projection de capacité, classification applicative), ce qu'un outil commercial fermé ne permet pas.

### 4.2 Avant-vente / qualification rapide
Face à un prospect hésitant, NetWatch permet de construire un démonstrateur fonctionnel gratuit pour objectiver un besoin (ex. : démonstration d'une capacité de détection de saturation d'interface, ou d'un calcul de conformité SLA) avant d'engager une licence commerciale.

### 4.3 Labo de validation technique
Test de scénarios de détection, de seuils d'alerte ou de règles avant un déploiement en environnement client, dans un environnement sans risque et sans coût de licence.

## 5. Coût et investissement

- **Licence** : nulle (AGPL v3, dépôt public).
- **Infrastructure** : une VM standard (6 vCPU / 8 Go RAM / 60 Go disque) suffit pour un environnement de démonstration complet ; déploiement en moins de 30 minutes.
- **Maintenance** : à ce jour projet personnel développé en alternance. Une adoption officielle par Axians nécessiterait de statuer sur un mode de maintenance (temps dédié, fork interne éventuel, gouvernance).

## 6. Limites à ne pas occulter

- Pas de support éditeur ni de SLA contractuel.
- Scalabilité multi-sites/multi-Tbps non validée en production.
- Écosystème d'intégrations tierces plus restreint qu'un produit commercial mature.
- Certifications produit et conformité réglementaire du logiciel lui-même non établies (contrairement aux solutions commerciales certifiées).

## 7. Prochaines étapes proposées

1. Présentation à l'équipe observabilité réseau pour recueillir un retour d'usage terrain.
2. Test en environnement labo sur infrastructure Axians (Proxmox physique avec port SPAN dédié).
3. Évaluation formelle de l'usage comme support de formation interne.
4. Décision de la hiérarchie sur un élargissement éventuel à l'avant-vente, sur un périmètre de dossiers ciblés.

## 8. Conclusion

NetWatch représente une opportunité à coût nul de renforcer la compétence interne en observabilité réseau et d'outiller certaines phases d'avant-vente, sans se substituer à nos offres commerciales. Je propose une phase d'évaluation courte avec l'équipe concernée avant toute décision d'adoption plus large.

---

**Contact :** Nicolas Malok — `github.com/Ourslow/netwatch`
