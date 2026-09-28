# NetWatch face aux autres solutions — matrice par éditeur

> Document de référence, à usage documentaire et commercial interne. Établi le **28 septembre 2026** à partir de la documentation publique des éditeurs (sites, fiches produit, documentation en ligne). Aucun test comparatif n'a été mené : les cases décrivent le périmètre déclaré, pas une mesure. Les offres évoluent ; vérifier avant toute reprise dans un support externe. Sur le site public, la comparaison est faite par **famille**, sans nom d'éditeur.

## 1. Comment lire la matrice

- **NPM** : supervision de la performance réseau par les flux et les paquets — top talkers, temps de réponse applicatif (ART), santé TCP (retransmissions, zero window), SLA.
- **NDR** : détection des menaces sur le réseau — signatures IDS, comportement (beaconing, exfiltration), threat intelligence.
- **IA locale** : assistance par modèle de langage exécuté sur la sonde, sans envoi de données à un tiers.
- **Sur site** : l'analyse et le stockage restent dans le réseau du client (pas de télémétrie vers un cloud éditeur pour fonctionner).
- **Cible** : taille d'organisation visée par l'éditeur d'après son discours public.
- ● couvert · ◐ partiel ou en option · — absent ou hors périmètre · *n.d.* non documenté publiquement

## 2. Matrice

| Solution | Famille | Origine | Licence | NPM (flux/ART/SLA) | NDR (IDS + comportement) | IA locale | Sur site | Cible | Modèle tarifaire public |
|---|---|---|---|---|---|---|---|---|---|
| **NetWatch** | NPM + NDR | France | AGPL v3 (Community) + Pro | ● | ● (Zeek, Snort 3, Suricata 7, beaconing) | ● (édition IA, Ollama) | ● | PME 50-500 postes, MSP | Community gratuite ; Pro : abonnement par sonde (hypothèse 99-149 €/mois, non publié) |
| Security Onion | NSM / SIEM open source | États-Unis | Elastic License 2.0 (v2.4+) | — | ● (Zeek, Suricata, Elastic) | — | ● | SOC, équipes sécurité | Gratuit ; support et formation payants |
| Malcolm (CISA) | NSM open source | États-Unis | Apache 2.0 | ◐ (métadonnées Zeek, pas de SLA/ART) | ● (Zeek, Suricata, Arkime) | — | ● | Réseaux OT / IT, analystes | Gratuit |
| Clear NDR Community (ex-SELKS) | NDR open source | France / États-Unis | GPL v3 | — | ● (Suricata, Scirius) | — | ● | Praticiens, formation, PME | Gratuit ; éditions commerciales Stamus |
| Wazuh | SIEM / XDR open source | Espagne / États-Unis | GPL v2 | — | ◐ (centré endpoints ; IDS réseau via intégration) | — | ● (ou cloud) | Toutes tailles | Gratuit ; cloud et support payants |
| ntopng | Supervision de trafic | Italie | GPL v3 (Community) + Pro/Enterprise | ● (flux, top talkers) / ◐ ART, — SLA | ◐ (alertes comportementales) | — | ● | PME à grands comptes | Community gratuite ; licences Pro / Enterprise |
| NETSCOUT nGeniusONE | NPM commercial | États-Unis | Propriétaire | ● (référence du marché, DPI ASI) | ◐ (Omnis Cyber Intelligence, offre séparée) | — | ● (appliances) | Grands comptes, opérateurs | Sur devis |
| Riverbed (NetProfiler, AppResponse) | NPM commercial | États-Unis | Propriétaire | ● (flux + paquets, 1 300+ signatures applicatives) | ◐ (anomalies de flux) | — | ● (ou cloud Riverbed) | Grands comptes | Sur devis |
| Gigamon | Visibilité / TAP | États-Unis | Propriétaire | ◐ (métadonnées, pas de portail NPM) | ◐ (alimente d'autres outils) | — | ● | Grands comptes | Sur devis |
| Allegro Network Multimeter | NPM + sécurité commercial | Allemagne | Propriétaire | ● | ◐ | — | ● (appliance ou VM) | PME à grands comptes | Sur devis |
| Flowmon (Progress) | NPM / NDR commercial | Rép. tchèque / États-Unis | Propriétaire | ● (flux) | ● (module ADS) | — | ● | ETI, grands comptes | Sur devis |
| Darktrace | NDR IA | Royaume-Uni | Propriétaire | — | ● (IA comportementale) | — (modèles éditeur) | ◐ (sonde sur site, analyse et console cloud) | ETI, grands comptes | Sur devis |
| Vectra AI | NDR IA | États-Unis | Propriétaire | — | ● | — | ◐ (capteurs sur site, plateforme cloud) | Grands comptes | Sur devis |
| ExtraHop Reveal(x) | NDR (+ NPM historique) | États-Unis | Propriétaire | ◐ | ● | — | ◐ (360 : cloud ; EDA : sur site) | Grands comptes | Sur devis |
| Gatewatcher AionIQ | NDR souverain | France | Propriétaire | — | ● (qualifié ANSSI) | ◐ | ● | Grands comptes, OIV | Sur devis |
| Sesame IT Jizô | NDR souverain | France | Propriétaire | — | ● (qualifié ANSSI) | — | ● | OIV, réseaux sensibles | Sur devis |
| Custocy | NDR souverain IA | France | Propriétaire | — | ● | ◐ | ◐ (SaaS) | ETI | Sur devis |
| Centreon | Supervision métriques | France | Open-core (GPL + éditions) | ◐ (SNMP, disponibilité) | — | — | ● | Toutes tailles, MSP | Communauté gratuite ; éditions IT / Business / MSP |
| Zabbix | Supervision métriques | Lettonie | AGPL v3 | ◐ (SNMP) | — | — | ● | Toutes tailles | Gratuit ; support payant |
| PRTG (Paessler) | Supervision métriques | Allemagne | Propriétaire | ◐ (SNMP, flux en option) | — | — | ● | PME, ETI | Licence par capteurs, tarifs publiés |

## 3. Ce qui distingue NetWatch

1. **NPM et NDR dans la même sonde.** Les suites open source (Security Onion, Malcolm, Clear NDR) couvrent la sécurité ; les NPM commerciaux couvrent la performance. NetWatch fait les deux sur le même trafic, avec un portail unique et un pivot par adresse IP.
2. **Rien ne sort du réseau.** Pas de télémétrie éditeur, IA exécutée sur la sonde. Les NDR cloud analysent ailleurs ; NetWatch analyse chez le client.
3. **Un prix et un périmètre pour les PME et les MSP.** Les NPM et NDR commerciaux visent les grands comptes (appliances, devis, intégrateur). NetWatch s'installe en une commande sur une VM.
4. **Code ouvert, en français.** Documentation, portail et support en français ; licence AGPL v3 sur l'édition Community.

## 4. Ce que NetWatch ne fait pas (à dire au client)

- Pas de DPI propriétaire à plusieurs milliers de signatures : le dictionnaire applicatif repose sur SNI, domaines et ports (voir `docs/reports/gaps-vs-editeurs-commerciaux.md`).
- Pas de capture à plusieurs dizaines de Gb/s ni d'appliance matérielle.
- Pas de qualification ANSSI ni de certification ; pas de SLA contractuel 24/7 sur l'édition Community.
- Pas de console multi-sites hébergée en phase 1 (control plane envisagé en phase 2).

## 5. Méthode, sources et précautions

- Sources : documentation et pages produit publiques des éditeurs à la date du document — [securityonion.net](https://securityonion.net/), [github.com/cisa/malcolm](https://github.com/cisa/malcolm), [stamus-networks.com](https://www.stamus-networks.com/), [wazuh.com](https://wazuh.com/), [ntop.org](https://www.ntop.org/), [netscout.com](https://www.netscout.com/), [riverbed.com](https://www.riverbed.com/), [gigamon.com](https://www.gigamon.com/), [allegro-packets.com](https://allegro-packets.com/), [progress.com/flowmon](https://www.progress.com/flowmon), [darktrace.com](https://darktrace.com/), [vectra.ai](https://www.vectra.ai/), [extrahop.com](https://www.extrahop.com/), [gatewatcher.com](https://www.gatewatcher.com/), [sesame-it.com](https://www.sesame-it.com/), [centreon.com](https://www.centreon.com/), [zabbix.com](https://www.zabbix.com/), [paessler.com](https://www.paessler.com/prtg) ; qualifications ANSSI : catalogue des produits qualifiés sur [cyber.gouv.fr](https://cyber.gouv.fr/).
- Les colonnes « modèle tarifaire » reprennent uniquement ce que l'éditeur publie ; « sur devis » signifie qu'aucun tarif public n'a été trouvé. Aucun montant n'est avancé pour un éditeur tiers.
- Usage externe : toute comparaison publique nommant un éditeur doit rester objective, vérifiable et non trompeuse (publicité comparative, art. L.122-1 et suivants du Code de la consommation). Ce document n'est pas conçu pour être diffusé tel quel ; le site public compare par famille.
- Mise à jour : relire à chaque version majeure de NetWatch ou au plus tard tous les six mois ; dater chaque révision ici.

| Révision | Date | Changement |
|---|---|---|
| 1 | 2026-09-28 | Première version (19 solutions, 6 familles). |
