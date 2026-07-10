# NetWatch et l'écosystème français de l'observabilité et de la sécurité réseau open-source : panorama, comparaison et positionnement

## TL;DR
- **Il n'existe aucun projet français strictement identique à NetWatch** (banc d'essai open-source Zeek + ELK + Grafana orienté NPM/comparaison pédagogique). Le voisin le plus proche est **SELKS / Clear NDR Community**, édité par **Stamus Networks** (société d'origine française, cofondée par le Français Éric Leblond, développeur cœur de Suricata) : même logique « stack turnkey Dockerisé + dashboards », mais orientée IDS/NDR (Suricata) et non NPM/Zeek.
- Côté **observabilité/supervision**, la France dispose de champions open-source solides — **Centreon** (open-core, lauréat de l'OW2con'24 Best Project Technology Award le 11 juin 2024), **Canopsis/Capensis** (hypervision AGPLv3), **Vigilo NMS** et **Prelude SIEM** (CS Group) — mais aucun n'adresse le cœur NPM par capture/analyse de flux (Zeek) : ils font de la supervision par métriques/SNMP ou du SIEM.
- Côté **sécurité réseau souveraine**, l'offre française est riche mais **majoritairement propriétaire** (Gatewatcher, Custocy, Sesame IT — NDR qualifiés ANSSI). NetWatch conserve donc un positionnement différenciant réel : **lab de comparaison NPM commercial vs open-source, léger, pédagogique et pré-vente** — une niche que personne n'occupe explicitement en France. Recommandation : rattacher NetWatch à l'écosystème Suricata/Stamus et aux communautés Campus Cyber / CNLL / OW2, et intégrer des briques françaises (Suricata, Scirius, Centreon) plutôt que de les concurrencer.

## Key Findings

1. **Le périmètre exact de NetWatch (NPM open-source par analyse de flux Zeek) est très peu couvert en France.** La quasi-totalité des projets français d'observabilité relèvent de la *supervision IT* (métriques, SNMP, disponibilité) ou de la *sécurité* (IDS/NDR/SIEM), pas du *Network Performance Monitoring* par métadonnées de flux à la Netscout/Gigamon.

2. **Le vrai « cousin » de NetWatch est franco-américain : SELKS/Clear NDR Community de Stamus Networks.** Même approche « stack complète Dockerisée, dashboards prêts à l'emploi, orientée découverte/formation », mais bâtie sur Suricata (IDS/IPS/NSM) et non sur Zeek, et orientée détection de menaces plutôt que performance réseau.

3. **La France est un leader mondial de l'IDS open-source via Suricata**, dont le CTO/cofondateur de l'éditeur de référence (Stamus) est français (Éric Leblond, également membre du core team Netfilter). C'est le point d'ancrage naturel de NetWatch dans l'écosystème français.

4. **Les champions français de l'observabilité sont en modèle « open-core »** (cœur libre + éditions commerciales) : Centreon (GPL), Canopsis (AGPLv3), Vigilo NMS (GPLv2), Prelude SIEM (GPLv2). Ce sont des compléments/inspirations potentiels, pas des concurrents directs de NetWatch.

5. **Les NDR souverains français (Gatewatcher AionIQ/Clear NDR, Custocy, Sesame IT Jizô) sont propriétaires mais qualifiés ANSSI** — ils incarnent la « souveraineté » sans être open-source. Ils sont l'équivalent français des outils commerciaux que NetWatch cherche à démystifier.

6. **Le cadre de souveraineté français** (visa de sécurité ANSSI = CSPN/Critères Communs/Qualification, label France Cybersecurity, SILL, doctrine « cloud au centre »/SecNumCloud, Campus Cyber, Hexatrust) valorise fortement l'origine et l'auditabilité du code — un argument que NetWatch peut mobiliser, même comme projet non certifié.

## Details

### 1. Le cadre de la « souveraineté numérique » en France

La souveraineté numérique française repose sur plusieurs dispositifs pilotés par l'**ANSSI** (Agence nationale de la sécurité des systèmes d'information, créée par décret en 2009) :

- **Le Visa de sécurité ANSSI** est un label parapluie regroupant trois délivrables : la **CSPN** (Certification de Sécurité de Premier Niveau, depuis 2008 — tests en boîte noire en temps/charge contraints, ~25-35 j/homme), les **Certifications Critères Communs** (ISO/IEC 15408, désormais sous le règlement européen **EUCC** qui a succédé à SOG-IS le 27 février 2026), et la **Qualification** à trois niveaux (Élémentaire, Standard, Renforcé). La Qualification est « la recommandation par l'État français » et inclut un audit du code source.
- **SecNumCloud** : qualification ANSSI des offres cloud, pierre angulaire de la doctrine **« cloud au centre »** qui impose aux administrations le recours à des solutions qualifiées pour les données sensibles.
- **Le label France Cybersecurity** : label de filière (gouvernance partagée avec Hexatrust) attestant l'origine française d'une solution. Prelude SIEM (CS Group) l'a obtenu dès 2015.
- **Le SILL (Socle Interministériel de Logiciels Libres)** : catalogue de référence des logiciels libres recommandés pour l'administration, maintenu par la DINUM, ~500 logiciels fin 2024, fondé sur l'article 16 de la loi pour une République numérique. **Point important vérifié : Centreon, Grafana, Elasticsearch et OpenSearch figurent au SILL ; Suricata et Zeek n'y figurent apparemment pas** (aucune fiche SILL localisée). À noter : Nagios et Shinken ont été *retirés* du SILL (Shinken en 2022 « car plus maintenu »).
- **Écosystèmes fédérateurs** : le **Campus Cyber** (La Défense, lieu totem de la cyber française), **Hexatrust** (association créée en 2014 représentant 165 membres éditeurs/intégrateurs souverains à mi-2026 après 44 adhésions en 2025, présidée par Jean-Noël de Galzain, dirigeant de Wallix, domiciliée au Campus Cyber), le **CNLL** (Union des entreprises du logiciel libre), **OW2** (consortium open-source européen basé en France, Orange/Inria/Mairie de Paris) et les pôles de compétitivité (**Systematic Paris-Region**, **Pôle d'excellence cyber** à Rennes).

**Implication pour NetWatch :** un projet open-source à code auditable coche la case « transparence/souveraineté » prisée par ce cadre, même sans certification. Mais NetWatch n'étant ni un produit commercial ni qualifiable en l'état, sa valeur « souveraine » est symbolique/pédagogique, pas réglementaire.

### 2. Panorama des solutions françaises (et proches) comparées à NetWatch

#### A. Le cousin le plus proche : Stamus Networks (SELKS / Clear NDR Community)

**Stamus Networks** — fondée en 2014 par **Éric Leblond** (Français, résidant à Escalles, CTO, core dev Suricata et Netfilter) et **Peter Manev** (d'origine bulgare). La société a une **identité franco-américaine** : entité **Stamus Networks SAS à Paris (229 rue Saint-Honoré, 75001)** et siège social **Stamus Networks, Inc. à Indianapolis (USA)**. Ses communiqués sont systématiquement datés « INDIANAPOLIS and PARIS ». C'est donc une société **d'origine française désormais siégée aux États-Unis** (~70 % de ses clients restent européens).

- **SELKS** (créé en 2014, GPLv3), rebaptisé **Clear NDR Community** en 2024-2025 (v1.0 GA avec Suricata 8.0, OpenSearch, 58 dashboards, MCP). Stack : **Suricata + Elasticsearch/OpenSearch + Kibana/dashboards + Scirius (UI de threat hunting) + Arkime + EveBox**, déployable **via Docker Compose** ou ISO Debian. Outil « turnkey », largement utilisé par « practitioners, researchers, educators, students, and hobbyists ».
- **Ressemblances avec NetWatch** : philosophie identique (stack open-source complète Dockerisée + dashboards prêts à l'emploi + scripts custom + vocation démonstration/formation) ; même socle ELK ; même esprit « montrer ce qu'on peut faire ».
- **Différences clés** : SELKS/Clear NDR est bâti sur **Suricata (IDS/IPS/NDR par signatures + ML)**, alors que NetWatch privilégie **Zeek (analyse de flux/métadonnées, orientation NPM)** ; SELKS vise la **détection de menaces en production PME**, NetWatch se veut **banc d'essai de comparaison NPM commercial vs open-source**. NetWatch v2 intègre justement Suricata 7 et Snort 3 — il *converge* donc partiellement vers le terrain de SELKS sur le volet sécurité.
- **Nature** : c'est à la fois une **inspiration** (référence de « stack turnkey »), un **concurrent partiel** (sur le volet IDS de NetWatch v2) et surtout un **complément/partenaire potentiel** (Scirius, Suricata Language Server, rulesets Stamus sont réutilisables).
- **Maturité/communauté** : très élevée. Suricata est le moteur d'IDS open-source de référence mondiale ; SELKS a 10+ ans, une forte communauté, et est même référencé par la CISA américaine.

#### B. Le projet cœur : Suricata (OISF, forte empreinte française)

**Suricata** — moteur IDS/IPS/NSM open-source (GPLv2) développé depuis 2008 par la fondation américaine **OISF**, avec une contribution française majeure via Éric Leblond/Stamus. Il tourne « à plus de 40 Gb/s sur un seul serveur ». C'est le socle des sondes souveraines françaises **qualifiées ANSSI** : **Cybels Sensor (Thales)**, **Trackwatch/AionIQ (Gatewatcher)** et **Jizô (Sesame IT)**. Selon Éric Leblond, fondateur de Stamus Networks (cité par LeMagIT), « pour respecter le cahier des charges de l'Anssi au sujet des sondes souveraines, la solution la plus simple pour y arriver était d'utiliser Suricata ».
- **Pertinence NetWatch** : brique directement intégrée en v2. C'est le pont naturel entre NetWatch et la souveraineté française.

#### C. Les champions français de l'observabilité/supervision (open-core)

| Solution | Éditeur / Pays | Licence | Périmètre | Rapport à NetWatch |
|---|---|---|---|---|
| **Centreon** | Centreon (ex-Merethis), FR (fondé 2005) | Open-core (GPL, cœur libre + éditions IT/Business/MSP) | Supervision IT/réseau, observabilité (OpenTelemetry, agent open-source 2025), DEM | **Complément/inspiration** : leader FR de l'observabilité, 1 200 clients et 250 000 utilisateurs dans 60 pays (fin 2024, croissance ~23 %), lauréat de l'**OW2con'24 Best Project Technology Award** (11 juin 2024) ; MAIS supervision par métriques/SNMP, pas de capture de flux Zeek. NetWatch pourrait exporter vers Centreon. |
| **Canopsis** | Capensis, FR (Wasquehal, depuis 2011) | AGPLv3 | Hypervision/observabilité : centralisation, corrélation, méta-alarmes, bac à alarmes | **Complément** : « première solution d'hypervision open-source au monde », agrège >100 sources. Se place *au-dessus* de la supervision : NetWatch pourrait être une source d'événements. |
| **Vigilo NMS** | CS Group, FR | GPLv2 | Supervision réseau grands comptes (autour de Nagios), métrologie, cartographie, corrélation | **Inspiration lointaine** : NMS massif (dizaines de milliers d'équipements), pensé comme alternative aux éditeurs US. Convergence annoncée avec Prelude (Unity 360). Pas d'analyse de flux. |
| **Prelude SIEM** | CS Group, FR (projet créé 1998 par Yoann Vandoorselaere) | Open-core (OSS GPLv2 + éditions SIEM/SOC) | SIEM hybride, normalisation IDMEF (RFC 4765), compatible Suricata/Snort/OSSEC | **Complément** : label France Cybersecurity 2015, OW2 Best Community Project 2016. NetWatch (via Suricata) pourrait alimenter Prelude en IDMEF. |
| **Shinken** | Jean Gabès, FR | AGPL | Supervision (réimplémentation Python de Nagios) | **Historique** : pépite FR, mais **retiré du SILL en 2022 (« plus maintenu »)**. Illustre le risque de pérennité des projets communautaires. |

À signaler également : **Alignak** (fork/successeur de Shinken), **Rudder** (Normation, FR — gestion de configuration/conformité, pas de l'observabilité réseau), et **Kunai** (outil open-source de threat hunting Linux via eBPF, équivalent Sysmon-for-Linux, écrit en Rust — mais développé au **Luxembourg** par Quentin Jerome/CIRCL, donc *pas français*, souvent cité par erreur).

#### D. Les NDR souverains français (propriétaires, non open-source)

| Solution | Éditeur / Pays | Nature | Souveraineté | Rapport à NetWatch |
|---|---|---|---|---|
| **AionIQ / Clear NDR** | Gatewatcher, FR (Paris, fondée 2015 par Jacques de La Rivière et Philippe Gillet) | NDR propriétaire (ML + analyse statique/dynamique) | Sonde Trackwatch **qualifiée ANSSI** ; seul acteur positionné « Visionary » au tout premier Gartner Magic Quadrant NDR (juin 2025) ; facilité de financement de 25 M€ accordée par la BEI (2025) | **Concurrent « souverain »** = ce que NetWatch veut démystifier. S'appuie sur Suricata. |
| **NDR Custocy** | Custocy, FR (Toulouse, spin-off IMS Networks, 2018) | NDR propriétaire IA (SaaS, « MetaLearner » multi-temporel) | « 100% Made in France », lauréat i-Nov/France 2030, LAAS-CNRS | Concurrent souverain IA. Intègre le logiciel de visibilité réseau d'Enea (suédois). |
| **Jizô NDR** | Sesame IT, FR (Paris, fondée 2017 par Audrey Amédro et Jérôme Gouy) | Sonde NDR durcie propriétaire | **Qualification ANSSI (Visa de sécurité, juin 2021, catégorie « sondes de détection »)**, cible OIV/SIIV (LPM art. 22, loi n° 2013-1168) ; l'une des 4 seules solutions NDR qualifiées ANSSI | Concurrent souverain haut de gamme (réseaux les plus sensibles). |

Ces trois éditeurs illustrent le **positionnement « souverain propriétaire »** : ils sont l'équivalent français des Netscout/Gigamon/Keysight (côté sécurité/NDR), et co-animent l'initiative **Open XDR Platform** (avec HarfangLab, Sekoia, Glimps, Pradeo, Vade) — un écosystème souverain fédéré.

#### E. Les projets internationaux de référence (pour situer NetWatch)

Non français mais incontournables dans le paysage : **Security Onion** (US), **Malcolm** (US/CISA — le plus proche conceptuellement de NetWatch : Zeek + Arkime + OpenSearch + dashboards Dockerisés), **Arkime** (US), **ntopng** (italien), **Wazuh** (SIEM/XDR, éditeur d'origine espagnole), **Zabbix** (letton), **OpenNMS** (US), **Elastic** (néerlando-américain), **Grafana/Prometheus** (américains). **Malcolm et Security Onion sont les vrais équivalents fonctionnels de NetWatch — mais aucun n'est français**, ce qui laisse un espace de différenciation « souverain » à NetWatch.

### 3. Réponse directe à la question posée

**« Existe-t-il un autre produit comme NetWatch, open-source, observabilité, de souveraineté française ? »**

- **Réponse honnête : non, pas d'équivalent exact français.** Le concept de NetWatch (banc d'essai/lab de comparaison NPM commercial vs open-source, léger, pédagogique, Zeek-centric) n'a pas d'équivalent français direct. Les projets « proches » sont soit **franco-américains et orientés IDS** (SELKS/Clear NDR de Stamus), soit **français mais orientés supervision/SIEM** (Centreon, Canopsis, Vigilo, Prelude), soit **français mais propriétaires** (Gatewatcher, Custocy, Sesame IT).
- **Les vrais équivalents fonctionnels (Malcolm, Security Onion) ne sont pas français.** C'est précisément là que réside l'espace de NetWatch.

## Recommandations

**Étape 1 — Assumer et clarifier le positionnement (immédiat).** Positionner explicitement NetWatch comme **« lab de comparaison et de formation NPM/NDR, souverain par sa transparence de code »**, distinct de : (a) SELKS/Clear NDR (production IDS), (b) Centreon/Canopsis (supervision IT), (c) Gatewatcher/Custocy (NDR propriétaire). Le tableau comparatif ci-dessus est le meilleur argument de pré-vente/positionnement : il montre où se situe chaque brique.

**Étape 2 — S'ancrer dans l'écosystème Suricata/Stamus (court terme).** Puisque NetWatch v2 intègre déjà Suricata, capitaliser sur le lien français : réutiliser **Scirius**, le **Suricata Language Server** et les **rulesets Stamus Labs** (GPLv3). Cela crédibilise NetWatch et évite de réinventer l'existant. Envisager de rejoindre la communauté Suricata/Discord et de citer SELKS comme « référence dont NetWatch s'inspire côté Zeek ».

**Étape 3 — Intégrer des briques françaises comme sorties/compléments (moyen terme).** Prototyper un connecteur d'export des événements NetWatch vers **Centreon** (supervision) et/ou **Prelude SIEM** (IDMEF) et/ou **Canopsis** (hypervision). Argument fort : NetWatch devient un **démonstrateur d'intégration souveraine bout-en-bout** (capture Zeek → détection Suricata → supervision Centreon → hypervision Canopsis).

**Étape 4 — Rattachement communautaire/institutionnel (moyen-long terme).** Présenter NetWatch dans les écosystèmes français : **OW2con** (conférence open-source, où Centreon a été primé), **Campus Cyber**, **CNLL**, meetups **monitoring-fr.org**. Objectif : visibilité, feedback, et crédibilité « souveraine ».

**Benchmarks/seuils qui changeraient la donne :**
- Si NetWatch atteignait une **communauté et une maturité de production**, il faudrait revoir le positionnement « lab » vers « outil semi-production » — et alors la comparaison directe avec SELKS/Clear NDR deviendrait frontale (défavorable, Suricata étant mieux doté). **Rester sur le créneau NPM/Zeek + pédagogie est plus défendable.**
- Si un projet français émergeait sur le créneau exact (NPM open-source Zeek-centric), il faudrait envisager convergence/contribution plutôt que concurrence.
- Si un usage client réel était visé, la question de la **pérennité/maintenance** (leçon Shinken retiré du SILL) et d'une éventuelle **qualification** deviendrait centrale — ce que NetWatch, en l'état de lab, n'adresse pas.

## Caveats

- **Distinction open-source vs souverain-propriétaire** : bien séparer les deux dans toute présentation. Suricata, SELKS/Clear NDR, Centreon (cœur), Canopsis, Vigilo, Prelude (OSS) sont réellement open-source ; Gatewatcher, Custocy, Sesame IT sont propriétaires (souverains mais fermés).
- **« Origine française » nuancée pour Stamus** : société d'origine française (SAS Paris, cofondateur français) mais désormais siégée à Indianapolis. À présenter comme « franco-américaine / d'origine française », pas comme « pure française ».
- **Kunai** est fréquemment cité comme projet français : c'est inexact — il est développé au Luxembourg (CIRCL). À ne pas mettre dans la colonne « français ».
- **Vérification SILL** : la présence/absence au SILL a été confirmée via les fiches indexées ; l'absence de Suricata et Zeek est « apparente » (non contredite mais non prouvée à 100 % faute d'avoir interrogé le JSON complet du catalogue). À noter aussi une liste distincte, celle du « marché de support interministériel » de la DINUM (qui inclut Centreon, Elasticsearch, Grafana), à ne pas confondre avec le SILL.
- **Modèle open-core** : pour Centreon, Canopsis, Vigilo, Prelude, les fonctionnalités avancées sont souvent dans les éditions commerciales ; le « libre » ne couvre pas tout le périmètre.
- **Sources marketing** : les descriptifs de Gatewatcher, Custocy, Canopsis proviennent en partie de communications d'éditeurs (superlatifs « seul au monde », « unique ») — à prendre avec recul. Les qualifications ANSSI, le positionnement Gartner et les prix OW2, en revanche, sont des faits vérifiables.
