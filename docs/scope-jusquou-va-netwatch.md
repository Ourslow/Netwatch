# Jusqu'où va NetWatch ? — Doc de scope

Question posée par Jerem en réunion du 2026-07-10 : à quel moment doit-on
basculer sur un autre outil (commercial) plutôt que de pousser NetWatch
plus loin ? Ce document fixe une ligne claire — à challenger au point du
10 septembre.

## Ce que NetWatch fait bien aujourd'hui (à garder, à renforcer)

- **Détection multi-moteurs sur le même trafic** (Zeek + Snort + Suricata)
  — corrélation, pas juste de la détection isolée.
- **Capteurs/dashboards sur mesure** (Grafana) — plus flexible que les
  éditeurs figés sur ce point précis, confirmé en réunion (exemple : suivi
  d'une requête SQL spécifique).
- **Coût nul, code auditable** — argument différenciant réel pour les
  TPE/PME et pour l'axe souveraineté.
- **Déploiement rapide sur boîtier transportable** (Shuttle) — l'angle
  "box à tout faire" qui revient le plus dans les retours de l'équipe.
- **Conformité NIS2/ISO 27001/ANSSI** — bonne couverture fonctionnelle (pas
  de certification, voir plus bas).

## Ce que NetWatch ne fera probablement jamais aussi bien qu'un éditeur (limite assumée)

- **DPI propriétaire profond** (1300+ signatures applicatives type
  Riverbed AppFlow) — hors de portée réaliste ; un mapping SNI/domaine
  enrichi couvre 70-80% des cas d'usage réels, pas 100%.
- **Scalabilité très grande échelle** — pensé pour PME/ETI, pas pour un
  grand compte avec des dizaines de milliers d'équipements (cf. Vigilo NMS
  côté français, pensé précisément pour ça).
- **Support éditeur 24/7, SLA contractuel** — NetWatch repose sur une
  personne (Nicolas) et la communauté, pas une équipe support dédiée.
- **Certifications produit formelles** (Critères Communs, Qualification
  ANSSI) — nécessiteraient des ressources et un processus que le projet
  n'a pas vocation à porter en l'état.
- **Capture matérielle très haut débit** (40+ Gb/s type sondes
  InfiniStreamNG) — dépend du matériel du Shuttle, pas une limite logicielle
  mais une limite d'infrastructure à ne pas sur-promettre.

## La ligne de bascule proposée

**NetWatch reste pertinent tant qu'on est dans un des 2 cas d'usage
validés : formation ou audit ponctuel/pré-vente.** Le basculement vers un
outil commercial (Allegro, Netscout, Riverbed, Gigamon) devient pertinent
dès qu'un des critères suivants apparaît :

1. Le client a besoin d'un **support contractuel garanti** (SLA, astreinte).
2. Le volume/débit dépasse ce que la sonde Shuttle peut absorber.
3. Le client a une **exigence de certification formelle** (pas juste de la
   couverture fonctionnelle).
4. L'usage devient de la **production continue** plutôt qu'un audit borné
   dans le temps — NetWatch n'est pas conçu (aujourd'hui) pour tourner en
   permanence chez un client sans supervision.

Dans tous ces cas, **NetWatch garde sa valeur en amont** : il sert à
qualifier le besoin avant d'engager la discussion commerciale sur l'outil
adapté — c'est exactement le rôle "avant-vente" déjà identifié.

## Ce qui reste à trancher collectivement (pas une décision unilatérale de Nicolas)

- À partir de quel volume de données/nombre d'équipements dit-on
  explicitement "ça sort du périmètre NetWatch" ?
- Un audit NetWatch peut-il durer plus de quelques jours, ou doit-il rester
  borné dans le temps par principe ?
- Si un client demande un déploiement permanent après un audit concluant,
  propose-t-on NetWatch en continu (avec les limites de support que ça
  implique) ou bascule-t-on systématiquement vers l'offre commerciale ?

**How to apply** : ce document est une proposition de cadrage, pas une
règle gravée — objectif : avoir un point de départ concret pour la
discussion du 10 septembre plutôt que de repartir d'une feuille blanche.
