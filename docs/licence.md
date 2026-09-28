# Licence hors ligne — édition Pro

NetWatch se vend en deux éditions : **Community** (AGPL v3, ce dépôt, complète pour une sonde utile) et **Pro** (abonnement par sonde : assistant IA, rapports PDF planifiables, conformité, intégration ITSM, comptes et rôles, support). La licence Pro est un fichier signé, vérifié **sans réseau** : la sonde n'appelle jamais l'éditeur, aucune télémétrie ne sort.

## Format

Une licence tient sur une ligne :

```
NW1.<kid>.<charge utile base64url>.<signature base64url>
```

- `kid` : identifiant de la clé de signature (`2026-09`), pour faire tourner les clés sans invalider l'existant.
- Charge utile (JSON) : `id`, `customer`, `edition` (`pro`), `sensors`, `issued`, `expires` (AAAA-MM-JJ), `features` (liste vide = toutes), `notes`.
- Signature Ed25519 de la charge utile par la clé privée de l'éditeur. Le portail n'embarque que les clés publiques (`portal/netwatch/license.py`, `PUBLIC_KEYS`).

## Côté client

1. Page **Licence** du portail (administrateurs) : coller la licence, *Vérifier et installer*. Elle est enregistrée dans `portal/data/license.key` (sauvegardée par `make backup`). Alternative sans interface : `LICENSE_KEY=NW1…` dans `.env` puis redémarrage du portail ; le fichier a priorité sur la variable.
2. États : **valide** → **tolérance** (30 jours après l'expiration, tout fonctionne, bandeau d'avertissement) → **expirée** (édition Community). Sans licence : Community.
3. Bridage : `LICENSE_ENFORCE=false` par défaut. Tant que ce réglage est faux, la licence est seulement affichée (page Licence, page Statut) et aucune fonction n'est bloquée. Avec `LICENSE_ENFORCE=true`, les fonctions Pro hors licence répondent 402 (page ou JSON) avec un message explicite.
4. `make license-status` affiche l'état en une ligne.

Fonctions et clés : `ia`, `reports`, `compliance`, `itsm`, `rbac`, `support`. Une licence sans `features` couvre tout.

## Côté éditeur

L'outil `scripts/license/netwatch-license.py` (dépend de `cryptography`) :

```bash
# Une fois : paire de clés, hors du dépôt (private/ est ignoré par git)
python3 scripts/license/netwatch-license.py keygen --out private/license-signing
#   → private/license-signing/private.pem (0600, ne jamais diffuser)
#   → clé publique à copier dans portal/netwatch/license.py : PUBLIC_KEYS["2026-09"]

# À chaque client
python3 scripts/license/netwatch-license.py issue --key private/license-signing/private.pem --kid 2026-09 \
  --customer "PME Exemple" --sensors 2 --expires 2027-09-28 --features ia,reports,compliance

# Lire une licence
python3 scripts/license/netwatch-license.py inspect "NW1…"
```

Renouvellement : émettre une nouvelle licence avec une nouvelle date et la transmettre au client avant l'échéance. Révocation : il n'y a pas de liste de révocation (fonctionnement hors ligne) ; la date d'expiration est le seul levier, d'où des durées d'un an au plus.

Rotation de clé : `keygen` dans un nouveau dossier, ajouter la clé publique sous un nouveau `kid`, émettre les nouvelles licences avec ce `kid` ; l'ancienne clé publique reste dans `PUBLIC_KEYS` jusqu'à l'expiration de la dernière licence qu'elle a signée.

## Sauvegarde et sécurité

- La clé privée est le seul secret : sauvegarde chiffrée hors ligne, jamais dans le dépôt, jamais sur une sonde.
- Perdre la clé privée n'invalide pas les licences déjà émises ; il faut une nouvelle paire pour les suivantes.
- Le mécanisme empêche l'usage d'une licence forgée, pas la modification du code d'une édition AGPL : c'est le contrat et le support qui portent la valeur de l'édition Pro, pas la protection technique.
