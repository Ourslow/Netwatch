# NetWatch — identité visuelle

Référence unique pour le nom, le logo, les couleurs, la typographie et le ton. Le portail (`portal/static/img/`), le site (`site/assets/img/`) et le README utilisent des copies des fichiers de ce dossier : modifier ici, puis recopier (`make brand-sync`).

## Nom

- **NetWatch** s'écrit en un mot, N et W majuscules. Jamais « Net Watch », « Netwatch », « NetWatch Portal » ni « NetWatch v2 » dans l'interface : le numéro de version vient du fichier `VERSION` et s'affiche à part (`NetWatch 2.2.0`).
- Dans le code, le nom est lu depuis `portal/config.py` (`PRODUCT_NAME`, global Jinja `product`) : un changement de nom commercial se fait à un seul endroit, plus les fichiers de ce dossier.
- Signature : **Observabilité réseau et détection, sur site.** Accroche longue (site) : *Voir et protéger son réseau, sans SOC et sans budget grand compte.*

## Logo

| Fichier | Usage |
|---|---|
| `logo-mark.svg` | Symbole seul (carré arrondi, anneaux, aiguille). Barre latérale, avatar, icône d'application. Taille minimale 24 px. |
| `logo.svg` | Symbole + nom + signature, sur fond sombre. En-têtes, documents, site. |
| `logo-light.svg` | Même composition pour fond clair (rapports imprimés, présentations claires). |
| `favicon.svg` | Icône d'onglet 32 px, tracé simplifié. |

Le symbole représente une portée de guet : deux anneaux (le réseau observé, de près et de loin), une aiguille qui balaie, un point central (la sonde). Ne pas le déformer, le recolorer hors palette, ni l'accoler à un autre logo.

Espace de protection : la moitié de la hauteur du symbole sur chaque côté.

## Couleurs

| Rôle | Sombre (défaut) | Clair |
|---|---|---|
| Fond | `#0a0e16` | `#f6f8fa` |
| Surface | `#0e1420` / `#121a29` | `#ffffff` |
| Accent (cyan NetWatch) | `#22d3ee` | `#0e7490` |
| Accent vif | `#a5f3fc` | `#0891b2` |
| Accent profond | `#0e7490` | `#155e75` |
| Texte fort | `#e6f1f5` | `#0a0e16` |
| Texte atténué | `#7f97a6` | `#5b6b78` |
| Critique / Moyen / Faible | `#f85149` / `#e3b341` / `#79c0ff` | idem |

Le cyan est réservé à l'accent (liens, valeurs clés, « Watch » du nom). Les états de sévérité gardent leurs trois couleurs partout (portail, Grafana, site).

## Typographie

- **Inter** (400, 500, 600, 700) pour l'interface et le site ; **JetBrains Mono** pour les valeurs techniques (IP, ports, identifiants, code). Les deux sont vendorisées : aucune police externe.
- Titres en graisse 700, interlettrage légèrement resserré (−0.01 em). Chiffres clés en Inter 600 avec `font-variant-numeric: tabular-nums`.

## Ton

- Français, vouvoiement, phrases courtes, pas de superlatifs. On dit ce que le produit fait et ce qu'il ne fait pas (pas de qualification ANSSI, pas de 40 Gb/s).
- Jamais de nom d'employeur, d'école, de client ni d'éditeur nommé dans le produit et sur le site ; les comparaisons publiques se font par famille de solutions (`docs/comparatif-editeurs.md` porte la matrice nommée, à usage documentaire).
- Vocabulaire fixé : *sonde* (pas « appliance »), *portail* (pas « dashboard » pour l'ensemble), *édition Community / Pro*, *flux*, *temps de réponse applicatif (ART)*, *hostgroup*.

## Changement de nom

Quand le nom commercial sera vérifié (INPI, TMview, domaines) : `PRODUCT_NAME` dans `portal/config.py`, les quatre SVG de ce dossier, `site/index.html` (titre, textes), `README.md`, puis `make brand-sync`. Les identifiants techniques (`netwatch-*` pour les conteneurs, index, images) peuvent rester : ce sont des noms internes.
