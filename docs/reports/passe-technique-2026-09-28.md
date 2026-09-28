# Passe technique — 28 septembre 2026 (v2.1, `main`)

Revue de l'ensemble de la solution avant mise en avant publique (site produit, pilote). Périmètre :
qualité de code, tests, sécurité du portail, exploitabilité, écart labo → produit. Tout ce qui est
marqué ✅ a été vérifié sur ce PC (labo WSL, 23 conteneurs) le 28/09.

## 1. État des contrôles automatiques

| Contrôle | Résultat |
|---|---|
| `ruff check portal scripts simulate-traffic.py` | ✅ All checks passed |
| `pytest` (portail + conventions, sans stack) | ✅ 158 tests verts (+ 1 ajouté ce jour, voir § 3) |
| `bash -n` sur tous les `.sh` | ✅ |
| `docker compose config` — `docker-compose.yml`, `sensors.yml`, `data.yml` | ✅ 23 / 11 / 13 services |
| CI GitHub Actions (ruff, pytest, compose, promtool, shellcheck, caddy) | ✅ verte sur les 5 derniers commits |
| `shellcheck` local | absent de la VM — couvert par la CI |

## 2. Sécurité du portail (revue de code)

| Point | Constat | Décision |
|---|---|---|
| Authentification | mot de passe unique, comparaison constant-time (`hmac.compare_digest`), refus si `PORTAL_PASSWORD` vide | OK |
| Force brute sur `/login` | **aucune limitation** — un script pouvait tester des mots de passe sans contrainte | **corrigé** (§ 3) |
| Session | cookie `HttpOnly`, `SameSite=Lax`, `Secure` via `SESSION_COOKIE_SECURE` (activé par install.sh en mode proxy) | OK |
| Redirection `next` après login | validée (même hôte, schéma http/https) | OK |
| Routes | 77 routes, toutes derrière `login_required` sauf `/login` et `/auth/check` (voulu : forward-auth Caddy) | OK |
| Sous-processus (`tshark`, scripts d'analyse) | 7 appels, tous en liste d'arguments, jamais `shell=True` ; chemin PCAP confiné à `pcap/` (`basename` + `commonpath`) | OK |
| Templates | `\| safe` uniquement après `tojson` (exec.html) ; autoescape Jinja actif | OK |
| En-têtes | `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy` | OK — pas de CSP (§ 4) |
| Services internes | ES, Prometheus, Blackbox, Kibana, ntopng liés à `127.0.0.1` ; en mode proxy, un seul port 443 et une seule session | OK |
| Secrets | générés par `install.sh`, jamais commités (`.gitignore`), `.env.example` sans valeur réelle | OK |
| Arkime | `anonymous` en labo (viewer sur `127.0.0.1`), `form` par défaut en 2-VM et derrière le proxy | OK, documenté |

## 3. Corrections faites ce jour

- **Anti-force-brute `/login`** (`portal/app.py`) : 5 échecs consécutifs depuis une même adresse →
  verrou de 60 s (HTTP 429, message clair), journalisé en WARNING. Adresse lue dans
  `X-Forwarded-For` uniquement en mode proxy (Caddy). Test :
  `test_login_locked_after_repeated_failures`.
- Site produit (`site/`) + publication GitHub Pages (`.github/workflows/pages.yml`).
- Jeu de données de démonstration reproductible (`make demo-data`, 23/09) — les captures du site et
  du deck en viennent.

## 4. Reste à faire (par ordre de valeur pour un pilote)

| Chantier | Pourquoi | Effort |
|---|---|---|
| **Activer GitHub Pages** (Settings → Pages → Source : GitHub Actions) | le workflow échoue sur `configure-pages` tant que Pages n'est pas activé — action manuelle sur le dépôt | 1 min |
| **Nom du produit** sur le site et le portail | « NetWatch » est un nom de code ; candidat retenu : NetPiquet (remplace Packhawk, trop proche du PacketHawk de NEOX Networks ; à vérifier INPI / TMview avant tout usage public) | 1 h après vérification |
| **Content-Security-Policy** | les templates embarquent des `<script>` inline ; passer par des nonces (Flask) puis `script-src 'nonce-…'` | ½ j |
| **Tags de version et images publiées** | `VERSION` = 2.1.0 mais aucun tag git ni image sur un registre : `upgrade.sh` ne peut pas cibler une version | ½ j |
| **ILM Elasticsearch documenté** pour tous les index (`zeek-*`, `suricata-*`, `snort-*`, `arkime_*`) | rétention = argument de dimensionnement et de conformité | ½ j |
| **Comptes nominatifs / rôles** | un seul compte `admin` ; attendu dès le premier pilote avec plusieurs exploitants | 2-3 j (édition Pro) |
| **Licence hors ligne signée** | prérequis de l'édition Pro, argument souveraineté (« pas de phone home ») | 2 j |
| **Télémétrie opt-in** (versions, santé) | phase 2, jamais de données réseau | 1 j |
| ~~Validation VM à blanc~~ **faite le 28/09** (`docs/validation-vm.md` § 2, 4, 5) : installation 11 min, backup 11 s, restauration complète 61 s, upgrade 13 s — **7 bugs corrigés** (`1fba6bd`, `77b6c3f`, `f315a9b`, `0e19720`) | install, HTTPS, backup/restore, upgrade validés sur Ubuntu 24.04 neuf | fait |

## 5. Mesures utiles (labo 28/09)

- Stack complète (édition IA, Ollama chargé à la demande) : 23 conteneurs, ≈ 6,4 Go de RAM sur la VM
  WSL de 7,8 Go ; `ES_HEAP=1g`. Cluster vert avec `number_of_replicas: 0`.
- Portail : 26 routes chronométrées, toutes < 1 s à froid (`/report` 0,27 s après le correctif Proxmox du 14/09).
- Données de démo : 226 k documents Zeek sur 7 jours + 15 k flux NetFlow sur 24 h en ≈ 3 min.
