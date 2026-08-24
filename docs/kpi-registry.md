# NetWatch — Registre des KPIs (figés vs configurables)

Point ouvert en réunion du 2026-07-10 ("KPIs figés à définir, lesquels
remontent systématiquement vs configurables"), jamais formalisé jusqu'ici.
Ce document propose une première structuration, basée sur ce qui est déjà
implémenté dans le portail (`portal/netwatch/es_client.py`), à valider avec
l'équipe avant le point du 10 septembre.

## KPIs figés — toujours actifs, quel que soit le client

Ceux-là ont du sens en toute circonstance, ils constituent le socle commun
présenté sur `/exec` (dashboard exécutif).

| KPI | Source | Où c'est déjà implémenté |
|---|---|---|
| Alertes 24h (total + répartition critique/high/medium) | Suricata + Snort | `es_client.get_exec_stats()` |
| Nombre de règles uniques déclenchées | Suricata + Snort | `es_client.get_exec_stats()` |
| Top IPs sources d'alertes | Suricata + Snort | `es_client.get_exec_stats()` |
| Score de risque IOC composite (0-100) | `ioc-score.py` | `/api/ioc-scores` |
| Conformité SLA (HTTP/DNS/RTT, p95, 7j) | Zeek | `es_client.get_sla_stats()` |
| Délai avant saturation par interface (rouge/orange/vert) | Prometheus | dashboard Grafana "capacity planning" |
| Disponibilité des services NetWatch eux-mêmes (uptime) | health check interne | `/exec` |

## KPIs configurables — à activer/adapter selon le client

Ceux-là dépendent du contexte métier du client. La flexibilité Grafana déjà
confirmée en réunion (capteur sur mesure, ex. suivi d'une requête SQL
précise) est le bon mécanisme pour ça — pas besoin de développement portail
dédié, juste un dashboard Grafana par client/contexte.

| KPI | Pertinent si... | Comment l'activer |
|---|---|---|
| Qualité VoIP (score MOS) | client avec téléphonie IP | dashboard Grafana dédié (déjà existant, à activer) |
| Suivi applicatif précis (requête SQL, endpoint API...) | besoin métier spécifique | capteur Grafana custom (confirmé faisable en réunion) |
| Seuils de saturation personnalisés | tolérance réseau différente du défaut | paramètre à exposer (actuellement seuils fixes 7j/30j) |
| Dashboards NetFlow par catégorie métier | selon les applications du client | filtre `/flows` déjà configurable par port/catégorie |

## Prochaine étape pour vraiment "mettre en place" ce registre

Actuellement cette distinction est **implicite** (dispersée dans le code,
jamais documentée). Pour que ce soit réellement piloté plutôt que subi :

1. Valider ce découpage avec l'équipe (support de ce document pour le point
   du 10 septembre).
2. Une fois validé, formaliser dans un fichier de config unique
   (`portal/config.py` ou un `kpis.yaml` dédié) plutôt que de laisser la
   distinction dispersée dans `es_client.py` — permettrait d'activer/
   désactiver un KPI configurable par déploiement sans toucher au code.
3. Documenter dans le README quels KPIs sont garantis "out of the box" vs
   lesquels demandent une config Grafana par client — utile pour un futur
   argumentaire commercial/avant-vente (« voici ce que vous avez dès le
   branchement, voici ce qu'on peut adapter »).
