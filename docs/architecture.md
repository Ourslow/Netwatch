# Architecture NetWatch

## Pipeline de données

```
Trafic réseau / PCAP
        ↓
      Zeek
  (analyse proto)
        ↓
  conn.log / dns.log
  http.log / ssl.log
    notice.log
        ↓
    Filebeat
  (collecte & transport)
        ↓
  Elasticsearch
  (indexation zeek-*)
        ↓
    Grafana
(dashboards & alertes)
```

## Index Elasticsearch

| Index | Source | Rétention conseillée |
|-------|--------|----------------------|
| zeek-zeek-YYYY.MM.DD | conn.log, dns.log, http.log | 30 jours |
| zeek-zeek-YYYY.MM.DD | ssl.log, notice.log | 90 jours |

## Ports exposés

| Service | Port | Usage |
|---------|------|-------|
| Grafana | 3000 | Interface web |
| Elasticsearch | 9200 | API REST |
