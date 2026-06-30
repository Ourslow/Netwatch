# CrowdSec — Intégration NetWatch

CrowdSec est un IPS collaboratif open-source ajouté à la stack NetWatch pour la détection comportementale et le blocage d'IPs malveillantes via une threat intelligence communautaire.

## Architecture

```
Zeek logs  ────────────────┐
Suricata eve.json  ─────── CrowdSec  ──→  cscli bouncer (iptables / firewall)
syslog  ───────────────────┘                     ↕
                                           CrowdSec Central API
                                           (threat intel communautaire)
```

## Prérequis

- Docker Compose v2+ (inclus dans la stack NetWatch)
- Volumes `netwatch_zeek-logs` et `netwatch_suricata-logs` créés par `docker compose up` depuis `/home/ourslow/code/netwatch`

## Installation

CrowdSec est intégré dans `docker-compose.yml`. Pour démarrer le service :

```bash
# Depuis le répertoire principal du projet (important pour les volumes)
cd /home/ourslow/code/netwatch
docker compose up -d crowdsec
```

## Collections installées

| Collection | Description |
|---|---|
| `crowdsecurity/linux` | Détection SSH brute-force, syslog |
| `crowdsecurity/nginx` | HTTP scan, bad user-agents, 4xx flood |
| `crowdsecurity/suricata` | Parse le format EVE JSON de Suricata |
| `crowdsecurity/sshd` | Inclus dans linux — brute-force SSH |
| `crowdsecurity/base-http-scenarios` | Scénarios HTTP génériques |

> **Note (2026-06)** : La collection `crowdsecurity/zeek` n'existe pas dans le hub officiel CrowdSec.
> Les logs Zeek (`conn.log`, `http.log`, `dns.log`, `ssl.log`) sont acquis et parsés via
> les règles syslog de `crowdsecurity/linux`. Une collection Zeek dédiée pourrait être
> disponible ultérieurement via `cscli hub update && cscli collections install crowdsecurity/zeek`.

## Sources de logs (acquis.yaml)

Fichier : `crowdsec/acquis.yaml`

| Source | Path dans le container | Format |
|---|---|---|
| Zeek conn/http/dns/ssl/weird/files | `/zeek/logs/*.log` | `zeek` |
| Suricata EVE JSON | `/var/log/suricata/eve.json` | `suricata-ecs` |
| syslog système | `/var/log/auth.log`, `/var/log/syslog` | `syslog` |

## Commandes utiles

### Vérifier l'état du service

```bash
docker compose ps crowdsec
# → netwatch-crowdsec   crowdsecurity/crowdsec:latest   Up
```

### Lister les collections actives

```bash
docker exec netwatch-crowdsec cscli collections list
```

### Lister les décisions de blocage

```bash
docker exec netwatch-crowdsec cscli decisions list
```

### Lister les alertes détectées

```bash
docker exec netwatch-crowdsec cscli alerts list
```

### Voir les métriques en temps réel

```bash
docker exec netwatch-crowdsec cscli metrics
```

### Mettre à jour les collections

```bash
docker exec netwatch-crowdsec cscli hub update
docker exec netwatch-crowdsec cscli hub upgrade
```

## Test de ban manuel

Pour valider qu'une décision de blocage fonctionne :

```bash
# Ajouter un ban test sur une IP fictive
docker exec netwatch-crowdsec cscli decisions add \
  --ip 1.2.3.4 \
  --duration 4h \
  --reason "test ban NetWatch"

# Vérifier la décision
docker exec netwatch-crowdsec cscli decisions list
# Sortie attendue :
# | ID | Source | Scope:Value |      Reason      | Action | ... | expiration |
# |----|--------|-------------|------------------|--------|-----|------------|
# | 1  | cscli  | Ip:1.2.3.4  | test ban NetWatch | ban   |     | 3h59m59s  |

# Supprimer le ban test
docker exec netwatch-crowdsec cscli decisions delete --ip 1.2.3.4
```

## Intégration d'un bouncer (blocage effectif)

CrowdSec détecte les menaces mais le blocage réel nécessite un **bouncer** :

```bash
# Installer le bouncer iptables sur l'hôte
apt-get install crowdsec-firewall-bouncer-iptables

# Configurer l'API key (depuis le container)
docker exec netwatch-crowdsec cscli bouncers add netwatch-firewall-bouncer
# → copier la clé API générée dans /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
```

> La stack NetWatch inclut déjà **autoblock** (webhook Flask → iptables). CrowdSec apporte
> une couche complémentaire avec la threat intelligence communautaire et la détection
> comportementale multi-sources (Zeek + Suricata + syslog).

## Logs et debug

```bash
# Logs du container
docker logs netwatch-crowdsec -f

# Logs CrowdSec internes
docker exec netwatch-crowdsec tail -f /var/log/crowdsec/crowdsec.log
```
