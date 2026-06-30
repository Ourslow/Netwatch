# NetFlow / IPFIX / sFlow — Configuration et intégration (T_017)

NetWatch collecte les flux réseau via **GoFlow2** et les indexe dans Elasticsearch sous le pattern `netflow-YYYY.MM.DD`.

## Architecture

```
Equipement réseau              NetWatch (VM)
(Cisco / HP / Aruba)          ┌─────────────────────────────┐
                               │                             │
   NetFlow v9 ──── UDP:2055 ──►│  goflow2 (container)        │
   IPFIX      ──── UDP:4739 ──►│  → JSON sur stdout          │
   sFlow v5   ──── UDP:6343 ──►│                             │
                               │  Filebeat (container)       │
                               │  ← lit logs Docker goflow2  │
                               │  → index netflow-YYYY.MM.DD │
                               │                             │
                               │  Elasticsearch              │
                               │  index netflow-*            │
                               └─────────────────────────────┘
```

## Démarrage rapide

```bash
# 1. Démarrer le stack (goflow2 inclus)
make start

# 2. Initialiser les templates ES et la politique ILM
make setup-netflow

# 3. Configurer l'export NetFlow sur vos équipements (voir ci-dessous)

# 4. Tester la réception (simulation Python si softflowd absent)
make netflow-test

# 5. Vérifier l'ingestion
curl "http://localhost:9200/netflow-*/_count?pretty"
```

---

## Configuration des équipements

### Cisco IOS / IOS-XE (NetFlow v9)

```
! Activer NetFlow sur l'interface WAN
interface GigabitEthernet0/0
 ip flow ingress
 ip flow egress

! Définir l'exporteur (adresse IP de la VM NetWatch)
ip flow-export version 9
ip flow-export destination <IP_NETWATCH> 2055
ip flow-export source GigabitEthernet0/0

! Paramètres du cache (timeout actif 60s, inactif 15s)
ip flow-cache timeout active 60
ip flow-cache timeout inactive 15

! Vérification
show ip flow export
show ip cache flow
```

**Note IOS-XE (Flexible NetFlow) :**

```
! Définir un flow record avec les champs minimum requis
flow record NETWATCH-RECORD
 match ipv4 source address
 match ipv4 destination address
 match transport source-port
 match transport destination-port
 match ipv4 protocol
 collect counter bytes long
 collect counter packets long
 collect timestamp sys-uptime first
 collect timestamp sys-uptime last
 collect interface input
 collect interface output
 collect routing source as
 collect routing destination as
 collect ipv4 next-hop address

! Exporter vers NetWatch
flow exporter NETWATCH-EXPORT
 destination <IP_NETWATCH>
 source GigabitEthernet0/0
 transport udp 2055
 export-protocol netflow-v9

! Appliquer sur l'interface
flow monitor NETWATCH-MONITOR
 record NETWATCH-RECORD
 exporter NETWATCH-EXPORT
 cache timeout active 60
 cache timeout inactive 15

interface GigabitEthernet0/0
 ip flow monitor NETWATCH-MONITOR input
 ip flow monitor NETWATCH-MONITOR output
```

---

### HP / Aruba ProCurve (sFlow)

Les switches HP ProCurve et Aruba utilisent **sFlow v5** (port UDP 6343).

```
! Via CLI ProCurve (2530 / 2920 / 5400R)
sflow 1 destination <IP_NETWATCH> 6343
sflow 1 sampling <INTERFACE> 512   ! 1 paquet sur 512
sflow 1 polling <INTERFACE> 30     ! polling toutes les 30s
sflow 1 enable
```

**Via interface web Aruba :**
1. Network > sFlow > Add Destination : `<IP_NETWATCH>:6343`
2. Sampling Rate : `512` (adapter selon le débit — 1024 pour 1 Gbps)
3. Polling Interval : `30`
4. Apply

**Vérification :**
```
show sflow agent
show sflow destination
show sflow sampling-polling
```

---

### Juniper (sFlow / IPFIX)

**sFlow :**
```
set protocols sflow polling-interval 30
set protocols sflow sample-rate ingress 512
set protocols sflow collector <IP_NETWATCH> udp-port 6343
set protocols sflow interfaces ge-0/0/0
```

**IPFIX (port 4739) :**
```
set services flow-monitoring version-ipfix template ipv4 flow-active-timeout 60
set services flow-monitoring version-ipfix template ipv4 flow-inactive-timeout 15
set services flow-monitoring version-ipfix template ipv4 ip-headers
set services flow-monitoring version-ipfix template ipv4 nexthop-learning

set forwarding-options sampling input rate 512
set forwarding-options sampling family inet output flow-server <IP_NETWATCH> port 4739
set forwarding-options sampling family inet output flow-server <IP_NETWATCH> version-ipfix template ipv4
```

---

## Simulation locale avec softflowd

`softflowd` capture le trafic d'une interface réseau et génère des flux NetFlow.

```bash
# Installation
sudo apt-get install softflowd    # Ubuntu/Debian
sudo yum install softflowd        # RHEL/CentOS

# Simulation depuis l'interface loopback (ou eth0)
sudo softflowd -n 127.0.0.1:2055 -v 9 -t 30 -c 100 -i lo

# Paramètres utiles :
#   -n <host>:<port>   : destination NetFlow
#   -v 9               : version (5 ou 9)
#   -t <sec>           : durée de capture
#   -c <n>             : nombre maximum de flows à exporter
#   -i <iface>         : interface à capturer

# Via make (Python fallback si softflowd absent)
make netflow-test
```

---

## Vérification dans Elasticsearch

```bash
# Indices créés
curl "http://localhost:9200/_cat/indices/netflow-*?v&s=index"

# Nombre de documents
curl "http://localhost:9200/netflow-*/_count?pretty"

# Exemple de document goflow2 (champs dans .netflow.*)
curl "http://localhost:9200/netflow-*/_search?size=1&pretty" | python3 -m json.tool | head -60

# Top 10 IP sources (bytes)
curl -s "http://localhost:9200/netflow-*/_search?pretty" -H "Content-Type: application/json" -d '{
  "size": 0,
  "aggs": {
    "top_src": {
      "terms": { "field": "netflow.src_addr", "size": 10 },
      "aggs": { "total_bytes": { "sum": { "field": "netflow.bytes" } } }
    }
  }
}'
```

---

## Champs indexés (mapping netflow-*)

| Champ             | Type      | Description                          |
|-------------------|-----------|--------------------------------------|
| `netflow.type`    | keyword   | NETFLOW_V9, IPFIX, SFLOW_5           |
| `netflow.src_addr`| ip        | IP source                            |
| `netflow.dst_addr`| ip        | IP destination                       |
| `netflow.next_hop`| ip        | IP du prochain saut                  |
| `netflow.src_port`| integer   | Port source                          |
| `netflow.dst_port`| integer   | Port destination                     |
| `netflow.proto`   | keyword   | Numéro de protocole (6=TCP, 17=UDP)  |
| `netflow.bytes`   | long      | Octets du flux                       |
| `netflow.packets` | long      | Paquets du flux                      |
| `netflow.start`   | date      | Timestamp début du flux              |
| `netflow.end`     | date      | Timestamp fin du flux                |
| `netflow.in_if`   | integer   | Interface d'entrée (SNMP index)      |
| `netflow.out_if`  | integer   | Interface de sortie (SNMP index)     |
| `netflow.src_as`  | long      | AS source (BGP)                      |
| `netflow.dst_as`  | long      | AS destination (BGP)                 |
| `@timestamp`      | date      | Timestamp d'ingestion                |
| `engine`          | keyword   | "netflow"                            |
| `container.name`  | keyword   | "netwatch-goflow2"                   |

---

## ILM — Rétention 30 jours

La politique ILM `netwatch-netflow` gère automatiquement la rotation et la suppression des index.

```bash
# Vérifier la politique ILM
curl "http://localhost:9200/_ilm/policy/netwatch-netflow?pretty"

# Vérifier l'état ILM des index netflow-*
curl "http://localhost:9200/netflow-*/_ilm/explain?pretty"
```

Pour modifier la rétention (ex. 60 jours) :
```bash
curl -X PUT "http://localhost:9200/_ilm/policy/netwatch-netflow" \
  -H "Content-Type: application/json" \
  -d '{"policy":{"phases":{"hot":{"min_age":"0ms","actions":{"rollover":{"max_age":"1d","max_primary_shard_size":"5gb"}}},"delete":{"min_age":"60d","actions":{"delete":{}}}}}}'
```

---

## Health check

```bash
# Via make
make health

# La ligne GoFlow2 affiche :
#   ✓  GoFlow2              running — 3 index netflow-* (42156 docs)
```

GoFlow2 est en warn si le container tourne mais aucun flux n'a encore été reçu (`aucun index netflow-*`). C'est normal avant la configuration des équipements réseau.
