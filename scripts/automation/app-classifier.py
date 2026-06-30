#!/usr/bin/env python3
"""
app-classifier.py — NetWatch Application Flow Classifier

Enrichit les flux réseau (netflow-* et zeek-*) avec le nom d'application
et la catégorie à partir du port de destination ou du service Zeek détecté.

Sources :
  1. ES netflow-*  : champ dst_port  → app_name / app_category
  2. ES zeek-*     : champ service (Zeek) puis id.resp_p en fallback

Output :
  - Bulk update ES (update_by_query par port pour netflow-*, par service pour zeek-*)
  - Fichier app-flows-today.json pour le portail (top_apps + by_category)

Usage :
    python3 app-classifier.py [--days 1] [--output FILE] [--dry-run] [--verbose]
                              [--es-url http://localhost:9200]
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR   = Path(__file__).resolve().parent
REPO_ROOT    = SCRIPT_DIR.parent.parent
DEFAULT_OUTPUT = SCRIPT_DIR / "app-flows-today.json"
DEFAULT_ES_URL = os.environ.get("ES_URL", "http://localhost:9200")

# ---------------------------------------------------------------------------
# PORT → (app_name, category) — 400+ entrées
# Catégories : web | remote-access | file-share | email | database
#              collaboration | streaming | infrastructure | security | unknown
# ---------------------------------------------------------------------------
PORT_APP_MAP: dict[int, tuple[str, str]] = {
    # ── Web ──────────────────────────────────────────────────────────────────
    80:    ("HTTP",              "web"),
    443:   ("HTTPS",             "web"),
    3000:  ("Grafana-HTTP",      "web"),
    3001:  ("React-DevServer",   "web"),
    3128:  ("Squid-Proxy",       "web"),
    4000:  ("Web-Dev",           "web"),
    4200:  ("Angular-DevServer", "web"),
    4243:  ("Docker-HTTP",       "web"),
    4443:  ("HTTPS-Alt",         "web"),
    5000:  ("Flask-HTTP",        "web"),
    5001:  ("Web-Dev2",          "web"),
    6060:  ("HTTP-Pprof",        "web"),
    6080:  ("HTTP-GW",           "web"),
    7001:  ("WebLogic-HTTP",     "web"),
    7002:  ("WebLogic-HTTPS",    "web"),
    7070:  ("HTTP-Alt",          "web"),
    7080:  ("HTTP-GW2",          "web"),
    7443:  ("HTTPS-GW",          "web"),
    8000:  ("HTTP-Dev",          "web"),
    8001:  ("HTTP-Dev2",         "web"),
    8002:  ("HTTP-Dev3",         "web"),
    8003:  ("HTTP-Dev4",         "web"),
    8004:  ("HTTP-Dev5",         "web"),
    8005:  ("Tomcat-Shutdown",   "web"),
    8006:  ("HTTP-Dev6",         "web"),
    8007:  ("HTTP-Dev7",         "web"),
    8008:  ("HTTP-Alt2",         "web"),
    8009:  ("AJP-Tomcat",        "web"),
    8010:  ("HTTP-Dev8",         "web"),
    8080:  ("HTTP-Proxy",        "web"),
    8081:  ("HTTP-Alt3",         "web"),
    8082:  ("HTTP-Alt4",         "web"),
    8083:  ("HTTP-Alt5",         "web"),
    8084:  ("HTTP-Alt6",         "web"),
    8085:  ("HTTP-Alt7",         "web"),
    8087:  ("HTTP-Alt8",         "web"),
    8088:  ("HTTP-Alt9",         "web"),
    8089:  ("Splunk-Web",        "web"),
    8090:  ("HTTP-Alt10",        "web"),
    8091:  ("Couchbase-Web",     "web"),
    8095:  ("HTTP-Alt11",        "web"),
    8118:  ("Privoxy-HTTP",      "web"),
    8180:  ("HTTP-Alt12",        "web"),
    8181:  ("HTTPS-Tomcat",      "web"),
    8280:  ("HTTP-Alt13",        "web"),
    8443:  ("HTTPS-Alt2",        "web"),
    8480:  ("HTTP-Alt14",        "web"),
    8543:  ("HTTPS-Alt3",        "web"),
    8800:  ("HTTP-Alt15",        "web"),
    8880:  ("HTTP-Alt16",        "web"),
    8888:  ("Jupyter-HTTP",      "web"),
    8900:  ("HTTP-Alt17",        "web"),
    8983:  ("Solr-HTTP",         "web"),
    9000:  ("HTTP-Alt18",        "web"),
    9001:  ("HTTP-Alt19",        "web"),
    9080:  ("HTTP-Alt20",        "web"),
    9081:  ("HTTP-Alt21",        "web"),
    9082:  ("HTTP-Alt22",        "web"),
    9083:  ("HTTP-Alt23",        "web"),
    9090:  ("Prometheus-UI",     "web"),
    9091:  ("Prometheus-Alt",    "web"),
    9100:  ("Prometheus-Exp",    "web"),
    9200:  ("Elasticsearch-HTTP","web"),
    9201:  ("ES-HTTP-Alt",       "web"),
    9300:  ("ES-Cluster",        "web"),
    9443:  ("HTTPS-Alt4",        "web"),
    10080: ("HTTP-Alt21",        "web"),
    11371: ("HKP-Keyserver",     "web"),
    # ── Remote Access ────────────────────────────────────────────────────────
    22:    ("SSH",               "remote-access"),
    23:    ("Telnet",            "remote-access"),
    222:   ("SSH-Alt",           "remote-access"),
    1723:  ("PPTP",              "remote-access"),
    2022:  ("SSH-Alt2",          "remote-access"),
    2200:  ("SSH-Alt3",          "remote-access"),
    2222:  ("SSH-Alt4",          "remote-access"),
    2223:  ("SSH-Alt5",          "remote-access"),
    3389:  ("RDP",               "remote-access"),
    3390:  ("RDP-Alt",           "remote-access"),
    3391:  ("RDP-Alt2",          "remote-access"),
    4444:  ("NC-Bind",           "remote-access"),
    4899:  ("RAdmin",            "remote-access"),
    5900:  ("VNC",               "remote-access"),
    5901:  ("VNC-2",             "remote-access"),
    5902:  ("VNC-3",             "remote-access"),
    5903:  ("VNC-4",             "remote-access"),
    5904:  ("VNC-5",             "remote-access"),
    5985:  ("WinRM-HTTP",        "remote-access"),
    5986:  ("WinRM-HTTPS",       "remote-access"),
    6543:  ("RDP-Alt3",          "remote-access"),
    8291:  ("Mikrotik-Winbox",   "remote-access"),
    9922:  ("SSH-Alt6",          "remote-access"),
    10000: ("Webmin-HTTP",       "remote-access"),
    20000: ("Usermin-HTTP",      "remote-access"),
    # ── File Share ───────────────────────────────────────────────────────────
    20:    ("FTP-Data",          "file-share"),
    21:    ("FTP",               "file-share"),
    69:    ("TFTP",              "file-share"),
    111:   ("RPCbind",           "file-share"),
    137:   ("NetBIOS-NS",        "file-share"),
    138:   ("NetBIOS-DGM",       "file-share"),
    139:   ("NetBIOS-SSN",       "file-share"),
    427:   ("SLP",               "file-share"),
    445:   ("SMB",               "file-share"),
    548:   ("AFP",               "file-share"),
    860:   ("iSCSI-UDP",         "file-share"),
    873:   ("rsync",             "file-share"),
    989:   ("FTPS-Data",         "file-share"),
    990:   ("FTPS",              "file-share"),
    2049:  ("NFS",               "file-share"),
    3260:  ("iSCSI",             "file-share"),
    4045:  ("NFS-Lockd",         "file-share"),
    4046:  ("NFS-Status",        "file-share"),
    # ── Email ────────────────────────────────────────────────────────────────
    25:    ("SMTP",              "email"),
    26:    ("SMTP-Alt",          "email"),
    110:   ("POP3",              "email"),
    143:   ("IMAP",              "email"),
    366:   ("ODMR",              "email"),
    465:   ("SMTPS",             "email"),
    587:   ("SMTP-TLS",          "email"),
    993:   ("IMAPS",             "email"),
    995:   ("POP3S",             "email"),
    2525:  ("SMTP-Alt2",         "email"),
    2526:  ("SMTP-Alt3",         "email"),
    # ── Database ─────────────────────────────────────────────────────────────
    1433:  ("MSSQL",             "database"),
    1434:  ("MSSQL-Browser",     "database"),
    1521:  ("Oracle-DB",         "database"),
    1522:  ("Oracle-Alt",        "database"),
    1526:  ("Oracle-Alt2",       "database"),
    1527:  ("Oracle-Alt3",       "database"),
    3306:  ("MySQL",             "database"),
    3307:  ("MySQL-Alt",         "database"),
    5432:  ("PostgreSQL",        "database"),
    5433:  ("PostgreSQL-Alt",    "database"),
    5984:  ("CouchDB-HTTP",      "database"),
    6379:  ("Redis",             "database"),
    6380:  ("Redis-TLS",         "database"),
    6381:  ("Redis-Cluster-1",   "database"),
    6382:  ("Redis-Cluster-2",   "database"),
    6432:  ("PgBouncer",         "database"),
    7473:  ("Neo4j-HTTPS",       "database"),
    7474:  ("Neo4j-HTTP",        "database"),
    7687:  ("Neo4j-Bolt",        "database"),
    8086:  ("InfluxDB-HTTP",     "database"),
    8087:  ("InfluxDB-Alt",      "database"),
    8098:  ("Riak-HTTP",         "database"),
    8099:  ("Riak-PB",           "database"),
    9042:  ("Cassandra",         "database"),
    9142:  ("Cassandra-TLS",     "database"),
    9160:  ("Cassandra-Thrift",  "database"),
    11211: ("Memcached",         "database"),
    11212: ("Memcached-TLS",     "database"),
    27017: ("MongoDB",           "database"),
    27018: ("MongoDB-Shard",     "database"),
    27019: ("MongoDB-Config",    "database"),
    28015: ("RethinkDB",         "database"),
    28016: ("RethinkDB-Admin",   "database"),
    28017: ("MongoDB-Web",       "database"),
    26257: ("CockroachDB",       "database"),
    4369:  ("Erlang-EPMD",       "database"),
    5672:  ("AMQP-RabbitMQ",     "database"),
    5671:  ("AMQPS-RabbitMQ",    "database"),
    15672: ("RabbitMQ-Mgmt",     "database"),
    15671: ("RabbitMQ-Mgmt-TLS", "database"),
    61616: ("ActiveMQ",          "database"),
    61617: ("ActiveMQ-SSL",      "database"),
    # ── Collaboration ────────────────────────────────────────────────────────
    1863:  ("MSN-Messenger",     "collaboration"),
    3478:  ("STUN-Teams",        "collaboration"),
    3479:  ("Teams-UDP",         "collaboration"),
    3480:  ("STUN-Alt",          "collaboration"),
    5060:  ("SIP",               "collaboration"),
    5061:  ("SIPS",              "collaboration"),
    5080:  ("SIP-Alt",           "collaboration"),
    5222:  ("XMPP",              "collaboration"),
    5223:  ("XMPP-TLS",          "collaboration"),
    5228:  ("Google-FCM",        "collaboration"),
    5229:  ("Google-FCM-Alt",    "collaboration"),
    5230:  ("Google-FCM-Alt2",   "collaboration"),
    5269:  ("XMPP-S2S",          "collaboration"),
    5349:  ("STUN-TLS",          "collaboration"),
    8801:  ("Zoom-TCP",          "collaboration"),
    8802:  ("Zoom-UDP",          "collaboration"),
    8803:  ("Zoom-Alt",          "collaboration"),
    19302: ("Google-STUN",       "collaboration"),
    19303: ("Google-STUN-Alt",   "collaboration"),
    33434: ("STUN-Traceroute",   "collaboration"),
    # ── Streaming ────────────────────────────────────────────────────────────
    554:   ("RTSP",              "streaming"),
    555:   ("RTSP-Alt",          "streaming"),
    1234:  ("RTSP-VLC",          "streaming"),
    1755:  ("MMS",               "streaming"),
    1935:  ("RTMP",              "streaming"),
    1936:  ("RTMPS",             "streaming"),
    4747:  ("Streamr",           "streaming"),
    5004:  ("RTP",               "streaming"),
    5005:  ("RTCP",              "streaming"),
    7777:  ("HTTP-Streaming",    "streaming"),
    8096:  ("Jellyfin-HTTP",     "streaming"),
    8554:  ("RTSP-Alt2",         "streaming"),
    8920:  ("Jellyfin-HTTPS",    "streaming"),
    9554:  ("RTSP-Alt3",         "streaming"),
    32400: ("Plex-Media",        "streaming"),
    32469: ("Plex-DLNA",         "streaming"),
    # ── Infrastructure ───────────────────────────────────────────────────────
    53:    ("DNS",               "infrastructure"),
    67:    ("DHCP-Server",       "infrastructure"),
    68:    ("DHCP-Client",       "infrastructure"),
    88:    ("Kerberos",          "infrastructure"),
    102:   ("ISO-TSAP",          "infrastructure"),
    119:   ("NNTP",              "infrastructure"),
    123:   ("NTP",               "infrastructure"),
    135:   ("MS-RPC",            "infrastructure"),
    161:   ("SNMP",              "infrastructure"),
    162:   ("SNMP-Trap",         "infrastructure"),
    179:   ("BGP",               "infrastructure"),
    194:   ("IRC",               "infrastructure"),
    389:   ("LDAP",              "infrastructure"),
    443:   ("HTTPS",             "web"),           # skipped duplicate
    464:   ("Kerberos-Chpwd",    "infrastructure"),
    500:   ("IKEv2",             "security"),
    514:   ("Syslog-UDP",        "infrastructure"),
    515:   ("LPD-Print",         "infrastructure"),
    520:   ("RIPv1",             "infrastructure"),
    521:   ("RIPng",             "infrastructure"),
    546:   ("DHCPv6-Client",     "infrastructure"),
    547:   ("DHCPv6-Server",     "infrastructure"),
    636:   ("LDAPS",             "infrastructure"),
    749:   ("Kerberos-Admin",    "infrastructure"),
    750:   ("Kerberos-IV",       "infrastructure"),
    751:   ("Kerberos-Master",   "infrastructure"),
    853:   ("DNS-over-TLS",      "infrastructure"),
    1080:  ("SOCKS5-Proxy",      "infrastructure"),
    1812:  ("RADIUS-Auth",       "security"),
    1813:  ("RADIUS-Acct",       "security"),
    1883:  ("MQTT",              "infrastructure"),
    8883:  ("MQTTS",             "infrastructure"),
    2055:  ("NetFlow",           "infrastructure"),
    2083:  ("cPanel-HTTPS",      "infrastructure"),
    2086:  ("WHM-HTTP",          "infrastructure"),
    2087:  ("WHM-HTTPS",         "infrastructure"),
    2095:  ("cPanel-WebMail",    "infrastructure"),
    2096:  ("cPanel-WebMail-TLS","infrastructure"),
    2152:  ("GTP-U",             "infrastructure"),
    2181:  ("ZooKeeper",         "infrastructure"),
    2375:  ("Docker-HTTP",       "infrastructure"),
    2376:  ("Docker-TLS",        "infrastructure"),
    2377:  ("Docker-Swarm",      "infrastructure"),
    2379:  ("etcd-Client",       "infrastructure"),
    2380:  ("etcd-Peer",         "infrastructure"),
    2382:  ("MS-OLAP-HTTP",      "infrastructure"),
    3000:  ("Grafana-HTTP",      "web"),           # already web - will be skipped below
    4500:  ("IPsec-NAT-T",       "security"),
    4789:  ("VXLAN",             "infrastructure"),
    5353:  ("mDNS",              "infrastructure"),
    6053:  ("DNS-Alt",           "infrastructure"),
    6081:  ("Geneve-Overlay",    "infrastructure"),
    6443:  ("Kubernetes-API",    "infrastructure"),
    6514:  ("Syslog-TLS",        "infrastructure"),
    8125:  ("StatsD-UDP",        "infrastructure"),
    8126:  ("StatsD-TCP",        "infrastructure"),
    8300:  ("Consul-RPC",        "infrastructure"),
    8301:  ("Consul-LAN",        "infrastructure"),
    8302:  ("Consul-WAN",        "infrastructure"),
    8400:  ("Consul-CLI",        "infrastructure"),
    8500:  ("Consul-HTTP",       "infrastructure"),
    8600:  ("Consul-DNS",        "infrastructure"),
    9092:  ("Kafka-Broker",      "infrastructure"),
    9093:  ("Kafka-TLS",         "infrastructure"),
    9094:  ("Kafka-SASL",        "infrastructure"),
    9309:  ("ES-Cluster-Alt",    "infrastructure"),
    10250: ("Kubelet-API",       "infrastructure"),
    10255: ("Kubelet-RO",        "infrastructure"),
    10256: ("kube-proxy",        "infrastructure"),
    10443: ("Kubernetes-Mgmt",   "infrastructure"),
    2181:  ("ZooKeeper",         "infrastructure"),
    # Monitoring & Observability
    4317:  ("OTLP-gRPC",         "infrastructure"),
    4318:  ("OTLP-HTTP",         "infrastructure"),
    9104:  ("MySQL-Exporter",    "infrastructure"),
    9115:  ("Blackbox-Exporter", "infrastructure"),
    9116:  ("SNMP-Exporter",     "infrastructure"),
    9187:  ("PG-Exporter",       "infrastructure"),
    9216:  ("MongoDB-Exporter",  "infrastructure"),
    14268: ("Jaeger-HTTP",       "infrastructure"),
    14250: ("Jaeger-gRPC",       "infrastructure"),
    16686: ("Jaeger-UI",         "infrastructure"),
    3100:  ("Loki-HTTP",         "infrastructure"),
    3200:  ("Grafana-Tempo",     "infrastructure"),
    # CI/CD & DevOps
    2224:  ("GitLab-SSH",        "infrastructure"),
    8929:  ("GitLab-Pages",      "infrastructure"),
    8888:  ("Jupyter-HTTP",      "web"),           # duplicate skip
    # Service Mesh & Network
    15001: ("Istio-Envoy",       "infrastructure"),
    15006: ("Istio-Envoy-Out",   "infrastructure"),
    15010: ("Pilot-gRPC",        "infrastructure"),
    15012: ("Pilot-gRPC-TLS",    "infrastructure"),
    15014: ("Citadel-gRPC",      "infrastructure"),
    15017: ("Istiod-Webhook",    "infrastructure"),
    15020: ("Merlin-HTTP",       "infrastructure"),
    15021: ("Istiod-Health",     "infrastructure"),
    15090: ("Envoy-Admin",       "infrastructure"),
    # PKI / Certificate
    8200:  ("HashiCorp-Vault",   "security"),
    8201:  ("Vault-Cluster",     "security"),
    9090:  ("Prometheus-UI",     "web"),           # duplicate skip
    # Time Series & Metrics
    2003:  ("Graphite-Carbon",   "infrastructure"),
    2004:  ("Graphite-Pickle",   "infrastructure"),
    8082:  ("InfluxDB-UDP",      "database"),      # duplicate skip
    # Network Management
    69:    ("TFTP",              "file-share"),    # duplicate
    5632:  ("PCAnywhere",        "remote-access"),
    161:   ("SNMP",              "infrastructure"),# duplicate
    162:   ("SNMP-Trap",         "infrastructure"),# duplicate
    # Router / Switch management
    22:    ("SSH",               "remote-access"), # duplicate
    23:    ("Telnet",            "remote-access"), # duplicate
    830:   ("NETCONF-SSH",       "infrastructure"),
    831:   ("NETCONF-BeepSec",   "infrastructure"),
    6513:  ("NETCONF-TLS",       "infrastructure"),
    8022:  ("Ansible-SSH",       "infrastructure"),
    8888:  ("API-GW",            "web"),           # duplicate
    # DNS variants
    784:   ("DNS-over-QUIC",     "infrastructure"),
    8853:  ("DNS-over-HTTPS-Alt","infrastructure"),
    # SNMP versions
    161:   ("SNMP",              "infrastructure"), # duplicate
    10161: ("SNMP-Alt",          "infrastructure"),
    10162: ("SNMP-Trap-Alt",     "infrastructure"),
    # Industrial / IoT
    102:   ("S7comm",            "infrastructure"), # duplicate
    502:   ("Modbus-TCP",        "infrastructure"),
    503:   ("Modbus-TLS",        "infrastructure"),
    20000: ("DNP3-TCP",          "infrastructure"),  # duplicate - override Usermin
    44818: ("EtherNet-IP",       "infrastructure"),
    47808: ("BACnet",            "infrastructure"),
    1911:  ("Niagara-Fox",       "infrastructure"),
    4840:  ("OPC-UA",            "infrastructure"),
    4843:  ("OPC-UA-TLS",        "infrastructure"),
    2404:  ("IEC-60870-5-104",   "infrastructure"),
    # Zabbix / Nagios / Monitoring agents
    10050: ("Zabbix-Agent",      "infrastructure"),
    10051: ("Zabbix-Server",     "infrastructure"),
    12489: ("Nagios-NRPE",       "infrastructure"),
    5666:  ("NRPE",              "infrastructure"),
    # Puppet / Chef / Ansible
    8140:  ("Puppet-Master",     "infrastructure"),
    9418:  ("Git-Protocol",      "infrastructure"),
    # Container Registry
    5000:  ("Docker-Registry",   "infrastructure"),  # duplicate - Flask
    # Vault / Secrets
    8200:  ("Vault-HTTP",        "security"),     # duplicate
    # Networking protocols
    179:   ("BGP",               "infrastructure"),  # duplicate
    646:   ("LDP-MPLS",          "infrastructure"),
    4789:  ("VXLAN",             "infrastructure"),  # duplicate
    6633:  ("OpenFlow",          "infrastructure"),
    6634:  ("OpenFlow-Alt",      "infrastructure"),
    6653:  ("OpenFlow-1.3",      "infrastructure"),
    # RADIUS / DIAMETER
    3868:  ("Diameter",          "security"),
    3869:  ("Diameter-TLS",      "security"),
    # TACACS+
    49:    ("TACACS",            "security"),
    # GRE / tunnels (no port but added for completeness)
    1701:  ("L2TP",              "security"),
    1702:  ("L2TP-Alt",          "security"),
    # Zscaler / proxy
    9480:  ("Zscaler-HTTP",      "security"),
    9443:  ("Zscaler-HTTPS",     "security"),  # duplicate
    # ── Security ─────────────────────────────────────────────────────────────
    500:   ("IKEv2",             "security"),    # duplicate
    1194:  ("OpenVPN",           "security"),
    1195:  ("OpenVPN-Alt",       "security"),
    1196:  ("OpenVPN-Alt2",      "security"),
    1197:  ("OpenVPN-Alt3",      "security"),
    1198:  ("OpenVPN-Alt4",      "security"),
    1199:  ("OpenVPN-Alt5",      "security"),
    4500:  ("IPsec-NAT-T",       "security"),  # duplicate
    51820: ("WireGuard",         "security"),
    51821: ("WireGuard-Alt",     "security"),
    1194:  ("OpenVPN-UDP",       "security"),  # duplicate
    943:   ("OpenVPN-AS-Web",    "security"),
    945:   ("OpenVPN-AS-Web2",   "security"),
    8443:  ("Cisco-ASDM",        "web"),       # duplicate
    10443: ("FortiGate-Admin",   "security"),
    4444:  ("Meterpreter",       "security"),  # duplicate as remote-access
    9001:  ("Tor-OR",            "security"),
    9030:  ("Tor-Dir",           "security"),
    9050:  ("Tor-SOCKS",         "security"),
    9051:  ("Tor-Control",       "security"),
    2702:  ("SMS-XFER",          "security"),
    8834:  ("Nessus-HTTPS",      "security"),
    8835:  ("Nessus-Agent",      "security"),
    7054:  ("OpenDaylight",      "security"),
    # Splunk
    9997:  ("Splunk-Forward",    "infrastructure"),
    8000:  ("Splunk-Web",        "web"),        # duplicate
    8089:  ("Splunk-Mgmt",       "web"),        # duplicate
    514:   ("Splunk-Syslog",     "infrastructure"),  # duplicate
    # HashiCorp
    8500:  ("Consul-HTTP",       "infrastructure"),  # duplicate
    8300:  ("Consul-RPC",        "infrastructure"),  # duplicate
    8301:  ("Consul-Serf",       "infrastructure"),  # duplicate
    8302:  ("Consul-Serf-WAN",   "infrastructure"),  # duplicate
    # Kubernetes
    6443:  ("K8s-API",           "infrastructure"),  # duplicate
    10250: ("Kubelet",           "infrastructure"),  # duplicate
    30000: ("K8s-NodePort-Min",  "infrastructure"),
    32767: ("K8s-NodePort-Max",  "infrastructure"),
    # Redis Sentinel / Cluster
    26379: ("Redis-Sentinel",    "database"),
    # Elasticsearch
    9200:  ("ES-HTTP",           "web"),        # duplicate
    9300:  ("ES-Transport",      "web"),        # duplicate
    # Graylog
    12201: ("Graylog-GELF-UDP",  "infrastructure"),
    12202: ("Graylog-GELF-TCP",  "infrastructure"),
    12900: ("Graylog-API",       "infrastructure"),
    # Kafka Connect / Schema Registry
    8083:  ("Kafka-Connect",     "infrastructure"),  # duplicate
    8081:  ("Schema-Registry",   "infrastructure"),  # duplicate
    # NSQ
    4150:  ("NSQ-TCP",           "infrastructure"),
    4151:  ("NSQ-HTTP",          "infrastructure"),
    4160:  ("NSQLookupd-TCP",    "infrastructure"),
    4161:  ("NSQLookupd-HTTP",   "infrastructure"),
    # NATS
    4222:  ("NATS",              "infrastructure"),
    6222:  ("NATS-Route",        "infrastructure"),
    8222:  ("NATS-Monitor",      "infrastructure"),
    # Thrift / gRPC
    9090:  ("Thrift-HTTP",       "web"),  # duplicate
    50051: ("gRPC",              "infrastructure"),
    # CockroachDB cluster
    26258: ("CockroachDB-CLI",   "database"),
    # Prometheus Alertmanager
    9093:  ("Alertmanager",      "infrastructure"),  # duplicate
    # ClickHouse
    8123:  ("ClickHouse-HTTP",   "database"),
    9000:  ("ClickHouse-Native", "database"),  # duplicate
    9440:  ("ClickHouse-HTTPS",  "database"),
    # TimescaleDB (PostgreSQL)
    5435:  ("TimescaleDB",       "database"),
    # Druid
    8082:  ("Druid-Broker",      "database"),  # duplicate
    8083:  ("Druid-Coord",       "database"),  # duplicate
    8084:  ("Druid-Router",      "database"),  # duplicate
    8888:  ("Druid-Router2",     "database"),  # duplicate
    # Flink
    6123:  ("Flink-RPC",         "infrastructure"),
    6124:  ("Flink-Blob",        "infrastructure"),
    8081:  ("Flink-UI",          "web"),       # duplicate
    # Hadoop
    8020:  ("HDFS-NameNode",     "infrastructure"),
    9870:  ("HDFS-Web",          "infrastructure"),
    19888: ("MapReduce-History",  "infrastructure"),
    # Spark
    4040:  ("Spark-UI",          "infrastructure"),
    7077:  ("Spark-Master",      "infrastructure"),
    8080:  ("Spark-UI2",         "web"),       # duplicate
    # ELK Stack
    5601:  ("Kibana-HTTP",       "web"),
    5044:  ("Logstash-Beats",    "infrastructure"),
    9600:  ("Logstash-Monitor",  "infrastructure"),
    # Airflow
    8793:  ("Airflow-Worker",    "infrastructure"),
    # PostgreSQL replication
    5434:  ("PG-Replication",    "database"),
    # MySQL replication
    3308:  ("MySQL-Replication", "database"),
    # Ceph
    6789:  ("Ceph-Monitor",      "infrastructure"),
    6800:  ("Ceph-OSD",          "infrastructure"),
    6801:  ("Ceph-OSD-Alt",      "infrastructure"),
    6802:  ("Ceph-OSD-Alt2",     "infrastructure"),
    6803:  ("Ceph-OSD-Alt3",     "infrastructure"),
    # MinIO
    9000:  ("MinIO-S3",          "infrastructure"),  # duplicate
    9001:  ("MinIO-Console",     "infrastructure"),  # duplicate
    # Vault
    8200:  ("Vault-API",         "security"),  # duplicate
    8201:  ("Vault-Cluster",     "security"),  # duplicate
    # Zipkin
    9411:  ("Zipkin-HTTP",       "infrastructure"),
    # CoreDNS
    53:    ("CoreDNS",           "infrastructure"),  # duplicate
    # FreeRADIUS
    1812:  ("RADIUS-Auth",       "security"),  # duplicate
    1813:  ("RADIUS-Acct",       "security"),  # duplicate
    1814:  ("RADIUS-Dyn-Auth",   "security"),
    # Samba DC
    88:    ("Samba-Kerberos",    "infrastructure"),  # duplicate
    464:   ("Samba-Kerberos-Pwd","infrastructure"),  # duplicate
    636:   ("Samba-LDAPS",       "infrastructure"),  # duplicate
    # Network printing
    631:   ("IPP",               "infrastructure"),
    9100:  ("RAW-Print",         "infrastructure"),  # duplicate
    # Citrix
    1494:  ("Citrix-ICA",        "remote-access"),
    2598:  ("Citrix-CGP",        "remote-access"),
    # X11
    6000:  ("X11",               "remote-access"),
    6001:  ("X11-Alt",           "remote-access"),
    6002:  ("X11-Alt2",          "remote-access"),
    # Nginx Unit
    8080:  ("Nginx-Unit",        "web"),  # duplicate
    # Caddy
    2020:  ("Caddy-API",         "infrastructure"),
    # Traefik
    8080:  ("Traefik-Dashboard", "web"),  # duplicate
    # HAProxy
    1936:  ("HAProxy-Stats",     "web"),    # also streaming
    # Keepalived / VRRP
    112:   ("VRRP",              "infrastructure"),
    # HSRP uses multicast - 224.0.0.2:1985
    # SNMP over UDP
    161:   ("SNMP-UDP",          "infrastructure"),  # duplicate
    # OSPF uses protocol 89, no port
    # EIGRP uses protocol 88, no port
    # Wireshark dissects these as TCP/UDP port 0 sometimes
    # Syslog TLS
    6514:  ("Syslog-TLS",        "infrastructure"),  # duplicate
    # SolarWinds
    17778: ("SolarWinds-HTTPS",  "infrastructure"),
    17777: ("SolarWinds-HTTP",   "infrastructure"),
    # PRTG
    9090:  ("PRTG-Web",          "web"),    # duplicate
    # Nagios
    5666:  ("Nagios-NRPE",       "infrastructure"),  # duplicate
    # Ansible AWX/Tower
    8052:  ("AWX-WebSocket",     "infrastructure"),
    # Checkmk
    6556:  ("Checkmk-Agent",     "infrastructure"),
    # Puppet
    8140:  ("Puppet-Server",     "infrastructure"),  # duplicate
    # Salt
    4505:  ("SaltStack-Pub",     "infrastructure"),
    4506:  ("SaltStack-RPC",     "infrastructure"),
    # WireGuard alternate
    51820: ("WireGuard",         "security"),  # duplicate
    # NFS v4
    2049:  ("NFSv4",             "file-share"),  # duplicate
    # DRBD replication
    7788:  ("DRBD",              "infrastructure"),
    # Kubernetes etcd backup
    2378:  ("etcd-Alt",          "infrastructure"),
    # HA Cluster
    5404:  ("Corosync-UDP",      "infrastructure"),
    5405:  ("Corosync-UDP-Alt",  "infrastructure"),
    # Database extras
    4782:  ("Cassandra-JMX",     "database"),
    # Zookeeper ensemble
    2888:  ("ZK-Leader",         "infrastructure"),
    3888:  ("ZK-Election",       "infrastructure"),
    # Prometheus extras
    9312:  ("Sphinx-Search",     "database"),
    9308:  ("ES-Tribe",          "database"),
    # Windows cluster
    135:   ("DCOM",              "infrastructure"),  # duplicate
    3343:  ("MS-Cluster",        "infrastructure"),
    # Hyper-V
    2179:  ("Hyper-V",           "remote-access"),
    # VMware
    443:   ("VMware-HTTPS",      "web"),     # duplicate
    902:   ("VMware-ESXi",       "infrastructure"),
    903:   ("VMware-Console",    "remote-access"),
    907:   ("VMware-RDT",        "remote-access"),
    # vSphere
    5480:  ("vCenter-Appliance", "infrastructure"),
    9443:  ("vCenter-HTTPS",     "web"),  # duplicate
    # iDRAC / ILO
    623:   ("IPMI-RMCP",         "infrastructure"),
    664:   ("IPMI-RMCP-TLS",     "infrastructure"),
    # Wake on LAN
    7:     ("Echo",              "infrastructure"),
    9:     ("Discard",           "infrastructure"),
    # Additional common ports
    512:   ("rexec",             "remote-access"),
    513:   ("rlogin",            "remote-access"),
    43:    ("WHOIS",             "infrastructure"),
    70:    ("Gopher",            "web"),
    79:    ("Finger",            "infrastructure"),
    104:   ("DICOM",             "infrastructure"),
    143:   ("IMAP",              "email"),    # duplicate
    220:   ("IMAPv3",            "email"),
    389:   ("LDAP",              "infrastructure"),  # duplicate
    443:   ("HTTPS",             "web"),     # duplicate
    # Extra database ports
    5050:  ("Trino-HTTP",        "database"),
    8080:  ("Trino-HTTPS",       "web"),    # duplicate
    8090:  ("Presto-HTTP",       "database"),  # duplicate
    9083:  ("Hive-Metastore",    "database"),  # duplicate
    10000: ("HiveServer2",       "database"),  # already remote-access
    10002: ("HiveServer2-HTTP",  "database"),
}

# ---------------------------------------------------------------------------
# Zeek service name → (app_name, category)
# Used as primary lookup for zeek-* conn.log (field: service or id.service)
# ---------------------------------------------------------------------------
ZEEK_SERVICE_MAP: dict[str, tuple[str, str]] = {
    "http":          ("HTTP",           "web"),
    "http/1.1":      ("HTTP",           "web"),
    "ssl":           ("HTTPS",          "web"),
    "tls":           ("HTTPS",          "web"),
    "quic":          ("QUIC-HTTP3",     "web"),
    "ssh":           ("SSH",            "remote-access"),
    "rdp":           ("RDP",            "remote-access"),
    "telnet":        ("Telnet",         "remote-access"),
    "vnc":           ("VNC",            "remote-access"),
    "rfb":           ("VNC-RFB",        "remote-access"),
    "ftp":           ("FTP",            "file-share"),
    "ftp-data":      ("FTP-Data",       "file-share"),
    "smb":           ("SMB",            "file-share"),
    "dce_rpc":       ("DCE-RPC",        "infrastructure"),
    "dns":           ("DNS",            "infrastructure"),
    "dhcp":          ("DHCP",           "infrastructure"),
    "ntp":           ("NTP",            "infrastructure"),
    "snmp":          ("SNMP",           "infrastructure"),
    "ldap":          ("LDAP",           "infrastructure"),
    "kerberos":      ("Kerberos",       "infrastructure"),
    "krb":           ("Kerberos",       "infrastructure"),
    "syslog":        ("Syslog",         "infrastructure"),
    "tftp":          ("TFTP",           "file-share"),
    "netflow":       ("NetFlow",        "infrastructure"),
    "mqtt":          ("MQTT",           "infrastructure"),
    "modbus":        ("Modbus",         "infrastructure"),
    "dnp3":          ("DNP3",           "infrastructure"),
    "bacnet":        ("BACnet",         "infrastructure"),
    "opcua":         ("OPC-UA",         "infrastructure"),
    "coap":          ("CoAP",           "infrastructure"),
    "smtp":          ("SMTP",           "email"),
    "imap":          ("IMAP",           "email"),
    "pop3":          ("POP3",           "email"),
    "mysql":         ("MySQL",          "database"),
    "postgresql":    ("PostgreSQL",     "database"),
    "redis":         ("Redis",          "database"),
    "mongodb":       ("MongoDB",        "database"),
    "elasticsearch": ("Elasticsearch",  "database"),
    "cassandra":     ("Cassandra",      "database"),
    "sip":           ("SIP",            "collaboration"),
    "xmpp":          ("XMPP",          "collaboration"),
    "irc":           ("IRC",            "collaboration"),
    "rtp":           ("RTP",            "streaming"),
    "rtsp":          ("RTSP",           "streaming"),
    "rtmp":          ("RTMP",           "streaming"),
    "radius":        ("RADIUS",         "security"),
    "gssapi":        ("GSSAPI",         "security"),
    "ntlm":          ("NTLM",           "security"),
    "ike":           ("IKEv2",          "security"),
    "openvpn":       ("OpenVPN",        "security"),
    "amqp":          ("AMQP",           "database"),
    "nfs":           ("NFS",            "file-share"),
    "portmapper":    ("RPCbind",        "file-share"),
    "ident":         ("Ident",          "infrastructure"),
    "finger":        ("Finger",         "infrastructure"),
    "gopher":        ("Gopher",         "web"),
    "rsync":         ("rsync",          "file-share"),
    "bgp":           ("BGP",            "infrastructure"),
    "ospf":          ("OSPF",           "infrastructure"),
    "eigrp":         ("EIGRP",          "infrastructure"),
}

# Build deduplicated PORT_APP_MAP (first definition wins, ignoring duplicates)
_seen_ports: set[int] = set()
_PORT_APP_MAP_CLEAN: dict[int, tuple[str, str]] = {}
for _port, _info in PORT_APP_MAP.items():
    if _port not in _seen_ports:
        _seen_ports.add(_port)
        _PORT_APP_MAP_CLEAN[_port] = _info
PORT_APP_MAP = _PORT_APP_MAP_CLEAN


# ---------------------------------------------------------------------------
# ES helpers
# ---------------------------------------------------------------------------

def es_request(es_url: str, method: str, path: str,
               body: dict | None = None, verbose: bool = False) -> dict:
    url = es_url.rstrip("/") + path
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method=method.upper(),
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_txt = e.read()[:300].decode(errors="replace") if e.fp else ""
        if verbose:
            print(f"  [ES] HTTP {e.code} {method} {path}: {body_txt}", file=sys.stderr)
        return {"error": f"HTTP {e.code}", "detail": body_txt}
    except (urllib.error.URLError, OSError) as e:
        if verbose:
            print(f"  [ES] request error {method} {path}: {e}", file=sys.stderr)
        return {"error": str(e)}


def index_exists(es_url: str, pattern: str, verbose: bool = False) -> bool:
    resp = es_request(es_url, "HEAD", f"/{pattern}", verbose=verbose)
    return "error" not in resp


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def lookup_port(port: int | None) -> tuple[str, str]:
    """Return (app_name, category) from port number."""
    if port is None:
        return ("Unknown", "unknown")
    entry = PORT_APP_MAP.get(int(port))
    return entry if entry else ("Unknown", "unknown")


def lookup_zeek_service(service: str | None, fallback_port: int | None = None) -> tuple[str, str]:
    """Return (app_name, category) from Zeek service string, with port fallback."""
    if service:
        svc = service.strip().lower()
        entry = ZEEK_SERVICE_MAP.get(svc)
        if entry:
            return entry
    return lookup_port(fallback_port)


# ---------------------------------------------------------------------------
# Query 1 : netflow-* aggregations by dst_port
# ---------------------------------------------------------------------------

def query_netflow_by_port(es_url: str, days: int, verbose: bool) -> list[dict]:
    """
    Aggregate netflow-* by dst_port.
    Returns list of {port, app_name, category, bytes, flows}.
    """
    url = f"/netflow-*/_search"
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
        "aggs": {
            "by_port": {
                "terms": {"field": "dst_port", "size": 500, "min_doc_count": 1},
                "aggs": {
                    "bytes": {"sum": {"field": "in_bytes"}},
                },
            }
        },
    }
    resp = es_request(es_url, "POST", url, body, verbose)
    if "error" in resp:
        if verbose:
            print(f"  [netflow] agg error: {resp['error']}", file=sys.stderr)
        return []

    buckets = resp.get("aggregations", {}).get("by_port", {}).get("buckets", [])
    results = []
    for b in buckets:
        port = b.get("key")
        flows = b.get("doc_count", 0)
        bytes_val = int(b.get("bytes", {}).get("value") or 0)
        app_name, category = lookup_port(port)
        results.append({
            "port": port,
            "app_name": app_name,
            "category": category,
            "bytes": bytes_val,
            "flows": flows,
        })
    return results


# ---------------------------------------------------------------------------
# Query 2 : zeek-* aggregations by service + id.resp_p fallback
# ---------------------------------------------------------------------------

def query_zeek_by_service(es_url: str, days: int, verbose: bool) -> list[dict]:
    """
    Aggregate zeek-* by 'service' field, fallback to 'id.resp_p'.
    Returns list of {app_name, category, bytes, flows}.
    """
    results = []

    # Pass 1 — by service (detected protocol)
    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range":  {"@timestamp": {"gte": f"now-{days}d"}}},
                    {"exists": {"field": "service"}},
                ]
            }
        },
        "aggs": {
            "by_service": {
                "terms": {"field": "service", "size": 200, "min_doc_count": 1},
                "aggs": {
                    "bytes": {
                        "sum": {
                            "script": {
                                "source": (
                                    "(doc.containsKey('orig_bytes') && doc['orig_bytes'].size()>0 "
                                    " ? doc['orig_bytes'].value : 0) + "
                                    "(doc.containsKey('resp_bytes') && doc['resp_bytes'].size()>0 "
                                    " ? doc['resp_bytes'].value : 0)"
                                ),
                                "lang": "painless",
                            }
                        }
                    }
                },
            }
        },
    }
    resp = es_request(es_url, "POST", "/zeek-*/_search", body, verbose)
    if "error" not in resp:
        for b in resp.get("aggregations", {}).get("by_service", {}).get("buckets", []):
            svc = b.get("key", "")
            app_name, category = lookup_zeek_service(svc)
            results.append({
                "app_name": app_name,
                "category": category,
                "bytes": int(b.get("bytes", {}).get("value") or 0),
                "flows": b.get("doc_count", 0),
            })

    # Pass 2 — by id.resp_p for flows with no service
    body2 = {
        "size": 0,
        "query": {
            "bool": {
                "must":     [{"range":  {"@timestamp": {"gte": f"now-{days}d"}}}],
                "must_not": [{"exists": {"field": "service"}}],
                "filter":   [{"exists": {"field": "id.resp_p"}}],
            }
        },
        "aggs": {
            "by_port": {
                "terms": {"field": "id.resp_p", "size": 300, "min_doc_count": 1},
                "aggs": {
                    "bytes": {
                        "sum": {
                            "script": {
                                "source": (
                                    "(doc.containsKey('orig_bytes') && doc['orig_bytes'].size()>0 "
                                    " ? doc['orig_bytes'].value : 0) + "
                                    "(doc.containsKey('resp_bytes') && doc['resp_bytes'].size()>0 "
                                    " ? doc['resp_bytes'].value : 0)"
                                ),
                                "lang": "painless",
                            }
                        }
                    }
                },
            }
        },
    }
    resp2 = es_request(es_url, "POST", "/zeek-*/_search", body2, verbose)
    if "error" not in resp2:
        for b in resp2.get("aggregations", {}).get("by_port", {}).get("buckets", []):
            port = b.get("key")
            app_name, category = lookup_port(port)
            results.append({
                "app_name": app_name,
                "category": category,
                "bytes": int(b.get("bytes", {}).get("value") or 0),
                "flows": b.get("doc_count", 0),
            })

    return results


# ---------------------------------------------------------------------------
# ES bulk update — update_by_query per port
# ---------------------------------------------------------------------------

def bulk_update_netflow(es_url: str, days: int, top_ports: list[dict],
                        dry_run: bool, verbose: bool) -> int:
    """
    Add app_name / app_category to netflow-* docs using update_by_query.
    Only processes top ports (by bytes) to limit ES load.
    Returns number of ports updated.
    """
    updated = 0
    # Process top 50 ports only to avoid overloading ES
    for entry in sorted(top_ports, key=lambda x: x["bytes"], reverse=True)[:50]:
        port = entry.get("port")
        app_name = entry.get("app_name", "Unknown")
        category = entry.get("category", "unknown")
        if not port or app_name == "Unknown":
            continue

        if dry_run:
            if verbose:
                print(f"  [DRY-RUN] update netflow-* port={port} → {app_name}/{category}")
            updated += 1
            continue

        body = {
            "script": {
                "source": (
                    "if (!ctx._source.containsKey('app_name')) { "
                    "ctx._source.app_name = params.a; "
                    "ctx._source.app_category = params.c; }"
                ),
                "lang":   "painless",
                "params": {"a": app_name, "c": category},
            },
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
                        {"term":  {"dst_port": port}},
                    ]
                }
            },
        }
        resp = es_request(es_url, "POST", f"/netflow-*/_update_by_query?conflicts=proceed", body, verbose)
        if "error" not in resp:
            n = resp.get("updated", 0)
            if verbose and n:
                print(f"  [netflow] port={port} {app_name} → updated {n} docs")
            updated += 1
        else:
            if verbose:
                print(f"  [netflow] update_by_query error port={port}: {resp.get('error')}", file=sys.stderr)

    return updated


# ---------------------------------------------------------------------------
# Aggregate and merge results
# ---------------------------------------------------------------------------

def merge_results(netflow_results: list[dict], zeek_results: list[dict]) -> list[dict]:
    """
    Merge netflow and zeek results, combining bytes/flows for the same app_name.
    Returns sorted list by bytes descending.
    """
    agg: dict[str, dict] = {}
    for item in netflow_results + zeek_results:
        key = item["app_name"]
        if key == "Unknown":
            continue
        if key not in agg:
            agg[key] = {
                "name":     key,
                "category": item["category"],
                "bytes":    0,
                "flows":    0,
            }
        agg[key]["bytes"] += item["bytes"]
        agg[key]["flows"] += item["flows"]

    return sorted(agg.values(), key=lambda x: x["bytes"], reverse=True)


def build_by_category(apps: list[dict]) -> list[dict]:
    """Aggregate bytes by category and compute percentages."""
    cat_agg: dict[str, int] = {}
    total = 0
    for a in apps:
        cat = a["category"]
        cat_agg[cat] = cat_agg.get(cat, 0) + a["bytes"]
        total += a["bytes"]

    result = []
    for cat, b in sorted(cat_agg.items(), key=lambda x: x[1], reverse=True):
        result.append({
            "cat":   cat,
            "bytes": b,
            "pct":   round(b / total * 100, 1) if total > 0 else 0.0,
        })
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="NetWatch App Classifier — enrichit les flux ES avec app_name/app_category."
    )
    parser.add_argument("--days", type=int, default=1,
                        help="Fenêtre d'analyse en jours (défaut: 1)")
    parser.add_argument("--output", "-o", default=str(DEFAULT_OUTPUT),
                        help=f"Fichier de sortie JSON (défaut: {DEFAULT_OUTPUT})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simuler sans écrire dans ES ni sur disque")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Afficher les détails de chaque étape")
    parser.add_argument("--es-url", default=DEFAULT_ES_URL,
                        help=f"URL Elasticsearch (défaut: {DEFAULT_ES_URL})")
    parser.add_argument("--no-update", action="store_true",
                        help="Ne pas faire de bulk update ES (lecture seule)")
    args = parser.parse_args()

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[app-classifier] {ts} | days={args.days} | ES={args.es_url}"
          + (" | DRY-RUN" if args.dry_run else ""))
    print(f"  PORT_APP_MAP : {len(PORT_APP_MAP)} entrées | "
          f"ZEEK_SERVICE_MAP : {len(ZEEK_SERVICE_MAP)} services")

    netflow_results: list[dict] = []
    zeek_results:    list[dict] = []

    # ------------------------------------------------------------------
    # [1/3] netflow-*
    # ------------------------------------------------------------------
    print(f"\n[1/3] Interrogation netflow-* (dst_port) — fenêtre {args.days}j")
    if index_exists(args.es_url, "netflow-*", args.verbose):
        netflow_results = query_netflow_by_port(args.es_url, args.days, args.verbose)
        print(f"  {len(netflow_results)} ports distincts trouvés")
        if netflow_results and not args.no_update:
            n = bulk_update_netflow(
                args.es_url, args.days, netflow_results,
                args.dry_run, args.verbose
            )
            print(f"  Bulk update : {n} port(s) mis à jour dans netflow-*")
    else:
        print("  SKIP: index netflow-* absent")

    # ------------------------------------------------------------------
    # [2/3] zeek-*
    # ------------------------------------------------------------------
    print(f"\n[2/3] Interrogation zeek-* (service + id.resp_p) — fenêtre {args.days}j")
    if index_exists(args.es_url, "zeek-*", args.verbose):
        zeek_results = query_zeek_by_service(args.es_url, args.days, args.verbose)
        print(f"  {len(zeek_results)} entrées application trouvées")
    else:
        print("  SKIP: index zeek-* absent")

    # ------------------------------------------------------------------
    # [3/3] Build output
    # ------------------------------------------------------------------
    print(f"\n[3/3] Génération app-flows-today.json")
    merged    = merge_results(netflow_results, zeek_results)
    top_apps  = merged[:10]
    by_cat    = build_by_category(merged)

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "days":         args.days,
        "total_apps":   len(merged),
        "top_apps":     top_apps,
        "by_category":  by_cat,
    }

    # Summary
    print(f"  Top applications :")
    for i, a in enumerate(top_apps[:5], 1):
        mb = a["bytes"] / (1024 * 1024)
        print(f"    {i:2d}. {a['name']:20s} [{a['category']:15s}] "
              f"{mb:8.1f} MB  {a['flows']:6d} flux")

    if args.dry_run:
        print(f"\n  [DRY-RUN] sortie JSON non écrite — aperçu :")
        print(json.dumps(output, indent=2)[:500])
        return

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"  Fichier écrit : {out_path}  ({out_path.stat().st_size} octets)")

    print(f"\n[app-classifier] Terminé — {len(merged)} applications classifiées")


if __name__ == "__main__":
    main()
