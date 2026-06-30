# Guide de déploiement NetWatch v2

> Version : 2.0 · Date : 2026-06-30 · Auteur : Infra-agent / Nicolas Malok

Guide complet pour déployer la stack NetWatch sur une VM Ubuntu 22.04,
en environnement **Proxmox** ou **ESXi** (lab Axians).

---

## Table des matières

1. [Prérequis](#1-prérequis)
2. [Déploiement rapide — 5 étapes](#2-déploiement-rapide)
3. [Configuration `.env`](#3-configuration-env)
4. [Validation post-déploiement](#4-validation-post-déploiement)
5. [Section Proxmox](#5-section-proxmox)
6. [Section ESXi (lab Axians)](#6-section-esxi-lab-axians)
7. [Troubleshooting — 10 erreurs fréquentes](#7-troubleshooting)
8. [Référence des services](#8-référence-des-services)

---

## 1. Prérequis

### Matériel minimum

| Ressource | Minimum | Recommandé |
|-----------|---------|------------|
| CPU       | 4 vCPU  | 8 vCPU     |
| RAM       | 8 Go    | 16 Go      |
| Disque    | 50 Go   | 200 Go SSD |
| Réseau    | 1 port  | 2 ports (1 mgmt + 1 capture) |

> **Note** : Elasticsearch est gourmand. En dessous de 8 Go de RAM, le cluster
> passe en yellow et les indexations peuvent échouer.

### OS

**Ubuntu Server 22.04 LTS** (Jammy Jellyfish) — seule distribution officiellement
testée. Les dérivés Debian 12 fonctionnent aussi mais sans garantie.

```bash
# Vérifier la version
lsb_release -a
# Ubuntu 22.04.x LTS
```

### Docker Engine + Compose v2

```bash
# Installer Docker (méthode officielle)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker

# Vérifier les versions
docker --version          # Docker 24.x ou supérieur
docker compose version    # Docker Compose version v2.x
```

> **Attention** : Ne pas utiliser `docker-compose` (v1, Python, obsolète).
> Utiliser `docker compose` (v2, intégré au CLI Docker).

### Outils complémentaires

```bash
sudo apt-get update && sudo apt-get install -y \
  git curl make python3 python3-pip jq tcpdump net-tools
```

---

## 2. Déploiement rapide

### Étape 1 — Cloner le dépôt

```bash
git clone https://github.com/Ourslow/netwatch.git
cd netwatch
```

### Étape 2 — Configurer l'environnement

```bash
cp .env.example .env
# Éditer les variables (voir section 3)
nano .env
```

### Étape 3 — Démarrer la stack

```bash
# Démarrer tous les services en arrière-plan
make start

# Vérifier que les conteneurs sont Up
make status
```

La première fois, Docker télécharge les images (~3-5 Go). Prévoir 10-20 min
selon la connexion.

### Étape 4 — Initialiser Elasticsearch

```bash
# Configure les templates d'index, le pipeline GeoIP, désactive les réplicas
bash setup-es.sh
```

> Cette étape est obligatoire avant que Filebeat puisse indexer correctement.
> À relancer après un `make clean` (reset des volumes).

### Étape 5 — Valider le déploiement

```bash
# Health check complet (12 services)
make health

# Vérifier les index ES
curl "http://localhost:9200/_cat/indices?v&s=index&h=index,docs.count"
```

Résultat attendu après quelques minutes de capture :

```
zeek-2026.06.30     449
snort-2026.06.30    4709
suricata-2026.06.30 26587
```

---

## 3. Configuration `.env`

Copier `.env.example` et adapter chaque variable :

```bash
# ============================================================
# Elasticsearch
# ============================================================
# Mot de passe superuser ES (à changer en prod)
ELASTIC_PASSWORD=changeme

# ============================================================
# Grafana
# ============================================================
GF_SECURITY_ADMIN_PASSWORD=netwatch

# ============================================================
# Portail Flask
# ============================================================
# Clé secrète Flask (générer une valeur aléatoire en prod)
FLASK_SECRET_KEY=change-me-in-production
PORTAL_USERNAME=admin
PORTAL_PASSWORD=netwatch
FLASK_DEBUG=false

# ============================================================
# Proxmox (optionnel — si le portail pilote des VMs Proxmox)
# ============================================================
PROXMOX_HOST=192.168.1.100
PROXMOX_USER=root@pam
PROXMOX_PASSWORD=
PROXMOX_NODE=pve
PROXMOX_VERIFY_SSL=false

# ============================================================
# Snort
# ============================================================
# IP de la machine à surveiller (pour les règles custom)
SNORT_MONITORED_SERVER=192.168.1.0/24

# ============================================================
# AutoBlock
# ============================================================
# DRY_RUN=true : simule les blocages sans modifier iptables
DRY_RUN=true

# ============================================================
# Ollama (LLM local)
# ============================================================
# Modèle par défaut
OLLAMA_MODEL=mistral
```

### Variables obligatoires

| Variable | Description | Exemple |
|----------|-------------|---------|
| `ELASTIC_PASSWORD` | Mot de passe ES | `changeme` |
| `GF_SECURITY_ADMIN_PASSWORD` | Mot de passe Grafana admin | `netwatch` |
| `FLASK_SECRET_KEY` | Clé session Flask | Chaîne aléatoire 32 chars |
| `PORTAL_PASSWORD` | Mot de passe portail | `netwatch` |
| `SNORT_MONITORED_SERVER` | Plage IP à surveiller | `192.168.1.0/24` |

---

## 4. Validation post-déploiement

### Checklist rapide

```bash
# 1. Tous les conteneurs Up
docker compose ps
# → 12 services, status Up

# 2. ES cluster green
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool
# → "status": "green"

# 3. Grafana accessible
curl -s http://localhost:3000/api/health
# → {"database":"ok","version":"10.4.0"}

# 4. Filebeat indexe
curl -s "http://localhost:9200/zeek-*/_count" | python3 -m json.tool
# → "count": > 0

# 5. Health check complet
make health
```

### Accès aux interfaces

| Service       | URL                           | Credentials        |
|---------------|-------------------------------|---------------------|
| Grafana       | http://localhost:3000         | admin / (env)       |
| Elasticsearch | http://localhost:9200         | elastic / (env)     |
| Prometheus    | http://localhost:9090         | -                   |
| Portail Flask | http://localhost:5050         | admin / (env)       |
| Ollama        | http://localhost:11434        | -                   |
| n8n           | http://localhost:5678         | (premier accès)     |

### Tester avec du trafic simulé

```bash
# Simuler 1h de trafic réseau avec attaques (injecte dans ES)
make sim-fast

# Ou rejouer un PCAP sur les 3 moteurs (Zeek + Snort + Suricata)
./replay-pcap.sh pcap/sample.pcap
```

---

## 5. Section Proxmox

### 5.1 Prérequis Proxmox

- Proxmox VE 8.x installé sur le serveur physique
- Accès à l'interface web (`https://<IP>:8006`)
- Un switch manageable avec support port SPAN (ou port miroir)

### 5.2 Création de la VM NetWatch

**Via l'interface web Proxmox :**

1. Clic droit sur le nœud → **Create VM**
2. **General** :
   - VM ID : `100` (ou suivant)
   - Name : `netwatch-sensors` (ou `netwatch-data` pour la VM ES/Grafana)
3. **OS** :
   - ISO Image : `ubuntu-22.04-live-server-amd64.iso` (à uploader dans le stockage)
   - Type : `Linux`, Version : `6.x - 2.6 Kernel`
4. **System** :
   - BIOS : `SeaBIOS` (ou OVMF pour UEFI)
   - Machine : `q35`
5. **Disks** :
   - Bus : `VirtIO SCSI`
   - Disque 1 : `50 Go` (racine) — SSD si disponible
6. **CPU** :
   - Sockets : `1`, Cores : `4` minimum
   - Type : `host` (meilleure performance)
7. **Memory** : `8192` Mo minimum (`16384` recommandé)
8. **Network** :
   - Bridge : `vmbr0` (management)
   - Model : `VirtIO (paravirtualized)`

**Ajouter une deuxième carte réseau pour la capture :**

9. Hardware → Add → Network Device :
   - Bridge : `vmbr1` (voir 5.3 pour la config SPAN)
   - Model : `VirtIO`
   - **Décocher** "Firewall" (mode promiscuité requis)

**Finir l'installation :**

```bash
# Une fois Ubuntu installé et SSH accessible
ssh ubuntu@<IP_VM>
# Suivre les étapes 1-5 du déploiement rapide
```

### 5.3 Configuration réseau bridge + port SPAN

**Sur Proxmox (côté hyperviseur) :**

```bash
# /etc/network/interfaces sur le nœud Proxmox
# Interface de management
auto vmbr0
iface vmbr0 inet static
    address 192.168.1.10/24
    gateway 192.168.1.1
    bridge-ports eno1
    bridge-stp off
    bridge-fd 0

# Bridge de capture (mode promiscuité)
auto vmbr1
iface vmbr1 inet manual
    bridge-ports eno2
    bridge-stp off
    bridge-fd 0
    bridge-promisc vmbr1
```

Appliquer sans reboot :

```bash
ifreload -a
# Vérifier
brctl show vmbr1
```

**Sur le switch manageable (exemple Cisco) :**

```bash
# Configurer le port SPAN
monitor session 1 source interface GigabitEthernet0/1 both
monitor session 1 destination interface GigabitEthernet0/24
# GigabitEthernet0/24 → câblé vers eno2 du serveur Proxmox
```

**Activer le mode promiscuité dans la VM :**

```bash
# Dans la VM NetWatch (Ubuntu 22.04)
# eth1 = interface de capture (vmbr1)
sudo ip link set eth1 promisc on

# Rendre permanent via /etc/network/interfaces.d/
cat <<EOF | sudo tee /etc/network/interfaces.d/capture
auto eth1
iface eth1 inet manual
    up ip link set eth1 promisc on
    up ip link set eth1 up
EOF
```

**Configurer l'interface de capture dans docker-compose.yml :**

Vérifier que Zeek, Snort et Suricata utilisent la bonne interface :

```bash
# Dans le .env
CAPTURE_INTERFACE=eth1
```

### 5.4 Vérification capture réseau

```bash
# Vérifier que du trafic arrive sur l'interface de capture
sudo tcpdump -i eth1 -c 10
# → doit afficher des paquets du réseau capturé

# Vérifier que Zeek détecte du trafic
docker logs netwatch-zeek --tail 20
# → "Listening on eth1"
```

---

## 6. Section ESXi (lab Axians)

### 6.1 Prérequis ESXi

- ESXi 7.x ou 8.x installé sur le serveur physique
- Accès vSphere Client (`https://<IP_ESXI>/ui`) ou vCenter
- Un vSwitch configuré en mode promiscuité pour la capture

### 6.2 Création de la VM NetWatch

**Via le vSphere Client :**

1. **Create / Register VM** → **Create a new virtual machine**
2. **Select creation type** : Create a new virtual machine
3. **Select a name and guest OS** :
   - Name : `netwatch-v2`
   - Guest OS Family : `Linux`
   - Guest OS Version : `Ubuntu Linux (64-bit)`
4. **Select storage** : Datastore local ou NFS partagé, `50 Go` minimum
5. **Customize settings** :
   - **CPU** : 4 vCPU (cocher "Expose hardware assisted virtualization to the guest OS")
   - **Memory** : 8192 MB (cocher "Reserve all guest memory")
   - **Hard disk** : 50 GB, `Thick provision lazy zeroed` (meilleures perf I/O)
   - **Network adapter 1** : VM Network (management) — `VMXNET3`
   - **Add network adapter 2** : vSwitch de capture (voir 6.3) — `VMXNET3`
   - **CD/DVD drive** : ISO Ubuntu 22.04 depuis le datastore

### 6.3 Configuration vSwitch + port SPAN

**Créer un vSwitch dédié à la capture :**

1. Host → Networking → Virtual Switches → Add standard virtual switch
   - vSwitch Name : `vSwitch-Capture`
   - **Aucun uplink** (ou l'uplink physique branché au port SPAN du switch)
2. Sécurité du vSwitch (critique pour la capture) :
   - Promiscuous Mode : **Accept**
   - MAC Address Changes : **Accept**
   - Forged Transmits : **Accept**
3. Créer un **Port Group** sur ce vSwitch :
   - Name : `NetWatch-Capture`
   - VLAN ID : `0` (ou le VLAN du trafic à capturer)

**Sur le switch physique (exemple HP/Aruba) :**

```
# Port SPAN : copie le trafic du port 1-10 vers le port 24
# (branché sur le NIC de capture du serveur ESXi)
mirror ethernet 1-10 monitored-ports ethernet 24
```

**Configurer l'interface de capture dans la VM :**

```bash
# Dans la VM Ubuntu (ESXi) — eth0 = management, eth1 = capture
sudo ip link set eth1 promisc on
sudo ip link set eth1 up

# Vérifier
sudo tcpdump -i eth1 -c 5
# → doit afficher du trafic réseau
```

### 6.4 Considérations spécifiques lab Axians

- **VLAN** : Le trafic du lab peut être taggé VLAN. Configurer l'interface de capture
  pour recevoir les trames taguées (`ip link add link eth1 name eth1.100 type vlan id 100`)
- **Bande passante** : Un port SPAN 1 Gbps sur un réseau actif peut saturer.
  Limiter le SPAN aux VLANs pertinents.
- **Stockage** : Sur ESXi partagé (vCenter), préférer un datastore NFS dédié
  pour les volumes Elasticsearch (écriture intensive).
- **Firewall** : Ouvrir les ports `9200`, `3000`, `9090`, `5050`, `5678`, `11434`
  entre la VM et les postes d'administration.

```bash
# UFW sur la VM NetWatch (ajuster selon votre plage d'admin)
sudo ufw allow from 192.168.10.0/24 to any port 3000   # Grafana
sudo ufw allow from 192.168.10.0/24 to any port 5050   # Portail
sudo ufw allow from 192.168.10.0/24 to any port 9200   # ES (restreindre en prod)
sudo ufw enable
```

---

## 7. Troubleshooting

### Erreur 1 — Elasticsearch ne démarre pas (Out of Memory)

**Symptôme :**

```
netwatch-elasticsearch exited with code 137
```

**Cause :** JVM heap trop élevé ou mémoire système insuffisante.

**Solution :**

```bash
# Vérifier la RAM disponible
free -h

# Réduire le heap ES dans docker-compose.yml
# Rechercher la ligne ES_JAVA_OPTS et passer à 512m/1g minimum
ES_JAVA_OPTS: "-Xms1g -Xmx1g"

# Augmenter vm.max_map_count (obligatoire pour ES 8.x)
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### Erreur 2 — Filebeat : "data_stream must be enabled" ou indexation échoue

**Symptôme :**

```
{"type":"illegal_argument_exception","reason":"data_stream must be enabled"}
```

**Cause :** Templates ES absents ou conflit data-stream (bug connu T_002).

**Solution :**

```bash
# Réinitialiser et recréer les templates
bash setup-es.sh

# Redémarrer Filebeat
docker compose restart filebeat
docker logs netwatch-filebeat --tail 30
# → "Connection established"
```

Voir `docs/filebeat-fix.md` pour l'analyse complète.

### Erreur 3 — Snort ne démarre pas (library not found)

**Symptôme :**

```
netwatch-snort exited with code 1
docker logs netwatch-snort → "error while loading shared libraries: libdaq.so"
```

**Cause :** Image Snort 3 compilée depuis les sources — rebuild nécessaire.

**Solution :**

```bash
# Rebuild complet de l'image Snort
make build SVC=snort
# Le build prend 10-15 min (compile libdaq + snort depuis les sources)
```

### Erreur 4 — Grafana : "datasource not found"

**Symptôme :** Dashboards vides, erreur "datasource ES not found" dans Grafana.

**Cause :** Les datasources sont provisionnées au démarrage ; ES non encore accessible.

**Solution :**

```bash
# Attendre qu'ES soit healthy puis redémarrer Grafana
docker compose restart grafana

# Vérifier les datasources via API
curl -s http://admin:netwatch@localhost:3000/api/datasources | python3 -m json.tool
```

### Erreur 5 — Port 9200 inaccessible depuis l'extérieur

**Symptôme :** `curl http://<VM_IP>:9200` timeout depuis la machine hôte.

**Cause :** UFW ou règles iptables bloquent le port.

**Solution :**

```bash
# Vérifier UFW
sudo ufw status
sudo ufw allow 9200/tcp

# Vérifier que ES écoute sur 0.0.0.0 (et pas seulement 127.0.0.1)
ss -tlnp | grep 9200
# → 0.0.0.0:9200
```

> **Attention** : N'exposer ES sur l'extérieur qu'en environnement de lab.
> En production, placer un reverse-proxy nginx devant avec auth basique.

### Erreur 6 — CrowdSec : "cscli: not found"

**Symptôme :** `make health` indique CrowdSec en erreur, `cscli` absent.

**Cause :** Le container `netwatch-crowdsec` n'est pas lancé ou l'image est corrompue.

**Solution :**

```bash
docker compose ps crowdsec
# Si "Exit 1" :
docker compose logs crowdsec --tail 30
docker compose up -d crowdsec

# Vérifier les collections installées
docker exec netwatch-crowdsec cscli hub list
```

### Erreur 7 — Zeek : "No packets received" (interface de capture vide)

**Symptôme :** Aucun log dans `/zeek-logs/`, ES sans index `zeek-*`.

**Cause :** Mauvaise interface de capture configurée.

**Solution :**

```bash
# Lister les interfaces disponibles dans le container
docker exec netwatch-zeek ip link show

# Tester la capture sur l'interface
docker exec netwatch-zeek tcpdump -i eth1 -c 5

# Corriger dans docker-compose.yml
# Changer l'interface de capture de eth0 à eth1 (ou l'interface correcte)
```

### Erreur 8 — n8n : base de données SQLite corrompue

**Symptôme :** n8n redémarre en boucle, logs `database disk image is malformed`.

**Cause :** Volume Docker corrompu (arrêt brutal du container).

**Solution :**

```bash
# Arrêter n8n
docker compose stop n8n

# Sauvegarder le volume si possible
docker run --rm -v netwatch_n8n_data:/data -v $(pwd):/backup \
  ubuntu tar czf /backup/n8n-backup-$(date +%Y%m%d).tar.gz /data

# Recréer le volume (perte des workflows !)
docker compose down n8n
docker volume rm netwatch_n8n_data
docker compose up -d n8n
```

Importer ensuite les workflows depuis `scripts/automation/*.json`.

### Erreur 9 — make health : "Filebeat 0 docs (inactif?)"

**Symptôme :** Health check montre Filebeat en warning, 0 docs récents.

**Cause :** Aucun trafic réseau sur l'interface de capture, ou Zeek/Snort/Suricata arrêtés.

**Solution :**

```bash
# Vérifier que les capteurs tournent
docker compose ps zeek snort suricata
# → tous "Up"

# Générer du trafic test
make sim-fast

# Ou rejouer un PCAP
./replay-pcap.sh pcap/sample.pcap

# Vérifier que des docs apparaissent
curl -s "http://localhost:9200/zeek-*/_count"
```

### Erreur 10 — Portail Flask : "500 Internal Server Error"

**Symptôme :** http://localhost:5050 retourne une erreur 500.

**Cause :** Variable d'environnement manquante ou ES inaccessible.

**Solution :**

```bash
# Voir les logs du portail
make portal-log
# → chercher la ligne "Error" ou la traceback Python

# Vérifier que .env est bien chargé
cat .env | grep FLASK

# Vérifier la connexion ES depuis le portail
docker exec netwatch-elasticsearch curl -sf http://localhost:9200/_cluster/health

# Redémarrer le portail
make portal-stop && make portal
```

---

## 8. Référence des services

| Service        | Container              | Port(s)       | Image                              |
|----------------|------------------------|---------------|------------------------------------|
| Zeek           | netwatch-zeek          | -             | custom (Dockerfile.zeek)           |
| Snort          | netwatch-snort         | -             | custom (Dockerfile.snort)          |
| Suricata       | netwatch-suricata      | -             | jasonish/suricata                  |
| Filebeat       | netwatch-filebeat      | -             | docker.elastic.co/beats/filebeat   |
| Elasticsearch  | netwatch-elasticsearch | 9200          | docker.elastic.co/elasticsearch/.. |
| Prometheus     | netwatch-prometheus    | 9090          | prom/prometheus                    |
| Node Exporter  | netwatch-node-exporter | 9100          | prom/node-exporter                 |
| Grafana        | netwatch-grafana       | 3000          | grafana/grafana                    |
| Beacon-detect  | netwatch-beacon-detect | -             | custom (autoblock/)                |
| AutoBlock      | netwatch-autoblock     | 5001          | custom (autoblock/)                |
| CrowdSec       | netwatch-crowdsec      | 8080, 6060    | crowdsecurity/crowdsec             |
| n8n            | netwatch-n8n           | 5678          | n8nio/n8n                          |
| Ollama         | netwatch-ollama        | 11434         | ollama/ollama                      |
| Portail Flask  | (systemd / make portal)| 5050          | Python 3 (portal/app.py)           |

### Commandes de maintenance utiles

```bash
# Voir l'état de tous les services
make status

# Logs d'un service spécifique
make logs SVC=zeek

# Redémarrer un service
make restart SVC=elasticsearch

# Health check complet
make health

# Mettre à jour les listes threat intel Zeek
make update-intel

# Supprimer le stack ET les données (irréversible)
make clean

# Télécharger un modèle LLM dans Ollama
make llm-pull MODEL=llama3
```
