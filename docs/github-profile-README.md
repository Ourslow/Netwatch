# Hi, je suis Nicolas 👋

**Analyste Observabilité NPM** @ [Axians / Vinci Energies](https://www.axians.fr) · France  
École 2600 — Cybersécurité, promotion 2024-2027

---

### 🔭 Projet principal — NetWatch v2

Stack d'observabilité réseau open-source qui reproduit les fonctionnalités clés d'un outil NPM commercial (type Netscout nGeniusONE) avec des briques 100 % open-source.

**3 moteurs d'analyse en parallèle sur le même trafic :**

```
Trafic réseau (SPAN / PCAP)
        ↓
   ┌────┼────┐
  Zeek Snort Suricata   ← analyse protocolaire + IDS signatures
   └────┼────┘
     Filebeat → Elasticsearch → Grafana (11 dashboards)
```

[![NetWatch](https://img.shields.io/badge/NetWatch-v2.0-blue?style=flat-square&logo=github)](https://github.com/Ourslow/Netwatch)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-green?style=flat-square)](https://www.gnu.org/licenses/agpl-3.0)
[![Stack](https://img.shields.io/badge/Stack-10%20services-informational?style=flat-square)](https://github.com/Ourslow/Netwatch)

**Ce que ça détecte :**
- Beaconing C2 (coefficient de variation des intervalles)
- Fingerprinting JA3 / HASSH (TLS/SSH malveillants)
- Mapping MITRE ATT&CK (Suricata + Snort)
- DNS tunneling, longues connexions, threat intel (Feodo / URLhaus)
- Blocage automatique iptables via webhook Flask (AutoBlock)

---

### 🛠️ Stack technique

![Zeek](https://img.shields.io/badge/Zeek-6.2-2b6cb0?style=flat-square)
![Snort](https://img.shields.io/badge/Snort-3.3.5-red?style=flat-square)
![Suricata](https://img.shields.io/badge/Suricata-7-orange?style=flat-square)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.13-005571?style=flat-square&logo=elasticsearch)
![Grafana](https://img.shields.io/badge/Grafana-10.4-F46800?style=flat-square&logo=grafana)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask)
![Prometheus](https://img.shields.io/badge/Prometheus-2.x-E6522C?style=flat-square&logo=prometheus)

---

### 📊 Stats

![GitHub stats](https://github-readme-stats.vercel.app/api?username=Ourslow&show_icons=true&theme=github_dark&hide_border=true&count_private=true)

---

### 📫 Contact

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Nicolas%20Malok-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/nicolas-malok)
[![Email](https://img.shields.io/badge/Email-nicolas.malokpro%40gmail.com-EA4335?style=flat-square&logo=gmail)](mailto:nicolas.malokpro@gmail.com)
