"""
Référentiel NIS2 — mapping des mesures techniques de NetWatch sur l'article 21.2.
Utilisé par le rapport exécutif (/report, édition Community) ; la page
Conformité multi-référentiels (NIST, ANSSI, ISO 27001) est dans l'édition Pro.
"""

# ============================================================
# Matrice NIS2 — mapping mesures techniques NetWatch ↔ article 21.2
# Couverture : "full" | "partial" | "none" (honnête : NetWatch est un outil
# de détection/réponse réseau, pas une suite GRC complète)
# ============================================================

NIS2_MATRIX = [
    {"ref": "Art. 21.2 (a)", "title": "Analyse des risques & politiques de sécurité des SI",
     "coverage": "partial",
     "netwatch": "Visibilité réseau continue (top-talkers, services exposés, GeoIP) et threat intel alimentent l'analyse de risque. NetWatch n'édite pas les politiques elles-mêmes.",
     "components": ["Dashboards", "Threat Intel", "GeoIP"]},
    {"ref": "Art. 21.2 (b)", "title": "Gestion des incidents — détection & réponse",
     "coverage": "full",
     "netwatch": "Cœur de NetWatch : détection multi-moteurs (Snort 3 + Suricata 7) sur le même trafic, corrélation, mapping MITRE ATT&CK, alerting temps réel et réponse automatique (AutoBlock iptables). Détection de beaconing C2 et de DNS tunneling (RITA-lite).",
     "components": ["Snort 3", "Suricata 7", "AutoBlock", "beacon-detect", "MITRE ATT&CK", "Grafana alerting"]},
    {"ref": "Art. 21.2 (c)", "title": "Continuité d'activité & gestion de crise (sauvegarde, PRA)",
     "coverage": "none",
     "netwatch": "Hors périmètre : NetWatch ne gère ni sauvegarde ni plan de reprise. Apporte indirectement la supervision de disponibilité pour détecter une indisponibilité de service.",
     "components": ["Prometheus (disponibilité)"]},
    {"ref": "Art. 21.2 (d)", "title": "Sécurité de la chaîne d'approvisionnement",
     "coverage": "partial",
     "netwatch": "Détecte les communications sortantes suspectes (C2, domaines DGA), fingerprinting JA3/HASSH des clients/serveurs, threat intel sur IoC. Ne couvre pas l'évaluation contractuelle des fournisseurs.",
     "components": ["JA3/HASSH", "Threat Intel", "beacon-detect"]},
    {"ref": "Art. 21.2 (e)", "title": "Sécurité acquisition/dév./maintenance & vulnérabilités",
     "coverage": "partial",
     "netwatch": "Détecte les tentatives d'exploitation via signatures IDS (Snort community + Suricata ET Open). Ne réalise pas de scan de vulnérabilités ni de gestion du cycle de développement.",
     "components": ["Snort 3", "Suricata 7 (ET Open)"]},
    {"ref": "Art. 21.2 (f)", "title": "Évaluation de l'efficacité des mesures",
     "coverage": "partial",
     "netwatch": "Dashboards, métriques et rapport exécutif (avec résumé IA) donnent une mesure objective de l'activité de détection et de la posture de sécurité. Pas d'audit de conformité formalisé.",
     "components": ["Dashboards", "Rapport exécutif", "Assistant IA"]},
    {"ref": "Art. 21.2 (g)", "title": "Cyber-hygiène & formation",
     "coverage": "partial",
     "netwatch": "Met en évidence les mauvaises pratiques (identifiants en clair sur HTTP, TLS obsolète) — support concret de sensibilisation. Ne dispense pas la formation elle-même.",
     "components": ["Règles NETWATCH custom"]},
    {"ref": "Art. 21.2 (h)", "title": "Cryptographie & chiffrement",
     "coverage": "partial",
     "netwatch": "Détecte le chiffrement faible/obsolète (TLSv1.0, certificats expirés) et l'absence de chiffrement (mots de passe en clair). N'impose pas de politique cryptographique.",
     "components": ["Zeek SSL/TLS", "Règles TLS custom"]},
    {"ref": "Art. 21.2 (i)", "title": "Contrôle d'accès & gestion des actifs",
     "coverage": "partial",
     "netwatch": "Inventaire passif des actifs et services vus sur le réseau (known-hosts, known-services). Le portail applique lui-même un contrôle d'accès (auth, cookies durcis). Pas de gestion IAM.",
     "components": ["Zeek known-hosts/services", "Portail (Flask-Login)"]},
    {"ref": "Art. 21.2 (j)", "title": "MFA & communications sécurisées",
     "coverage": "none",
     "netwatch": "Hors périmètre côté SI surveillé. À noter : l'assistant IA et toute la stack sont 100 % on-prem — souveraineté des données, aucune donnée ne sort du SI.",
     "components": ["—"]},
]
