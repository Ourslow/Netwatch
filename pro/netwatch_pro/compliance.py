"""
Conformité multi-référentiels (édition Pro) — page /compliance.

NIS2 vient du portail Community (netwatch.referentials, aussi utilisé par le
rapport exécutif) ; NIST CSF 2.0, ANSSI et ISO 27001 sont propres à l'édition Pro.
"""
from flask import render_template

from netwatch.referentials import NIS2_MATRIX

# NIST Cybersecurity Framework 2.0 — par fonction (NetWatch = NDR → fort sur Detect/Respond)
NIST_CSF_MATRIX = [
    {"ref": "GV — Govern", "title": "Gouvernance de la cybersécurité",
     "coverage": "partial",
     "netwatch": "Dashboards, métriques et rapport exécutif alimentent le pilotage et la prise de décision. NetWatch n'édite pas la stratégie ni les politiques.",
     "components": ["Dashboards", "Rapport exécutif"]},
    {"ref": "ID — Identify", "title": "Connaissance du contexte et des actifs",
     "coverage": "partial",
     "netwatch": "Inventaire passif des actifs et services observés sur le réseau (known-hosts/services), threat intel sur IoC. Pas de gestion d'inventaire formelle.",
     "components": ["Zeek known-hosts/services", "Threat Intel", "GeoIP"]},
    {"ref": "PR — Protect", "title": "Mesures de protection",
     "coverage": "partial",
     "netwatch": "Détecte les faiblesses (crypto obsolète, identifiants en clair) ; le portail applique un contrôle d'accès durci. NetWatch ne protège pas activement (ni pare-feu, ni IAM).",
     "components": ["Règles TLS custom", "Portail (Flask-Login)"]},
    {"ref": "DE — Detect", "title": "Détection des événements et anomalies",
     "coverage": "full",
     "netwatch": "Cœur de NetWatch : surveillance continue multi-moteurs (Snort + Suricata), détection d'anomalies (beaconing C2, DNS tunneling), corrélation et mapping MITRE ATT&CK.",
     "components": ["Snort 3", "Suricata 7", "beacon-detect", "MITRE ATT&CK", "Zeek"]},
    {"ref": "RS — Respond", "title": "Réponse aux incidents",
     "coverage": "full",
     "netwatch": "Alerting temps réel, blocage automatique des IP malveillantes (AutoBlock), et assistant IA qui explique chaque alerte pour accélérer l'analyse et la décision.",
     "components": ["Grafana alerting", "AutoBlock", "Assistant IA"]},
    {"ref": "RC — Recover", "title": "Reprise après incident",
     "coverage": "none",
     "netwatch": "Hors périmètre : NetWatch ne gère pas la restauration ni la reprise d'activité.",
     "components": ["—"]},
]

# ANSSI — Guide d'hygiène informatique + recommandations détection (PA-022)
ANSSI_MATRIX = [
    {"ref": "Hygiène · journalisation", "title": "Journaliser, analyser et corréler les événements",
     "coverage": "full",
     "netwatch": "Logs JSON normalisés des 3 moteurs centralisés dans Elasticsearch, corrélation multi-moteurs et tableaux de bord Grafana — répond directement à l'exigence de journalisation/analyse.",
     "components": ["Zeek", "Filebeat", "Elasticsearch", "Grafana"]},
    {"ref": "PA-022 · détection", "title": "Supervision de sécurité & détection des comportements anormaux",
     "coverage": "full",
     "netwatch": "Détection par signatures (Snort/Suricata) et comportementale (beaconing, DNS tunneling, scans). Couvre la logique d'une sonde de détection réseau recommandée par l'ANSSI.",
     "components": ["Snort 3", "Suricata 7", "beacon-detect"]},
    {"ref": "Hygiène · cartographie", "title": "Connaître le SI et maîtriser les flux réseau",
     "coverage": "partial",
     "netwatch": "Cartographie passive des flux, services et destinations externes (GeoIP, top-talkers). N'impose pas le cloisonnement.",
     "components": ["Zeek", "GeoIP", "Top-talkers"]},
    {"ref": "Hygiène · incidents", "title": "Gérer les incidents de sécurité",
     "coverage": "partial",
     "netwatch": "Détection, alerting et réponse automatique (AutoBlock) + aide à l'analyse par l'IA. Ne formalise pas le processus complet de gestion d'incident.",
     "components": ["AutoBlock", "Assistant IA"]},
    {"ref": "Hygiène · chiffrement", "title": "Chiffrer les flux sensibles",
     "coverage": "partial",
     "netwatch": "Détecte les protocoles obsolètes (TLSv1.0) et les flux en clair (mots de passe HTTP). N'impose pas le chiffrement.",
     "components": ["Zeek SSL/TLS", "Règles custom"]},
    {"ref": "Hygiène · sauvegarde", "title": "Sauvegarder et assurer la continuité",
     "coverage": "none",
     "netwatch": "Hors périmètre.",
     "components": ["—"]},
    {"ref": "Hygiène · authentification", "title": "Authentification forte (MFA)",
     "coverage": "none",
     "netwatch": "Hors périmètre côté SI surveillé.",
     "components": ["—"]},
]

# ISO/IEC 27001 / 27002:2022 — contrôles de l'Annexe A pertinents
ISO27001_MATRIX = [
    {"ref": "A.5.7", "title": "Renseignement sur les menaces (threat intelligence)",
     "coverage": "full",
     "netwatch": "Zeek Intel Framework (watchlists IP/domaines) + signatures ET Open : intègre et exploite le renseignement sur les menaces.",
     "components": ["Zeek Intel", "Suricata ET Open"]},
    {"ref": "A.8.15", "title": "Journalisation (logging)",
     "coverage": "full",
     "netwatch": "Journalisation centralisée et structurée de l'activité réseau et des détections dans Elasticsearch.",
     "components": ["Filebeat", "Elasticsearch"]},
    {"ref": "A.8.16", "title": "Activités de surveillance (monitoring)",
     "coverage": "full",
     "netwatch": "Surveillance continue du trafic et des anomalies par les 3 moteurs, dashboards temps réel et alerting.",
     "components": ["Snort 3", "Suricata 7", "Grafana"]},
    {"ref": "A.8.20", "title": "Sécurité des réseaux",
     "coverage": "partial",
     "netwatch": "Visibilité et détection sur les réseaux ; ne réalise pas la segmentation ni le filtrage actif (hors blocage AutoBlock).",
     "components": ["Zeek", "AutoBlock"]},
    {"ref": "A.5.25", "title": "Évaluation et décision sur les événements de sécurité",
     "coverage": "partial",
     "netwatch": "Corrélation, scoring de sévérité et triage des alertes ; explication IA pour aider à la décision.",
     "components": ["Corrélation", "Assistant IA"]},
    {"ref": "A.5.26", "title": "Réponse aux incidents de sécurité",
     "coverage": "partial",
     "netwatch": "Alerting et réponse automatisée (AutoBlock). Ne couvre pas l'ensemble du cycle de gestion d'incident.",
     "components": ["Grafana alerting", "AutoBlock"]},
    {"ref": "A.8.24", "title": "Utilisation de la cryptographie",
     "coverage": "partial",
     "netwatch": "Détecte le chiffrement faible/obsolète et les certificats expirés. N'applique pas de politique cryptographique.",
     "components": ["Zeek SSL/TLS"]},
    {"ref": "A.5.9", "title": "Inventaire des actifs",
     "coverage": "partial",
     "netwatch": "Inventaire passif des hôtes et services vus sur le réseau. Pas de CMDB.",
     "components": ["Zeek known-hosts/services"]},
]

# Référentiels exposés sur la page /compliance
REFERENTIALS = [
    {"id": "nis2",  "name": "NIS2",
     "label": "Directive UE 2022/2555 — art. 21.2",
     "intro": "Les 10 mesures techniques et organisationnelles minimales imposées aux entités essentielles et importantes.",
     "measures": NIS2_MATRIX},
    {"id": "nist",  "name": "NIST CSF 2.0",
     "label": "Cadre international — 6 fonctions",
     "intro": "NetWatch est une solution NDR : il couvre pleinement les fonctions Detect et Respond, cœur de la lutte contre les incidents.",
     "measures": NIST_CSF_MATRIX},
    {"id": "anssi", "name": "ANSSI",
     "label": "Guide d'hygiène + PA-022 (détection)",
     "intro": "Référentiel français de référence : NetWatch répond directement aux exigences de journalisation, supervision et détection.",
     "measures": ANSSI_MATRIX},
    {"id": "iso",   "name": "ISO/IEC 27001 · 27002:2022",
     "label": "Contrôles de l'Annexe A",
     "intro": "Contrôles de sécurité que les organisations certifient : NetWatch outille directement la journalisation, la surveillance et le renseignement sur les menaces.",
     "measures": ISO27001_MATRIX},
]


def _summary(measures):
    return {
        "full":    sum(1 for m in measures if m["coverage"] == "full"),
        "partial": sum(1 for m in measures if m["coverage"] == "partial"),
        "none":    sum(1 for m in measures if m["coverage"] == "none"),
        "total":   len(measures),
    }


def register(bp, api):
    @bp.route("/compliance")
    @api.login_required
    @api.pro_required("compliance")
    def compliance():
        referentials = [{**r, "summary": _summary(r["measures"])} for r in REFERENTIALS]
        return render_template("pro/compliance.html", referentials=referentials)

    api.add_nav("infra", "Conformité", "pro.compliance", "bi-clipboard2-check", i18n="nav_compliance")
    api.add_command("Conformité", "/compliance", "bi-clipboard2-check", hint="NIS2 · NIST · ISO")
