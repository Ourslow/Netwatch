"""
NetWatch — extension de l'édition Pro.

Paquet chargé par le portail Community (netwatch.extensions) au démarrage :
`register(api)` enregistre un blueprint `pro` (routes, templates), les entrées
de menu et les cartes de statut. Fonctions : assistant IA, rapports PDF,
conformité multi-référentiels, comptes nominatifs et rôles. Destiné au dépôt privé `netwatch-pro` ; vit
dans pro/ du dépôt Community pendant la phase de validation.

Contrat avec le portail : voir docs/edition-pro.md. Les templates sont sous
templates/pro/ (préfixe obligatoire pour ne pas masquer ceux du portail).
"""
import os

from flask import Blueprint

from . import compliance, ia, rbac, reports

__version__ = "0.1.0"
FEATURES = ("ia", "reports", "compliance", "rbac")


def register(api):
    bp = Blueprint("pro", __name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"))
    ia.register(bp, api)
    reports.register(bp, api)
    compliance.register(bp, api)
    rbac.register(bp, api)
    api.register_blueprint(bp)
    api.describe("netwatch-pro", __version__, FEATURES)
