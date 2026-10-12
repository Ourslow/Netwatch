# netwatch_pro — extension de l'édition Pro

Paquet Python chargé par le portail NetWatch Community au démarrage
(`portal/netwatch/extensions.py`). Il vit ici, dans `pro/`, pendant la phase de validation
terrain ; il est destiné au dépôt privé `netwatch-pro`. Contrat, recherche du paquet,
déploiement chez un client et procédure de split : [`docs/edition-pro.md`](../docs/edition-pro.md).

```
pro/netwatch_pro/
  __init__.py        register(api) : blueprint « pro », menu, cartes de statut ; __version__, FEATURES
  ia.py              /api/explain, /api/summary, /api/pcap-analysis/explain ; ai_enabled ; carte LLMOps
  llm_client.py      client Ollama (100 % on-prem) + journalisation LLMOps
  llmops.py          agrégation des appels IA (page Statut)
  reports.py         /reports, /api/reports/generate, /reports/download/<pdf>
  compliance.py      /compliance — NIST CSF 2.0, ANSSI, ISO 27001 (NIS2 vient du portail)
  templates/pro/     reports.html, compliance.html, _status_llmops.html
```

Règles :

- Templates toujours sous `templates/pro/` (jamais le même nom qu'un template du portail).
- Mêmes conventions que le portail : nonce CSP sur tout `<script>` inline, pas de `onclick=`,
  `ruff` propre (`make lint`), aucune mention d'employeur / école / client.
- Toute route Pro passe par `api.login_required` ; celles qui comptent pour la licence par
  `api.pro_required("<fonction>")` avec une clé de `netwatch.license.PRO_FEATURES`.
- Le paquet peut importer `config` et `netwatch.*` du portail, jamais `app` (import circulaire).
