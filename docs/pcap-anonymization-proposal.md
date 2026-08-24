# NetWatch — Proposition d'anonymisation PCAP

Point bloquant identifié en réunion du 2026-07-10, à valider avec Frédéric
Lemal (RSSI) avant toute implémentation. Ce document est la base de
discussion, pas une implémentation — l'objectif est d'avoir quelque chose
de concret à soumettre plutôt que de partir d'une page blanche.

## Ce qui doit être anonymisé

| Donnée | Sensible ? | Traitement recommandé |
|---|---|---|
| Adresses IP source/destination | Oui — identifie l'infrastructure client | Anonymisation **préservant les préfixes** (voir ci-dessous) |
| Adresses MAC | Oui — identifie le matériel/vendeur | Anonymisation ou troncature |
| Payload applicatif (contenu réel des paquets) | Oui — peut contenir des données métier/utilisateur | Troncature (snaplen réduit) plutôt qu'anonymisation — NetWatch analyse les métadonnées de flux (Zeek/NetFlow), pas le contenu applicatif complet |
| Noms de domaine / requêtes DNS | Partiellement | À évaluer au cas par cas — utile pour la détection (DGA, tunneling) mais peut révéler l'activité du client |

## Technique recommandée : anonymisation préservant les préfixes (CryptoPAn)

**Pourquoi pas une anonymisation aléatoire simple ?** Une IP remplacée par
une valeur aléatoire casse toute analyse de topologie réseau (on ne peut
plus dire que deux IPs anonymisées appartiennent au même sous-réseau) — ce
qui rend l'audit NetWatch inutile (cartographie réseau, top talkers, etc.
deviennent illisibles).

**CryptoPAn** (Cryptography-based Prefix-preserving Anonymization) est la
référence du domaine (utilisée notamment dans la recherche académique sur
les traces réseau) : deux IPs du même sous-réseau réel restent dans le même
sous-réseau anonymisé, mais il est cryptographiquement infaisable de
retrouver l'IP réelle sans la clé. C'est très probablement le mécanisme
qu'utilise Allegro (à confirmer avec Rodolphe/le fournisseur).

## Mise en œuvre technique (deux options)

**Option A — `tcprewrite` (le plus rapide à mettre en place)**
Déjà dans l'outillage prévu (tcpdump/tcpreplay évoqués en réunion pour la
génération de trafic de test). `tcprewrite` intègre une option
`--pnat=<ancien-préfixe>:<nouveau-préfixe>` pour de l'anonymisation par
préfixe. Simple, rapide, pas de dépendance supplémentaire.

**Option B — script Python dédié (`scapy` + `pycryptopan`)**
Plus de contrôle (anonymiser sélectivement IP/MAC, tronquer le payload,
logguer ce qui a été fait pour audit), s'intègre proprement dans le repo
NetWatch aux côtés des autres scripts Python existants. Recommandé si on
veut industrialiser ça comme une étape standard du pipeline plutôt qu'une
manip ponctuelle.

## Où l'insérer dans le pipeline

```
PCAP brut (jamais stocké ni partagé)
        ↓
  anonymize-pcap.(sh|py)   ← étape obligatoire, avant tout stockage
        ↓
  PCAP anonymisé            ← seul artefact qui touche Elasticsearch/disque
        ↓
  Zeek / Snort / Suricata
```

## Gestion de la clé d'anonymisation

- **Anonymisation pure (recommandé pour les audits client)** : clé générée
  aléatoirement à la volée pour chaque session d'audit, **jamais
  sauvegardée** — impossible de revenir aux IPs réelles après coup,
  garantie forte pour le client.
- **Pseudonymisation (si besoin de recouper des sessions dans le temps)** :
  clé conservée de façon sécurisée (coffre-fort de secrets), à valider
  explicitement avec le RSSI si ce besoin existe — sinon, préférer
  l'anonymisation pure par défaut.

## Ce qui reste à trancher avec Frédéric Lemal

1. Confirmer l'approche (CryptoPAn / préservation des préfixes) convient
   du point de vue sécurité/conformité.
2. Anonymisation pure par défaut, ou pseudonymisation avec clé conservée
   dans certains cas ? (Impact RGPD différent selon le choix.)
3. Le payload applicatif doit-il être totalement tronqué, ou y a-t-il des
   cas où l'inspection de contenu est nécessaire (et donc un besoin
   d'anonymisation de contenu, plus complexe) ?
4. Faut-il un log d'audit de chaque anonymisation (quand, quel PCAP, par
   qui) pour tracabilité ?
