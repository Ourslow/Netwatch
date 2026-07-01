# Script oral — Soutenance jury École 2600

Durée cible : **15-18 minutes** + questions. Ce script suit `jury-slides.md` slide par slide. Le texte est une base à s'approprier, pas à lire mot à mot.

---

### Slide 1 — Titre (30 sec)

"Bonjour, je m'appelle Nicolas Malok, je suis alternant analyste observabilité NPM chez Axians, filiale de Vinci Energies, et étudiant à l'École 2600. Je vais vous présenter NetWatch, mon SideQuest MVP : une stack d'observabilité réseau open-source que j'ai construite et fait évoluer sur ce semestre."

### Slide 2 — Sommaire (20 sec)

"Je vais dérouler le contexte, mes objectifs, la démarche que j'ai suivie, ce que j'ai concrètement livré, une démonstration, puis un retour sur les difficultés et les compétences acquises."

### Slide 3 — Contexte (1 min)

"Chez Axians, je suis positionné sur l'observabilité réseau. Axians revend des solutions commerciales comme Netscout nGeniusONE, Gigamon ou Riverbed — des outils très complets mais aussi très coûteux, entre 10 000 et plus de 100 000 euros par an, et souvent fermés : on ne voit pas ce qu'il y a dans la boîte noire. Je me suis posé une question simple : est-ce qu'on peut reproduire les fonctions clés de ces outils avec des briques 100% open-source ? C'est le point de départ de NetWatch."

### Slide 4 — Objectifs pédagogiques (1 min)

"Au-delà du produit, ce projet visait cinq objectifs de compétence : comprendre en profondeur le fonctionnement d'un NPM/NDR — pas juste l'utiliser, mais savoir ce qu'il y a dedans ; manipuler de vrais moteurs de détection ; construire une chaîne d'observabilité complète de bout en bout ; automatiser la réponse à incident ; et enfin, mener un projet dans la durée, avec une vraie méthode, pas un one-shot."

### Slide 5 — Concept (1 min)

"Le concept central de NetWatch, c'est de faire tourner trois moteurs d'analyse en parallèle sur le même trafic : Zeek pour l'analyse protocolaire, Snort et Suricata pour la détection par signatures. Chacun apporte une perspective différente sur le même flux, un peu comme trois experts qui analysent la même scène de crime avec des outils différents. Tout converge ensuite vers Elasticsearch et Grafana. Et j'ai ajouté un second volet, plus NPM que sécurité pur : NetFlow, SNMP, topologie, capacity planning."

### Slide 6 — Architecture (1 min 30)

"Concrètement, ça représente 14 services Docker orchestrés. Zeek 6.2 pour l'analyse protocolaire avec du fingerprinting JA3/HASSH. Snort 3.3.5, compilé depuis les sources, avec des règles custom mappées MITRE ATT&CK. Suricata 7 avec les règles Emerging Threats Open. Tout ça alimente Elasticsearch et Grafana. Et j'ai ajouté GoFlow2 et un SNMP exporter pour la partie supervision réseau pure, plus proche de ce que fait un vrai NPM commercial. Un portail Flask unifie tout ça avec une IA locale pour expliquer les alertes."

### Slide 7 — Démarche méthodologique (1 min 30)

"Point important pour vous : je n'ai pas fait ce projet en un seul bloc. La v1, livrée en mars, était un socle minimal fonctionnel — quatre services, quatre dashboards. La v2, c'est sept phases livrées progressivement en juin, chacune apportant une capacité testable et démontrable. Un choix que j'assume et que je veux expliciter : j'ai utilisé une orchestration multi-agents IA pour paralléliser le développement entre infrastructure, sécurité, automatisation et frontend, avec des worktrees Git séparés par domaine. Ça m'a permis d'avancer sur plusieurs fronts en même temps, tout en gardant la responsabilité de la relecture, du merge et de la validation de chaque livraison."

### Slide 8 — Les 7 phases (1 min)

"Pour donner un aperçu concret : les trois premières phases ont posé le socle — CrowdSec, l'automatisation n8n, un graphe d'indicateurs de compromission interactif. La phase 4 a ajouté une vue exécutive pour un RSSI. La phase 5 a intégré la collecte NetFlow. La phase 6, la supervision SNMP et la topologie réseau auto-découverte. La phase 7, le capacity planning, la qualité VoIP et la conformité SLA. Au final : 14 services, 13 dashboards, 9 pages de portail."

### Slide 9-10 — Démonstration dashboard / statut (1 min 30, + démo live si possible)

"Je vous montre ici le dashboard principal du portail — alertes en temps réel avec sparklines, filtres par moteur et sévérité. Et la page de statut, qui supervise en direct l'état des 14 services : Elasticsearch, Grafana, Prometheus, AutoBlock, l'IA locale. Si la configuration le permet, je peux vous montrer une démonstration en direct."

### Slide 11 — Démo exec & NPM (1 min 30)

"La page `/exec` donne une vue destinée à un décideur, pas un technicien : un score de risque composite, une tendance. La page `/flows` montre le débit réseau et la santé des connexions TCP. `/topology` reconstruit automatiquement la carte du réseau par SNMP et ARP. `/sla` calcule un taux de conformité sur 7 jours, avec une distinction heures ouvrées / non ouvrées, ce qui est un vrai besoin métier côté NPM."

### Slide 12 — Sécurité & conformité (1 min 30)

"Côté détection comportementale, j'ai implémenté une version allégée de RITA pour repérer du beaconing C2, du tunneling DNS, des connexions anormalement longues. Une réponse automatique bloque les IPs suspectes via iptables, déclenchée depuis Grafana. J'ai aussi mappé une partie de la couverture sur quatre référentiels : NIS2, NIST CSF 2.0, ANSSI et ISO 27001. Et — point que je trouve important — j'ai mené un audit de sécurité sur le code du projet lui-même, pas seulement sur ce qu'il détecte : 25 problèmes identifiés, 11 corrigés en priorité, notamment une route non authentifiée et une vérification TLS désactivée par défaut."

### Slide 13 — Difficultés rencontrées (1 min 30)

"Je veux être transparent sur les difficultés, parce que c'est aussi ça qui montre la démarche. Le build de Snort depuis les sources m'a pris du temps à stabiliser. Le workflow multi-agents m'a fait perdre du contenu à plusieurs reprises : des merges Git à un seul parent qui faisaient disparaître du code sans erreur visible — j'ai dû comprendre le mécanisme exact des merges pour le fiabiliser. J'ai aussi eu un bug assez vicieux où les champs Zeek stockés de façon imbriquée dans Elasticsearch n'étaient jamais lus correctement, ce qui faisait qu'aucune IP source n'était détectée en beaconing. Chaque bug a été une occasion de mieux comprendre la pile technique."

### Slide 14 — Compétences développées (1 min)

"Sur le plan technique, j'ai manipulé en profondeur Zeek, Snort, Suricata, la stack ELK, Prometheus et Grafana, et j'ai beaucoup écrit de Python pour parser des logs, interroger l'API bulk d'Elasticsearch, faire du SNMP, calculer des scores MOS ou des projections de capacité. J'ai aussi dû sécuriser une vraie application Flask exposée. Sur le plan transverse, j'ai conduit un projet en méthode itérative, mené un audit et priorisé des correctifs, et piloté des agents IA en parallèle sur un projet réel — ce qui est une compétence qui monte fortement dans le métier."

### Slide 15 — Bilan chiffré (30 sec)

"En résumé : 14 services, 13 dashboards, 9 pages de portail, 7 phases livrées, 425 ports applicatifs classifiés, plus de 100 vendors réseau reconnus, 25 bugs identifiés dont 11 corrigés en priorité. Le tout sous licence AGPL v3, en dépôt public."

### Slide 16 — Perspectives v3 (45 sec)

"La suite naturelle, c'est le déploiement physique sur l'infrastructure Shuttle avec Proxmox et un vrai port SPAN, avec une carte réseau dédiée à la capture. Je veux aussi construire un portail de gestion des VMs, et surtout une comparaison côte à côte avec les outils commerciaux qu'utilise Axians, pour objectiver où l'open-source tient la comparaison et où il ne la tient pas."

### Slide 17 — Conclusion (30 sec)

"Pour conclure : NetWatch montre qu'on peut reproduire les fonctions clés d'un NPM/NDR commercial avec des briques open-source, en gardant une vraie rigueur de projet et une qualité de code auditée. Et surtout, la montée en compétence que ça m'a apportée, je la réinvestis directement dans mon alternance chez Axians."

### Slide 18 — Questions (ouverture)

"Je suis prêt à répondre à vos questions."

---

## Anticiper les questions probables du jury

- **"Pourquoi ne pas avoir tout codé vous-même sans les agents IA ?"** → Assumer le choix : gain de temps sur du code répétitif (parsers, dashboards JSON), mais responsabilité de la relecture, des tests et du merge reste 100% humaine. Le bug des merges à 1 parent est une bonne illustration : l'agent ne fiabilise rien tout seul.
- **"Le projet est-il vraiment sécurisé si vous avez trouvé 25 bugs ?"** → C'est justement la preuve d'une démarche qualité : audit volontaire, priorisation par criticité, correctifs tracés. Un projet sans bugs détectés est plus suspect qu'un projet audité.
- **"Quelle est la vraie valeur ajoutée par rapport à un outil commercial ?"** → Ne pas prétendre égaler Netscout/Gigamon en maturité. La valeur est pédagogique et de compréhension fine — un futur usage réaliste est présenté dans le pitch entreprise (complémentaire, pas concurrent).
- **"Combien de temps pour reproduire ce projet ?"** → Situer : v1 = quelques semaines, v2 = 7 phases sur un mois, en parallélisation multi-agents. Sans agents, la v2 aurait pris nettement plus de temps solo.
