# Script oral — Présentation Axians

Durée cible : **10-12 minutes**. Ton business, orienté valeur et cas d'usage. Suit `axians-slides.md`.

---

### Slide 1 — Titre (20 sec)

"Bonjour à tous. Je vais vous présenter NetWatch, un projet que j'ai développé en parallèle de mon alternance, et je pense qu'il peut avoir une vraie utilité pour nos équipes."

### Slide 2 — En une phrase (30 sec)

"Je le dis tout de suite pour être clair : NetWatch n'est pas là pour concurrencer Netscout, Gigamon ou Riverbed. C'est un outil qu'on peut utiliser en interne pour comprendre, démontrer et qualifier des besoins, avant de vendre nos solutions commerciales."

### Slide 3 — Le constat métier (1 min)

"Le constat de départ, c'est qu'aujourd'hui nos clients découvrent souvent Netscout ou Gigamon sans vraiment comprendre ce qui se passe à l'intérieur — c'est une boîte noire, même pour nous parfois. Qualifier un besoin NPM chez un prospect implique souvent d'engager un PoC avec des licences temporaires, ce qui a un coût. Et nos analystes juniors montent en compétence directement sur des outils propriétaires fermés, ce qui ralentit la compréhension des fondamentaux. Il n'existe pas non plus de labo interne pour tester une signature de détection avant de la déployer chez un client."

### Slide 4 — La proposition NetWatch (1 min)

"NetWatch, c'est un labo réseau complet, 100% open-source et gratuit, qui reproduit les fonctions clés d'un NPM/NDR commercial : analyse protocolaire, détection d'intrusion, détection comportementale, mais aussi tout le volet NPM pur — flux réseau, SNMP, topologie, capacity planning, qualité VoIP, conformité SLA. Le tout dans un portail web unifié, avec une IA locale pour aider à interpréter les alertes. Et point important : ça se déploie en moins de 30 minutes sur une simple VM."

### Slide 5 — 3 cas d'usage (1 min 30)

"Concrètement, je vois trois usages directs pour nous. Premièrement, la formation interne : c'est un excellent support d'onboarding pour les juniors, parce que le code est ouvert — on peut montrer exactement ce qui se passe derrière chaque métrique. Deuxièmement, l'avant-vente : quand un prospect hésite ou veut voir avant d'investir dans une licence, NetWatch permet de faire un démonstrateur rapide et gratuit pour qualifier le besoin réel. Troisièmement, un labo de validation : avant de déployer une règle de détection ou un seuil d'alerte chez un client, on peut le tester ici sans risque."

### Slide 6 — Ce que NetWatch couvre (1 min)

"Sur la partie NPM spécifiquement — celle qui vous parle le plus je pense — j'ai intégré la collecte de flux NetFlow, IPFIX et sFlow via GoFlow2, l'équivalent de ce que fait Netscout ou Gigamon sur ce point. J'ai ajouté une supervision SNMP des interfaces, une topologie réseau qui se reconstruit automatiquement par LLDP et ARP, un module de capacity planning qui projette les dates de saturation, un score de qualité VoIP basé sur le modèle MOS standard, et un calcul de conformité SLA sur les temps de réponse HTTP, DNS et RTT."

### Slide 7 — Démonstration (2 min, live si possible)

"Je vous montre rapidement les pages clés : la vue exécutive pour un décideur, avec un score de risque synthétique. La page flux, avec le débit réseau et la santé TCP. La topologie, générée automatiquement. Et la page SLA, avec le taux de conformité sur 7 jours et une distinction heures ouvrées / non ouvrées, qui est un vrai besoin qu'on retrouve chez nos clients."

### Slide 8 — Ce que NetWatch ne remplace pas (1 min)

"Je veux être honnête sur les limites, parce que c'est important pour la crédibilité de la démarche. NetWatch ne remplace pas le support éditeur, les garanties contractuelles de disponibilité, la scalabilité validée en production multi-sites, ni l'écosystème d'intégrations tierces mature qu'on retrouve chez Netscout ou Riverbed. Ce n'est pas un produit à vendre au client final — c'est un outil de compréhension et de démonstration en interne."

### Slide 9 — Ce que ça apporte à Axians (1 min)

"Concrètement, ça nous donne un support de formation réutilisable, un argument différenciant en avant-vente — pouvoir dire qu'on comprend vraiment ce qu'on vend — une base de test pour valider des scénarios avant client, et une vitrine de compétence interne en observabilité réseau. Le coût est nul puisque c'est open-source, et l'investissement en temps de montée en compétence a déjà été fait."

### Slide 10 — Prochaines étapes (45 sec)

"Ce que je propose : présenter l'outil à l'équipe observabilité pour avoir un retour d'usage, faire un test en labo sur une infrastructure Axians avec un vrai port SPAN, évaluer son usage comme support de formation, et enfin décider si on veut l'élargir à l'avant-vente sur certains dossiers ciblés."

### Slide 11 — Questions

"Je suis disponible pour toute question ou pour organiser une démonstration plus approfondie."

---

## Anticiper les questions probables

- **"Pourquoi pas directement un vrai PoC Netscout ?"** → Coût et délai : un PoC commercial nécessite souvent une licence temporaire et un accompagnement éditeur. NetWatch permet de dégrossir la qualification du besoin avant d'engager ce coût, pas de le remplacer.
- **"Est-ce que c'est un risque de montrer un outil 'concurrent' gratuit à un client ?"** → Positionnement clair à maintenir : usage strictement interne (formation, qualification, labo), jamais présenté comme alternative vendable au client.
- **"Qui maintient ce projet si on l'adopte en interne ?"** → Point à clarifier avec la hiérarchie : aujourd'hui projet personnel sous licence AGPL v3 ; une adoption officielle impliquerait de définir un mode de maintenance (temps dédié, équipe, gouvernance du fork interne éventuel).
