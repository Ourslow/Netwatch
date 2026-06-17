# Tester le portail NetWatch avec Proxmox dans VirtualBox

Guide pas à pas pour monter un Proxmox VE de test dans VirtualBox et y connecter
le portail NetWatch (`portal/`). Objectif : valider le portail (dashboard, liste
VMs, statut, déploiement) avant le déploiement physique sur le Shuttle.

> **Durée** : ~45 min · **Difficulté** : moyenne

---

## ⚠️ À lire avant de commencer — le piège Docker/Hyper-V

Si tu utilises **Docker Desktop** ou **WSL2** sur Windows, Hyper-V est activé.
VirtualBox fonctionne alors en mode dégradé et l'option **« VT-x/AMD-V imbriqué »**
sera **grisée**.

**Conséquence** : Proxmox démarre et son **API fonctionne** (donc le portail se
teste parfaitement), mais les VM créées *dans* Proxmox ne pourront pas démarrer en
KVM.

➡️ **Pour tester le portail, ce n'est PAS bloquant.** Le portail clone et configure
les VM via l'API — il ne les démarre pas. On peut tout valider sans nested virt.

Si tu veux quand même le nested virt (pour faire booter une VM dans Proxmox) :
désactive temporairement Hyper-V puis redémarre :
```powershell
# PowerShell admin — désactive Hyper-V (réversible)
bcdedit /set hypervisorlaunchtype off
# Réactiver plus tard : bcdedit /set hypervisorlaunchtype auto
```
(Docker Desktop ne fonctionnera plus tant que Hyper-V est off.)

---

## Prérequis

- VirtualBox 7.x installé
- ~6 Go de RAM libre, ~35 Go de disque libre
- L'ISO **Proxmox VE 8.x** : https://www.proxmox.com/en/downloads → *Proxmox VE 8.x ISO Installer*

---

## Étape 1 — Créer la VM dans VirtualBox

1. **Nouvelle** (bouton bleu)
2. Renseigne :
   - **Nom** : `proxmox-netwatch`
   - **Type** : `Linux`
   - **Version** : `Debian (64-bit)` *(Proxmox 8 est basé sur Debian 12)*
   - **ISO** : sélectionne l'ISO Proxmox téléchargé
   - ❌ **Décoche** « Installation automatique » (Proxmox a son propre installeur)
3. **Matériel** :
   - **Mémoire** : `4096` Mo (4 Go)
   - **Processeurs** : `2`
4. **Disque dur** : créer un disque, **32 Go**, VDI, dynamiquement alloué
5. **Terminer** (ne pas démarrer tout de suite)

---

## Étape 2 — Réglages critiques (avant de démarrer)

Sélectionne la VM → **Configuration** :

### Système → Processeur
- **Processeurs** : 2
- ☑️ **Activer VT-x/AMD-V imbriqué** *(si grisé → voir le piège Hyper-V ci-dessus, on continue sans)*

### Réseau → Carte 1 — LE point important
Choisis selon ton cas :

| Mode | Quand l'utiliser | IP obtenue |
|------|------------------|------------|
| **Accès par pont** | Tu veux Proxmox sur ton réseau local | IP de ton LAN (ex. `192.168.1.x`) |
| **Réseau privé hôte** | Test isolé, IP stable | `192.168.56.x` |

➡️ **Recommandé : Accès par pont** (le plus simple). Sélectionne ta carte
physique (Wi-Fi ou Ethernet) dans le menu « Nom ».

> Si tu choisis **Réseau privé hôte** et qu'aucun réseau n'existe :
> *Fichier → Outils → Gestionnaire de réseau hôte → Créer*.

### Stockage
- Vérifie que l'ISO Proxmox est bien monté dans le lecteur optique.

Valide avec **OK**.

---

## Étape 3 — Installer Proxmox VE

1. **Démarrer** la VM
2. Au menu de boot : **Install Proxmox VE (Graphical)**
   - *Si l'écran graphique plante, choisis « Install Proxmox VE (Terminal UI) »*
3. Accepte le **contrat de licence** (*I agree*)
4. **Target disk** : le disque virtuel de 32 Go → *Next*
5. **Location** :
   - Country : `France`
   - Timezone : `Europe/Paris`
   - Keyboard : `French`
6. **Mot de passe** root + **email** (un email bidon valide suffit, ex. `admin@netwatch.local`)
7. **Network configuration** — ⚠️ **note bien ces valeurs** :
   - **Hostname (FQDN)** : `pve.netwatch.local` → le nom court `pve` sera notre `PROXMOX_NODE`
   - **IP address** : note l'IP proposée (ou mets-en une libre de ton réseau)
   - Gateway / DNS : laisse les valeurs par défaut détectées
8. **Résumé** → *Install* → patiente (~5-10 min)
9. **Reboot**. À l'invite, VirtualBox éjecte l'ISO automatiquement (sinon : Configuration → Stockage → retire l'ISO).

À la fin, la console affiche :
```
Welcome to the Proxmox VE.  Please use your web browser to
configure this server - connect to:  https://<IP>:8006/
```
➡️ **Note cette IP** : c'est notre `PROXMOX_HOST`.

---

## Étape 4 — Premier accès à l'interface web

1. Depuis ton navigateur Windows : `https://<IP>:8006`
2. Avertissement de certificat (auto-signé) → *Avancé* → *Continuer*
3. Connexion :
   - **User name** : `root`
   - **Password** : ton mot de passe
   - **Realm** : `Linux PAM standard authentication`
4. Une popup « No valid subscription » → *OK* (normal, version gratuite)

Tu vois ton nœud `pve` à gauche avec ses ressources CPU/RAM/disque. 🎉

---

## Étape 5 — Connecter le portail NetWatch

Sur ton PC Windows, édite `portal/.env` :

```ini
# Proxmox (valeurs notées à l'étape 3)
PROXMOX_HOST=<IP_de_proxmox>
PROXMOX_USER=root@pam
PROXMOX_PASSWORD=<ton_mot_de_passe_root>
PROXMOX_NODE=pve
PROXMOX_VERIFY_SSL=false

# Portail
FLASK_SECRET_KEY=dev-local-secret-key
FLASK_DEBUG=true
PORT=5050
PORTAL_USERNAME=admin
PORTAL_PASSWORD=netwatch
```

> `PROXMOX_VERIFY_SSL=false` est nécessaire car le certificat Proxmox est auto-signé.

---

## Étape 6 — Lancer le portail

Dans un terminal :

```powershell
cd C:\Users\nicolas.malok\netwatch\portal

# Installer les dépendances (une seule fois)
python -m pip install -r requirements.txt

# Lancer
python app.py
```

*(si `python` n'est pas reconnu, utilise le chemin complet :
`C:\Users\nicolas.malok\AppData\Local\Programs\Python\Python312\python.exe`)*

Ouvre **http://localhost:5050** → connecte-toi avec `admin` / `netwatch`.

---

## Étape 7 — Valider le portail (checklist)

| Test | Résultat attendu |
|------|------------------|
| **Connexion** admin/netwatch | Arrivée sur le dashboard |
| **Dashboard** | CPU / RAM / disque du nœud `pve` affichés |
| **Machines virtuelles** | Liste (vide au début, ou la VM Proxmox elle-même) |
| **Statut services** | ES/Grafana/Prometheus en rouge (normal, stack non lancée) ; nœud Proxmox « Connecté » |
| **Catalogue** | 6 outils affichés |
| **Comparaison** | Tableau + scores |

Si le dashboard affiche les ressources du nœud → **l'API Proxmox répond, tout est bon.** ✅

---

## (Optionnel) Tester le déploiement d'une VM

Le portail peut cloner une VM depuis un **template**. Pour l'essayer :

1. Dans Proxmox, crée une petite VM (ou une coquille vide), clic droit → **Convert to template**
2. Ajoute-lui le tag `template` : sélectionne la VM → *Options* → *Tags* → ajoute `template`
3. Dans le portail → **Catalogue** → un outil déployable → **Déployer**
4. Choisis le template, valide → le portail clone et configure une nouvelle VM
5. Vérifie dans l'onglet **VMs** qu'elle apparaît

> Sans nested virt la VM clonée ne **bootera** pas, mais le **clone via API
> réussit** — ce qui valide la logique du portail.

---

## Dépannage

| Problème | Cause / solution |
|----------|------------------|
| Portail : « Proxmox non joignable » | Vérifie l'IP dans `.env`, que la VM Proxmox tourne, et le ping `Test-NetConnection <IP> -Port 8006` |
| Case « VT-x imbriqué » grisée | Hyper-V actif (Docker/WSL2). Non bloquant pour le portail — voir le piège en haut |
| Proxmox sans réseau après install | Mode réseau VBox mal configuré → repasse en « Accès par pont » |
| `pip install` échoue sur proxmoxer | `python -m pip install --upgrade pip` puis réessaie |
| Page de login en boucle | `PORTAL_PASSWORD` vide dans `.env` → mets une valeur |
| Connexion API lente puis échoue | `timeout=5` déjà géré ; vérifie surtout que l'IP est joignable |

---

## Récap des variables à reporter dans `portal/.env`

| Variable | Où la trouver |
|----------|---------------|
| `PROXMOX_HOST` | IP affichée en fin d'install / console Proxmox |
| `PROXMOX_NODE` | Nom court du hostname (`pve`) |
| `PROXMOX_PASSWORD` | Mot de passe root défini à l'install |

Une fois Proxmox installé, donne-moi **l'IP** et **le nom du nœud** : je remplis
ton `.env` et on déroule la checklist ensemble.
