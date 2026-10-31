---
title: "Kerberos dans Active Directory — Fonctionnement, attaques et durcissement"
date: 2026-11-15 10:00:00 +0100
categories: [Active Directory]
tags: [kerberos, kerberoasting, asreproasting, delegation, pass-the-ticket, active-directory]
description: "Comprendre les échanges Kerberos pour comprendre pourquoi les attaques dessus fonctionnent — et comment s'en protéger."
---

> **TL;DR** — Kerberos repose sur des tickets chiffrés avec des secrets dérivés des mots de passe des comptes. Tout l'enjeu offensif tient là : obtenir un blob chiffré avec le secret d'un compte pour le casser hors ligne (AS-REP Roasting, Kerberoasting), ou voler / rejouer / forger un ticket (Pass-the-Ticket, Silver et Golden Ticket). Le durcissement le plus rentable : des mots de passe longs — ou des gMSA — pour les comptes à SPN, l'AES à la place du RC4, la pré-authentification partout, et un contrôle strict du compte `krbtgt`.
{: .prompt-info }

| | |
|---|---|
| **Niveau** | Intermédiaire |
| **Prérequis** | Notions d'Active Directory (utilisateurs, groupes, DC), hash NT |
| **Attaques couvertes** | AS-REP Roasting, Kerberoasting, Pass-the-Ticket / Overpass-the-Hash, abus de délégation, Silver / Golden Ticket |
| **Outils** | impacket, Rubeus, kerbrute, hashcat, BloodHound |

## 1. La notion

### 1.1 À quoi ça sert

Kerberos est le protocole d'authentification par défaut d'un domaine Active Directory depuis Windows 2000. Son objectif : permettre à un utilisateur de prouver son identité à un service **sans jamais faire transiter son mot de passe sur le réseau**, et offrir du *single sign-on* — on s'authentifie une fois, puis on accède à plusieurs services sans ressaisir ses identifiants.

Le cœur du système est le **KDC** (*Key Distribution Center*), hébergé sur chaque contrôleur de domaine. Il se décompose en deux services logiques :

- l'**AS** (*Authentication Service*), qui délivre le ticket initial (TGT) ;
- le **TGS** (*Ticket-Granting Service*), qui délivre les tickets d'accès aux services.

L'idée centrale est celle d'un **tiers de confiance** : le client et le service ne se font pas confiance mutuellement, mais tous deux font confiance au KDC. Ce dernier connaît le secret de chaque compte du domaine (le hash de son mot de passe) et s'en sert pour chiffrer les tickets.

### 1.2 Comment ça marche

L'authentification se déroule en trois échanges.

```text
Client                         KDC (DC)                          Service (SPN)
  │                               │                                   │
  │ ── 1. AS-REQ ────────────────▶│                                   │
  │     (pré-auth : timestamp     │                                   │
  │      chiffré avec la clé      │                                   │
  │      de l'utilisateur)        │                                   │
  │ ◀─ 2. AS-REP ─────────────────│   TGT chiffré avec la clé de      │
  │     (TGT + clé de session)    │   krbtgt ; le reste avec la clé   │
  │                               │   de l'utilisateur                │
  │                               │                                   │
  │ ── 3. TGS-REQ ───────────────▶│                                   │
  │     (TGT + SPN demandé)       │                                   │
  │ ◀─ 4. TGS-REP ────────────────│   Ticket de service (ST) chiffré  │
  │     (ST + clé de session)     │   avec la clé du compte de        │
  │                               │   service                         │
  │                               │                                   │
  │ ── 5. AP-REQ (ST) ──────────────────────────────────────────────▶│
  │                               │              le service déchiffre │
  │                               │              le ST et lit le PAC  │
```

**Étape 1-2 — AS-Exchange.** Le client envoie une `AS-REQ`. Avec la **pré-authentification** activée (le cas normal), il y inclut un *timestamp* chiffré avec sa propre clé (dérivée de son mot de passe). Le KDC, qui connaît cette clé, déchiffre le timestamp : s'il est récent et valide, l'identité est prouvée. Le KDC renvoie alors un **TGT** (*Ticket-Granting Ticket*) — chiffré avec la clé du compte **`krbtgt`**, donc opaque pour l'utilisateur — ainsi qu'une clé de session.

**Étape 3-4 — TGS-Exchange.** Pour accéder à un service, le client présente son TGT et demande un ticket pour un **SPN** (*Service Principal Name*, l'identifiant d'un service, par ex. `MSSQLSvc/db01.corp.local:1433`). Le KDC renvoie un **ticket de service (ST)** chiffré avec la clé du **compte qui porte ce SPN**.

**Étape 5 — AP-Exchange.** Le client présente le ST au service. Celui-ci le déchiffre avec sa propre clé et lit le **PAC** (*Privilege Attribute Certificate*), une structure incluse dans le ticket qui contient les SID de l'utilisateur et de ses groupes — c'est ce qui détermine ses autorisations.

**Les types de chiffrement comptent.** La clé dérivée du mot de passe peut être en **RC4-HMAC** (strictement équivalente au hash NT du compte) ou en **AES128/256** (dérivée via PBKDF2, avec un sel). Le RC4 n'a pas de sel et est beaucoup plus rapide à attaquer hors ligne : c'est un facteur déterminant pour la suite.

### 1.3 Ce qu'il faut retenir pour la suite

Quatre propriétés du protocole rendent les attaques possibles :

- **Le TGT est chiffré avec le secret de `krbtgt`.** Quiconque possède ce secret peut forger un TGT arbitraire, pour n'importe quel utilisateur et avec n'importe quelle appartenance de groupe. → *Golden Ticket* (§ 3.5).
- **Le ticket de service est chiffré avec le secret du compte qui porte le SPN**, et **tout utilisateur authentifié peut en demander un**. Le KDC ne vérifie pas que le demandeur a le droit d'accéder au service. → *Kerberoasting* (§ 3.2) et *Silver Ticket* (§ 3.5).
- **Sans pré-authentification**, le KDC renvoie une `AS-REP` à quiconque la demande, contenant une partie chiffrée avec la clé de l'utilisateur ciblé. → *AS-REP Roasting* (§ 3.1).
- **La clé dérive du mot de passe.** Connaître le hash (ou la clé AES) suffit à agir au nom du compte, sans jamais connaître le mot de passe en clair. → *Overpass-the-Hash* et *Pass-the-Ticket* (§ 3.3).

## 2. Surface d'attaque

| Élément abusable | Accès requis | Attaque |
|------------------|--------------|---------|
| Compte avec `DONT_REQ_PREAUTH` | Une liste de noms d'utilisateurs | § 3.1 |
| Compte utilisateur portant un SPN | Un compte de domaine valide | § 3.2 |
| TGT / clé de session / hash en mémoire | Admin local sur un hôte | § 3.3 |
| Délégation configurée (Unconstrained / Constrained / RBCD) | Variable | § 3.4 |
| Secret d'un compte de service | Compte de service compromis | § 3.5 |
| Secret du compte `krbtgt` | Domain Admin / DCSync | § 3.5 |

## 3. Attaques

> Les commandes ci-dessous visent un **lab ou un périmètre dûment autorisé**. Elles illustrent la méthodologie ; adaptez les noms de domaine, DC et comptes à votre environnement.
{: .prompt-warning }

### 3.1 AS-REP Roasting

**Principe** — Certains comptes ont la pré-authentification désactivée (attribut `DONT_REQ_PREAUTH`, souvent posé pour des applications anciennes). Pour ces comptes, le KDC renvoie une `AS-REP` à **n'importe quel demandeur**. Or une partie de cette réponse est chiffrée avec la clé de l'utilisateur ciblé : on obtient donc un blob cassable hors ligne, sans aucun credential de départ. On exploite ici la propriété « sans pré-auth, l'AS-REP expose la clé de l'utilisateur » (§ 1.3).

**Prérequis** — Une liste de noms d'utilisateurs. Aucun mot de passe. (Avec un compte de domaine valide, on peut d'abord énumérer en LDAP les comptes qui portent ce flag.)

**Exploitation**

```bash
# Avec une simple liste de noms (aucun credential)
impacket-GetNPUsers corp.local/ -usersfile users.txt -no-pass \
  -dc-ip 10.10.10.10 -format hashcat -outputfile asrep.hashes

# Avec un compte valide : cible uniquement les comptes réellement vulnérables
impacket-GetNPUsers corp.local/analyst:'Passw0rd!' -request \
  -dc-ip 10.10.10.10 -format hashcat -outputfile asrep.hashes
```

Puis crack hors ligne (mode hashcat `18200`) :

```bash
hashcat -m 18200 asrep.hashes rockyou.txt
```

**Résultat / impact** — Le mot de passe en clair de chaque compte dont la clé était faible. Un point d'entrée dans le domaine à partir de *zéro* credential.

### 3.2 Kerberoasting

**Principe** — Tout utilisateur authentifié peut demander un ticket de service pour n'importe quel SPN, et ce ticket est chiffré avec la clé du compte qui porte le SPN (§ 1.3). Si ce compte est un **compte utilisateur** (et non une machine), sa clé dérive d'un mot de passe choisi par un humain — donc potentiellement faible et cassable. Les comptes machines, eux, ont des mots de passe de 120 caractères générés aléatoirement : inattaquables en pratique.

**Prérequis** — Un compte de domaine valide (n'importe lequel).

**Exploitation**

```bash
# Énumère les comptes à SPN et récupère les tickets, en une commande
impacket-GetUserSPNs corp.local/analyst:'Passw0rd!' -dc-ip 10.10.10.10 \
  -request -outputfile kerb.hashes
```

Depuis Windows, l'équivalent avec Rubeus :

```powershell
Rubeus.exe kerberoast /outfile:kerb.hashes
```

Crack hors ligne (mode `13100` pour un ST en RC4) :

```bash
hashcat -m 13100 kerb.hashes rockyou.txt
```

> **Astuce défensive — et offensive.** Un attaquant peut forcer le KDC à délivrer un ticket **RC4** même quand l'AES est disponible (*downgrade*), car le RC4 se casse bien plus vite. Surveiller les `TGS-REQ` qui demandent explicitement du RC4 est un excellent signal de détection (§ 5).
{: .prompt-tip }

**Résultat / impact** — Le mot de passe en clair des comptes de service à SPN. Ces comptes ont souvent des privilèges élevés (SQL, IIS, comptes d'admin mal conçus), ce qui en fait un vecteur d'escalade très courant.

### 3.3 Pass-the-Ticket et Overpass-the-Hash

**Principe** — Puisque l'authentification repose sur des clés dérivées du mot de passe et sur des tickets (§ 1.3), il n'est pas nécessaire de connaître le mot de passe en clair :

- **Overpass-the-Hash (Pass-the-Key)** — à partir d'un hash NT ou d'une clé AES volés, on demande un TGT légitime au KDC.
- **Pass-the-Ticket** — on vole un TGT ou un ST déjà présent en mémoire (LSASS) sur un hôte compromis, puis on l'injecte dans sa propre session.

**Prérequis** — Un hash / une clé du compte cible (Overpass-the-Hash), ou un accès admin local permettant d'extraire les tickets en mémoire (Pass-the-Ticket).

**Exploitation**

```bash
# Overpass-the-Hash : obtenir un TGT à partir d'une clé AES256
impacket-getTGT corp.local/svc_sql -aesKey <AES256_KEY> -dc-ip 10.10.10.10
export KRB5CCNAME=svc_sql.ccache

# Réutiliser le ticket (ici avec nxc/impacket qui lisent KRB5CCNAME)
nxc smb dc01.corp.local -k --use-kcache
```

Depuis Windows, extraction puis réinjection d'un ticket avec Rubeus :

```powershell
Rubeus.exe asktgt /user:svc_sql /aes256:<AES256_KEY> /ptt
```

**Résultat / impact** — Exécution d'actions au nom du compte cible, et **mouvement latéral** sans toucher au mot de passe en clair. Préférer la clé AES au hash NT : utiliser du RC4 là où le domaine attend de l'AES est un signal détectable.

### 3.4 Abus de délégation

La délégation Kerberos permet à un service d'agir **au nom d'un utilisateur** auprès d'un autre service (ex. un serveur web qui interroge une base de données sous l'identité du client). Trois variantes, par ordre de dangerosité :

- **Unconstrained** — l'hôte reçoit et stocke le **TGT** de tout utilisateur qui s'y connecte. Si on compromet un tel hôte, et qu'on force un compte privilégié (voire un DC) à s'y authentifier, on capture son TGT. Très dangereux.
- **Constrained** — l'hôte ne peut déléguer que vers une liste de SPN définie. L'abus repose sur `S4U2Self` / `S4U2Proxy` pour obtenir un ticket au nom d'un utilisateur arbitraire vers ces services.
- **Resource-Based Constrained Delegation (RBCD)** — la confiance est portée par l'objet *cible*. Si on peut écrire l'attribut `msDS-AllowedToActOnBehalfOfOtherIdentity` d'une machine (via un abus d'ACL), on se configure soi-même comme délégué et on obtient un accès privilégié à cette machine.

Ce sujet mérite un article dédié ; on en retient ici le principe et le lien avec les ACL (voir les abus d'ACL dans les writeups du blog).

**Résultat / impact** — Usurpation de comptes privilégiés, souvent jusqu'au compromis du DC.

### 3.5 Tickets forgés — Silver et Golden Ticket

Ces attaques sont des techniques de **persistance** : elles supposent qu'un secret a déjà été compromis, et permettent ensuite de forger des tickets valides à volonté.

- **Silver Ticket** — avec le secret d'un **compte de service** (son hash / sa clé AES), on forge directement un **ticket de service** pour ce SPN. Le KDC n'est pas sollicité : le service déchiffre le ticket avec sa propre clé et fait confiance au PAC qu'il contient. Portée limitée à ce service.
- **Golden Ticket** — avec le secret du compte **`krbtgt`** (obtenu par DCSync sur un domaine déjà compromis), on forge un **TGT** arbitraire, pour n'importe quel utilisateur et n'importe quels groupes (y compris *Domain Admins*). Portée : tout le domaine, et tant que le secret `krbtgt` n'est pas changé **deux fois**.

```bash
# Golden Ticket (post-compromission, à des fins de démonstration/persistance)
impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid <SID> \
  -domain corp.local Administrator
```

**Résultat / impact** — Accès persistant et difficile à révoquer. La seule réponse complète à un Golden Ticket est une **double rotation du mot de passe de `krbtgt`**.

## 4. Vulnérabilités et mauvaises configurations courantes

| Constat | Pourquoi c'est dangereux | Comment le vérifier |
|---------|--------------------------|---------------------|
| Comptes de service à SPN avec mot de passe faible | Kerberoasting → mot de passe en clair | `impacket-GetUserSPNs corp.local/user:pass` |
| Comptes avec `DONT_REQ_PREAUTH` | AS-REP Roasting sans credential | `nxc ldap dc01 -u user -p pass --asreproast out.txt` |
| RC4-HMAC encore autorisé | Crack hors ligne bien plus rapide, downgrade possible | GPO *Network security: Configure encryption types* ; `msDS-SupportedEncryptionTypes` |
| Délégation *Unconstrained* sur un hôte non-DC | Capture de TGT privilégiés | BloodHound : `MATCH (c {unconstraineddelegation:true})` |
| Droits d'écriture sur `msDS-AllowedToActOnBehalfOf…` | RBCD → prise de contrôle de machine | BloodHound (edges `AddAllowedToAct`) |
| `krbtgt` jamais renouvelé | Golden Ticket indéfini | Âge du mot de passe de `krbtgt` |

## 5. Détection

| Attaque | Source / Event ID | Signal à surveiller |
|---------|-------------------|---------------------|
| AS-REP Roasting | 4768 (Security, DC) | `AS-REQ` sans pré-auth (`PREAUTH_NOT_REQUIRED`) pour plusieurs comptes |
| Kerberoasting | 4769 (Security, DC) | Volume anormal de `TGS-REQ`, surtout avec `Ticket Encryption Type = 0x17` (RC4) |
| Overpass-the-Hash / downgrade | 4768 / 4769 | RC4 demandé alors que le compte supporte l'AES |
| Pass-the-Ticket | 4624 + télémétrie EDR | TGT/ST présents sans AS-Exchange correspondant ; incohérences d'horodatage |
| Golden Ticket | 4769 | Tickets à durée de vie anormale ; TGT sans 4768 préalable |

> La meilleure détection du Kerberoasting n'est pas le volume brut de `4769` (le trafic Kerberos légitime est énorme) mais le **type de chiffrement** : un `4769` en RC4 vers un compte utilisateur à SPN, hors des horaires habituels, est un signal fort.
{: .prompt-tip }

## 6. Recommandations

| Priorité | Mesure | Bloque |
|----------|--------|--------|
| <span class="sev sev-critical">Critique</span> | Migrer les comptes de service vers des **gMSA** (mots de passe de 120 car. gérés automatiquement) | § 3.2 |
| <span class="sev sev-critical">Critique</span> | **Rotation planifiée de `krbtgt`** (deux fois, à 24 h d'intervalle) ; après tout incident | § 3.5 |
| <span class="sev sev-high">Haute</span> | **Désactiver RC4-HMAC**, imposer AES (après audit d'impact) | § 3.2, § 3.3 |
| <span class="sev sev-high">Haute</span> | Supprimer `DONT_REQ_PREAUTH` partout où c'est possible | § 3.1 |
| <span class="sev sev-high">Haute</span> | Supprimer la délégation *Unconstrained* hors DC ; privilégier RBCD maîtrisée | § 3.4 |
| <span class="sev sev-medium">Moyenne</span> | Mots de passe ≥ 25 caractères pour les comptes de service qui ne peuvent pas être des gMSA | § 3.2 |
| <span class="sev sev-medium">Moyenne</span> | Placer les comptes à hauts privilèges dans **Protected Users** (pas de RC4, pas de délégation) | § 3.3, § 3.4 |

## 7. Bonnes pratiques

- [ ] **Tiering** des comptes d'administration (Tier 0 / 1 / 2) pour cloisonner la valeur d'un secret volé
- [ ] Revue régulière des **SPN** portés par des comptes utilisateurs et des **délégations** (BloodHound)
- [ ] **Authentication Policies** / silos pour restreindre où les comptes sensibles peuvent s'authentifier
- [ ] Journalisation Kerberos (4768 / 4769) centralisée et corrélée sur le **type de chiffrement**
- [ ] Inventaire des comptes de service et plan de migration vers les gMSA

## Références

- [MS-KILE — Kerberos Protocol Extensions](https://learn.microsoft.com/openspecs/windows_protocols/ms-kile/)
- [The Hacker Recipes — Kerberos](https://www.thehacker.recipes/ad/movement/kerberos)
- [Microsoft — AES / RC4 et types de chiffrement Kerberos](https://learn.microsoft.com/windows-server/security/kerberos/)
- [Microsoft — Réinitialiser le mot de passe du compte krbtgt](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password)
