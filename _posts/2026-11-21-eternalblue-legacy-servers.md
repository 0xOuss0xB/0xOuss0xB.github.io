---
title: "Comment un serveur obsolète peut compromettre toute l'infrastructure"
date: 2026-11-21 10:00:00 +0100
categories: [Active Directory]
tags: [eternalblue, ms17-010, lsa-secrets, laps, pentest, windows-server-2003]
description: "En 2026, des serveurs Windows 2003 et 2008 sont encore en production. Un seul suffit pour compromettre un domaine AD entier : exploit public, dump des LSA Secrets, Domain Admin en quatre étapes."
image:
  path: /assets/img/posts/active-directory/eternalblue-banner.png
  alt: "EternalBlue — Legacy Servers"
---

> **TL;DR** — Un serveur Windows Server 2003 non patché, accessible depuis le réseau interne, exploité via EternalBlue (MS17-010) sans aucun identifiant. Les LSA Secrets livrent un mot de passe de compte de service en clair — le compte est Domain Admin. Pas de LAPS déployé : le hash admin local est partagé sur une trentaine de serveurs. Un seul serveur obsolète, quatre étapes, et l'intégralité du domaine est compromise.
{: .prompt-info }

| | |
|---|---|
| **Contexte** | Pentest interne, serveur obsolète en production |
| **Prérequis** | Accès réseau interne (port 445 vers la cible) |
| **Cible** | Domain Admin via EternalBlue + LSA Secrets |
| **Outils** | NetExec, Metasploit, impacket-secretsdump |
| **MITRE ATT&CK** | [T1210 — Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/), [T1003.004 — LSA Secrets](https://attack.mitre.org/techniques/T1003/004/) |

Cet article s'appuie sur les concepts couverts dans [NTLM](/posts/ntlm/) et [LDAP](/posts/ldap/). On détaille ici un scénario complet de compromission d'un domaine Active Directory à partir d'un seul serveur obsolète, issu d'un test d'intrusion interne.

## 1. Pourquoi c'est dangereux

### Des systèmes sans support depuis des années

Un système obsolète, c'est un système dont l'éditeur a arrêté le support. Plus de mises à jour de sécurité, plus de correctifs, plus rien. Chaque vulnérabilité découverte après la fin de support reste exploitable indéfiniment.

Les dates de fin de support étendu Microsoft :

- **Windows Server 2003** : 14 juillet 2015. Plus de 11 ans sans mise à jour de sécurité.
- **Windows Server 2008 R2** : 14 janvier 2020. Plus de 6 ans.

Chaque CVE publiée depuis ces dates sur le protocole SMB, le service RPC, le noyau Windows ou les composants réseau de ces systèmes est une porte ouverte permanente.

### EternalBlue : une faille de 9 ans toujours exploitable

MS17-010 (CVE-2017-0144) est une vulnérabilité critique dans l'implémentation de SMBv1 sur Windows. SMBv1 est la première version du protocole de partage de fichiers de Microsoft — un protocole ancien, conçu dans les années 90, qui n'intègre aucun mécanisme de sécurité moderne. L'exploit, baptisé EternalBlue, a été développé par la NSA puis fuité publiquement par le groupe Shadow Brokers en avril 2017.

Concrètement, la faille permet à un attaquant d'envoyer un paquet SMB spécialement forgé à une machine Windows exposant le port 445 (SMB). Le serveur traite ce paquet de manière incorrecte, ce qui provoque un dépassement de tampon dans le noyau. L'attaquant obtient alors une exécution de code en tant que `NT AUTHORITY\SYSTEM` — le niveau de privilège le plus élevé sur Windows — sans aucune authentification préalable.

En mai 2017, le ransomware **WannaCry** utilise EternalBlue pour se propager automatiquement. Le bilan : plus de 200 000 machines infectées dans 150 pays. Les hôpitaux du NHS britannique sont paralysés — des opérations chirurgicales reportées, des ambulances détournées. Renault arrête plusieurs usines. FedEx, Telefonica, Deutsche Bahn sont touchés. Le coût estimé dépasse les 4 milliards de dollars.

Quelques semaines plus tard, **NotPetya** utilise le même vecteur. Les dégâts sont encore plus lourds : Maersk perd l'intégralité de son infrastructure AD, Saint-Gobain chiffre ses pertes à 250 millions d'euros.

Microsoft a publié le patch en mars 2017 — y compris un correctif exceptionnel pour Windows Server 2003. Mais en 2026, les serveurs qui n'ont jamais été patchés ou qui ont été réinstallés depuis sans le correctif sont toujours vulnérables. Et l'exploit est toujours dans Metasploit, toujours fonctionnel, toujours trivial à lancer.

### Les protections modernes sont absentes

Sur un serveur Windows 2003 ou 2008 non patché, les couches de sécurité modernes n'existent pas :

- **Pas d'AMSI** (Antimalware Scan Interface) : introduit avec Windows 10, absent sur les anciens systèmes. AMSI permet aux antivirus d'inspecter le contenu des scripts PowerShell et des charges en mémoire avant leur exécution. Sans AMSI, l'antivirus ne voit pas ce qui s'exécute en mémoire.
- **Pas d'ETW Threat Intelligence** : pas de télémétrie sur les appels système suspects. Les outils de détection modernes (EDR) s'appuient sur ces événements pour repérer les comportements malveillants — injection de processus, dump de mémoire, manipulation de tokens. Sans ETW TI, l'EDR est aveugle.
- **Pas de Credential Guard** : sur les systèmes modernes, Credential Guard isole les identifiants en mémoire dans une enclave protégée par le processeur (VBS — Virtualization Based Security). Sur un serveur 2003, les hashes et mots de passe en mémoire sont accessibles à tout processus disposant des droits administrateur.
- **Agents EDR non supportés** : la plupart des solutions EDR actuelles ne supportent plus Windows Server 2003. Quand un agent est installé, il tourne avec des signatures obsolètes et des capacités réduites.

Le serveur est à la fois le plus vulnérable du parc et le moins supervisé.

## 2. Cas concret — d'un serveur 2003 à Domain Admin

Les faits suivants sont issus d'un test d'intrusion interne réalisé pour un organisme. Les noms, adresses IP et identifiants sont anonymisés. Le domaine Active Directory compte plus d'un millier de machines réparties sur plusieurs sites, avec plusieurs domaines liés par des relations d'approbation.

### Identification du serveur vulnérable

Scan du réseau interne à la recherche de machines vulnérables à MS17-010 avec NetExec. NetExec (nxc) est un outil de post-exploitation qui permet de scanner des plages réseau et d'exécuter des modules de détection de vulnérabilités sur les services Windows exposés :

```bash
nxc smb 10.0.0.0/24 -u user -p 'Password' -d corp.local -M ms17-010
```

```
[+] 10.0.1.50 is likely VULNERABLE to MS17-010! (Windows Server 2003 R2 3790 Service Pack 2)
```

Un serveur sort vulnérable : **SRV-COMPTA**, un Windows Server 2003 R2 SP2. C'est un serveur d'applications métier, toujours en production, accessible sans aucune restriction depuis le réseau utilisateur.

### Exploitation : SYSTEM sans credentials

Exploitation via Metasploit avec le module `ms17_010_psexec`. Ce module est spécifiquement adapté à Windows Server 2003 (contrairement au module `eternalblue` classique, plus fiable sur Windows 7 et 2008 R2). L'exploit ne nécessite aucun identifiant — il s'appuie sur la faille SMBv1 pour obtenir une exécution de code en tant que `NT AUTHORITY\SYSTEM` :

```text
use exploit/windows/smb/ms17_010_psexec
set RHOSTS 10.0.1.50
set PAYLOAD windows/exec
set CMD "net localgroup Administrateurs corp\\testaudit /add"
run
```

La commande ajoute le compte d'audit au groupe Administrateurs local du serveur. À partir de là, on dispose d'un accès administrateur complet sur cette machine.

### Dump des secrets : un mot de passe de service en clair

Avec un accès administrateur sur le serveur, extraction des secrets avec `impacket-secretsdump`. Cet outil se connecte au registre Windows à distance et lit trois bases de données internes :

- **SAM** (Security Account Manager) : contient les hashes des comptes locaux de la machine.
- **SECURITY** (LSA Secrets) : contient les mots de passe des comptes utilisés par les services Windows, les identifiants en cache des dernières sessions (cached domain logons), et les clés de la machine.
- **SYSTEM** : contient la clé de déchiffrement (bootKey) nécessaire pour lire les deux bases précédentes.

```bash
impacket-secretsdump 'SRV-COMPTA/Administrateur'@10.0.1.50
```

```
[*] Dumping LSA Secrets
[*] _SC_MSSQLSERVER
CORP\svc-sql:MotDePasse123!
[*] _SC_SQLSERVERAGENT
CORP\svc-sql:MotDePasse123!
```

Les services SQL Server (`MSSQLSERVER` et `SQLSERVERAGENT`) tournent sous un compte de domaine : `CORP\svc-sql`. Son mot de passe apparaît en clair dans le dump.

**Pourquoi le mot de passe est en clair ?** Quand un service Windows est configuré pour s'exécuter sous un compte de domaine, le Service Control Manager (SCM) doit pouvoir démarrer ce service automatiquement au boot — sans intervention humaine. Pour cela, il stocke le mot de passe du compte de manière réversible dans les LSA Secrets du registre. Le chiffrement utilisé est réversible par design : Windows a besoin du mot de passe en clair pour s'authentifier auprès de l'AD au démarrage du service. Avec un accès administrateur local, ces secrets sont lisibles. C'est un comportement normal de Windows, pas un bug — et c'est précisément la raison pour laquelle les comptes de service classiques représentent un risque.

Les entrées préfixées par `_SC_` dans les LSA Secrets correspondent aux comptes configurés dans le Service Control Manager. Chaque service qui tourne sous un compte de domaine (et non sous `LOCAL SYSTEM`) y stocke ses identifiants.

### Domain Admin

Vérification des privilèges du compte `svc-sql` dans l'annuaire Active Directory : il est membre du groupe **Admins du domaine** (`adminCount=1`). L'attribut `adminCount` à 1 indique que le compte est ou a été membre d'un groupe protégé (Domain Admins, Enterprise Admins, etc.) — c'est un marqueur que l'on recherche systématiquement lors d'un audit AD.

Test d'authentification sur le contrôleur de domaine :

```bash
nxc smb 10.0.0.1 -u 'svc-sql' -p 'MotDePasse123!' -d corp.local
```

```
SMB   10.0.0.1   DC01   [+] corp.local\svc-sql:MotDePasse123! (Pwn3d!)
```

Le marqueur `(Pwn3d!)` indique que le compte dispose des droits d'administration sur la machine cible. Sur un contrôleur de domaine, cela signifie **Domain Admin**.

Domain Admin atteint. Depuis le réseau interne, en passant par un seul serveur obsolète, en quelques commandes. Aucun identifiant n'était nécessaire au départ — l'exploitation d'EternalBlue fournit le premier accès, et les LSA Secrets font le reste.

### L'ampleur des dégâts

Le hash du compte Administrateur local de SRV-COMPTA est testé sur l'ensemble du parc serveur. L'attaque **pass-the-hash** consiste à s'authentifier sur une machine en utilisant directement le hash NTLM d'un compte, sans connaître le mot de passe en clair. Si le hash admin local est identique sur plusieurs machines, un seul hash suffit pour toutes les compromettre :

```bash
nxc smb 10.0.0.0/24 -u Administrateur -H 'aad3b435b51404ee:91240816b98cb3f2' --local-auth --continue-on-success
```

Résultat : une trentaine de serveurs répondent `Pwn3d!`. Le même mot de passe administrateur local partout — pas de LAPS déployé sur les serveurs.

**LAPS** (Local Administrator Password Solution) est un outil Microsoft gratuit qui génère un mot de passe administrateur local unique et aléatoire sur chaque machine, et le stocke dans l'AD. Sans LAPS, les administrateurs définissent souvent le même mot de passe local sur tous les serveurs par commodité — ce qui transforme la compromission d'une seule machine en accès à l'ensemble du parc.

Avec ce hash, accès direct aux hyperviseurs, aux serveurs de backup, aux instances SQL de production, à la ferme RDS. Sur l'un de ces serveurs, un deuxième compte Domain Admin est trouvé dans les LSA Secrets, utilisé par un autre service.

Un seul serveur vulnérable a ouvert la porte à l'ensemble de l'infrastructure.

## 3. Comment y remédier

### Décommissionner les serveurs obsolètes

Pas "quand c'est possible", pas "dès que le budget le permet" — les décommissionner. Un serveur Windows 2003 en production en 2026 n'est pas un héritage technique, c'est une faille béante connectée au réseau.

Si l'application métier ne tourne que sur du 2003, c'est un problème applicatif à traiter avec l'éditeur ou par migration. Ce n'est pas une raison valable pour garder un serveur exploitable en un scan et trois commandes.

### Isoler en attendant

Si le décommissionnement ne peut pas se faire immédiatement :

- Placer le serveur dans un **VLAN dédié**, isolé du réseau utilisateur.
- Restreindre les flux entrants et sortants au strict minimum : uniquement les postes et les protocoles nécessaires au fonctionnement de l'application métier.
- **Couper tout accès vers les contrôleurs de domaine** depuis ce VLAN.
- Couper l'accès depuis les postes utilisateurs — passer par un serveur de rebond durci si nécessaire.
- **Monitorer** toutes les connexions entrantes et sortantes sur ce serveur.

L'isolation ne corrige pas la vulnérabilité. Elle réduit la surface d'exploitation en attendant la décommission.

### Déployer LAPS sur tous les serveurs

LAPS gère automatiquement le mot de passe du compte administrateur local et garantit qu'il est unique sur chaque machine.

Un hash admin local partagé entre une trentaine de serveurs, c'est un mouvement latéral gratuit pour un attaquant. LAPS doit être déployé sur **tous** les serveurs et postes du parc, pas uniquement sur les postes utilisateurs.

### Utiliser des gMSA pour les services

Les **gMSA** (Group Managed Service Accounts) remplacent les comptes de domaine classiques pour l'exécution des services. Contrairement à un compte de domaine classique dont le mot de passe est statique et stocké en clair dans le SCM, les gMSA fonctionnent différemment :

- **Rotation automatique** du mot de passe (tous les 30 jours par défaut).
- Mot de passe de **120 caractères** (240 octets), généré aléatoirement par l'AD.
- **Pas de mot de passe stocké en clair dans le SCM** — la machine récupère le mot de passe directement auprès de l'AD via un canal sécurisé, sans intervention humaine.
- Pas de mot de passe à gérer, pas de mot de passe à oublier de changer.

Les gMSA sont supportés depuis Windows Server 2012 et couvrent la majorité des cas d'usage : services Windows, tâches planifiées, pools IIS.

### Appliquer le principe du moindre privilège sur les comptes de service

Un service SQL Server n'a pas besoin d'être Domain Admin. Un agent de supervision n'a pas besoin d'être Domain Admin. Les services de sauvegarde nécessitent parfois des droits élevés pour sauvegarder les contrôleurs de domaine, mais ces droits doivent être encadrés — compte dédié, mot de passe rotatif via gMSA, et surtout pas le même compte utilisé pour d'autres services sur des serveurs non durcis.

Le principe du moindre privilège n'est pas un concept théorique — c'est la différence entre "l'attaquant a compromis un serveur" et "l'attaquant a compromis tout le domaine".

Chaque compte de service doit avoir uniquement les permissions nécessaires à son fonctionnement. Les comptes de service doivent être inventoriés et leurs privilèges vérifiés régulièrement.

## Conclusion

Un seul serveur obsolète, oublié sur le réseau, a suffi pour compromettre l'ensemble du domaine Active Directory. Pas d'exploit zero-day, pas de technique avancée, pas de contournement d'EDR — juste une faille publique de 9 ans, un mot de passe de service en clair et un compte avec trop de privilèges.

Le chemin complet : scan réseau, exploit public, dump des LSA Secrets, Domain Admin. Quatre étapes, quelques commandes, et l'intégralité de l'infrastructure est compromise.

Les serveurs obsolètes ne sont pas un risque acceptable. Ce sont des portes ouvertes.
