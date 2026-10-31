# 0xOuss0xB — Guide de rédaction

## 1. Les trois types d'articles

Chaque article appartient à l'une de ces familles. Chacune a son template dans `_drafts/`.

| Type | Template | Pour quoi | Exemple |
|------|----------|-----------|---------|
| **Notion** | `TEMPLATE-notion.md` | Expliquer une notion technique de bout en bout : fonctionnement → attaques → vulnérabilités → détection → recommandations → bonnes pratiques | Kerberos, NTLM, LDAP, ADCS |
| **Writeup** | `TEMPLATE-writeup.md` | Walkthrough d'un lab / CTF | City Council, StellarComms |
| **Finding** | `TEMPLATE-finding.md` | Une vulnérabilité rencontrée en audit (anonymisée) | Bypass MFA TOTP |

Templates secondaires : `TEMPLATE-cve-analysis.md`, `TEMPLATE-tools.md`.

```bash
cp _drafts/TEMPLATE-notion.md _posts/$(date +%Y-%m-%d)-kerberos.md
```

## 2. Catégories

Peu de catégories, beaucoup de tags. Une catégorie n'apparaît sur le site qu'à partir du premier article.

| Catégorie | Contenu | Dossier d'images |
|-----------|---------|------------------|
| `Active Directory` | Notions et attaques AD | `active-directory/` |
| `Web Security` | Notions et findings web / API | `web/` |
| `Writeups` + sous-catégorie | `[Writeups, HTB]`, `[Writeups, HackSmarter]`, `[Writeups, TryHackMe]`, `[Writeups, VulnLab]` | un dossier par lab (`city-council/`) |
| `CVE Analysis` | Analyses de CVE | `cve/` |
| `Tools` | Outils, scripts | `tools/` |
| `Pentest Notes` | Méthodo, retours terrain, IA & cyber | `articles/` |

Avant d'ajouter une nouvelle catégorie (Cloud, Mobile…), attendre d'avoir au moins 2 articles à y mettre.

## 3. Tags

Minuscules, séparés par des tirets, 3 à 8 par article.

- **Notions :** `kerberos`, `ntlm`, `ldap`, `adcs`, `dpapi`, `gmsa`, `mfa`, `jwt`, `oauth`
- **Techniques :** `kerberoasting`, `asreproasting`, `delegation`, `ntlm-relay`, `coercion`, `pass-the-hash`, `pass-the-ticket`, `dcsync`, `acl-abuse`, `privilege-escalation`, `lateral-movement`, `credential-theft`, `authentication-bypass`, `sqli`, `xss`, `ssrf`, `idor`
- **Outils :** `bloodhound`, `impacket`, `nxc`, `rubeus`, `certipy`, `responder`, `ntlmrelayx`, `burpsuite`, `hashcat`
- **Plateforme :** `active-directory`, `windows`, `linux`, `cloud`
- **Référentiels :** `cwe-xxx`, `cve-xxxx-xxxxx`

## 4. Front matter

```yaml
---
title: "Titre clair"
date: 2026-11-15 10:00:00 +0100   # toujours avec heure + fuseau, sinon le post peut être considéré comme futur
categories: [Active Directory]
tags: [kerberos, kerberoasting]
description: "Une phrase pour le SEO et les aperçus de partage."
image:                            # optionnel — ne pas mettre de chemin vers une image qui n'existe pas
  path: /assets/img/posts/active-directory/kerberos-banner.png
  alt: "Kerberos"
---
```

Attention au fuseau : `+0200` en heure d'été, `+0100` en hiver.

## 5. Structure commune à tous les articles

1. **TL;DR** en encadré, juste sous le front matter :

   ```markdown
   > **TL;DR** — Deux ou trois phrases.
   {: .prompt-info }
   ```

2. **Fiche** : petit tableau à deux colonnes (`| | |`) avec le contexte (plateforme, cible, niveau, sévérité…).
3. **Sections numérotées** en `##` (`## 1. La notion`, `## 2. …`), sous-sections en `###` (`### 1.1 …`). La table des matières se génère automatiquement.
4. **Toujours expliquer le pourquoi avant le comment** : `Principe` → `Exploitation` → `Résultat`.
5. **Fin d'article** : `Recommandations` (tableau priorisé) puis `Références`.

Pas besoin de `---` entre les sections : le style ajoute déjà un séparateur sous chaque `##`.

## 6. Éléments de mise en forme

| Élément | Syntaxe |
|---------|---------|
| Encadré info / astuce / attention / danger | `{: .prompt-info }`, `{: .prompt-tip }`, `{: .prompt-warning }`, `{: .prompt-danger }` sous un `>` |
| Badge de sévérité | `<span class="sev sev-critical">Critique</span>` (`sev-high`, `sev-medium`, `sev-low`, `sev-info`) |
| Chaîne d'attaque / schéma | bloc ` ```text ` avec `→`, `↓`, `│` |
| Code | toujours préciser le langage (`bash`, `powershell`, `http`, `python`) |
| Image | `![Description](/assets/img/posts/<dossier>/<fichier>.png)` — PNG pour les captures |

## 7. Style

- Français, ton technique mais accessible. Les termes consacrés restent en anglais (*ticket*, *relay*, *hash*, *DACL*).
- Une capture = une preuve ; la commande correspondante doit aussi être en texte pour pouvoir être copiée.
- Sur un article *Notion*, chaque attaque doit renvoyer vers la propriété du protocole qu'elle abuse, et chaque recommandation vers l'attaque qu'elle bloque.
- Les findings d'audit sont **anonymisés** (client, URL, noms, données).

## 8. Commandes

```bash
bundle exec jekyll serve --drafts   # prévisualisation locale (http://127.0.0.1:4000)
bundle exec jekyll build            # build
```
