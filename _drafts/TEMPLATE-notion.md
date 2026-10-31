---
title: "NOTION — Fonctionnement, attaques et durcissement"
date: 2026-01-01 10:00:00 +0100
categories: [Active Directory]      # ou [Web Security], [Cloud]…
tags: [tag1, tag2, tag3]            # ex. kerberos, ntlm, ldap, kerberoasting, relay
description: "Une phrase : la notion, ce qu'on peut en faire en attaque, comment s'en protéger."
image:
  path: /assets/img/posts/active-directory/SLUG-banner.png
  alt: "NOTION"
---

> **TL;DR** — 2 à 3 phrases : ce qu'est la notion, pourquoi elle est intéressante pour un attaquant,
> et la mesure de durcissement la plus rentable.
{: .prompt-info }

| | |
|---|---|
| **Niveau** | Débutant / Intermédiaire / Avancé |
| **Prérequis** | Notions nécessaires pour suivre l'article |
| **Attaques couvertes** | Attaque 1, Attaque 2, Attaque 3 |
| **Outils** | impacket, nxc, Rubeus, BloodHound… |

## 1. La notion

### 1.1 À quoi ça sert

<!-- Le rôle de la notion dans le SI, sans jargon inutile -->

### 1.2 Comment ça marche

<!-- Échanges, messages, champs importants. Un schéma vaut mieux qu'un paragraphe : -->

```text
Client                         Serveur
  │ ── 1. Requête ───────────────▶ │
  │ ◀─ 2. Réponse ──────────────── │
```

### 1.3 Ce qu'il faut retenir pour la suite

<!-- Les 3-4 propriétés du protocole qui rendent les attaques possibles -->

## 2. Surface d'attaque

<!-- Quels éléments du fonctionnement sont abusables, et avec quel niveau d'accès -->

| Élément abusable | Accès requis | Attaque associée |
|------------------|--------------|------------------|
| … | Aucun / Utilisateur du domaine / Admin local | § 3.1 |

## 3. Attaques

<!-- Une sous-section par attaque, toujours dans le même ordre -->

### 3.1 NOM DE L'ATTAQUE

**Principe** —
<!-- Le mécanisme abusé, en lien avec la section 1 -->

**Prérequis** —
<!-- Accès, droits, configuration nécessaire -->

**Exploitation**

```bash
# Commande commentée
```

**Résultat / impact** —
<!-- Ce que l'attaquant obtient -->

### 3.2 NOM DE L'ATTAQUE

**Principe** —

**Prérequis** —

**Exploitation**

```bash
```

**Résultat / impact** —

## 4. Vulnérabilités et mauvaises configurations courantes

<!-- Ce qu'on retrouve réellement en audit : configurations par défaut, CVE, erreurs d'admin -->

| Constat | Pourquoi c'est dangereux | Comment le vérifier |
|---------|--------------------------|---------------------|
| … | … | `commande` |

## 5. Détection

| Attaque | Source / Event ID | Signal à surveiller |
|---------|-------------------|---------------------|
| § 3.1 | 4769 / Security | … |

## 6. Recommandations

| Priorité | Mesure | Bloque |
|----------|--------|--------|
| <span class="sev sev-critical">Critique</span> | … | § 3.1 |
| <span class="sev sev-high">Haute</span> | … | § 3.2 |
| <span class="sev sev-medium">Moyenne</span> | … | … |

## 7. Bonnes pratiques

<!-- Ce qui relève de l'hygiène à long terme, au-delà des correctifs ponctuels -->

- [ ] Bonne pratique 1
- [ ] Bonne pratique 2
- [ ] Bonne pratique 3

## Références

- [Documentation officielle](URL)
- [Article de recherche](URL)
