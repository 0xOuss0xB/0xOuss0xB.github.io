---
title: "TITLE — Active Directory Attack Technique"
date: YYYY-MM-DD
categories: [Active Directory]
tags: [tag1, tag2, tag3]    # e.g.: kerberos, ntlm, acl-abuse, bloodhound, dcsync, delegation
description: "One-line summary."
image:
  path: /assets/img/posts/active-directory/SLUG-banner.png
  alt: "TITLE"
---

## TL;DR

<!-- 2-3 sentences: what the technique is, when to use it -->

## Prerequisites

- **Access level needed:** Domain user / Local admin / etc.
- **Tools:** BloodHound, Impacket, Rubeus, etc.
- **Lab environment:** Windows Server version, domain setup

## Attack Theory

<!-- Explain the underlying AD mechanism being abused -->

### Why this works

<!-- The design flaw or misconfiguration that enables this -->

## Attack Walkthrough

### Step 1 — Enumeration

```powershell
# Discovery commands
```

### Step 2 — Exploitation

```bash
# Attack commands
```

### Step 3 — Post-Exploitation

```bash
# Leveraging the result
```

## BloodHound Perspective

<!-- How this shows up in BloodHound, what edges to look for -->

## Detection

| Indicator | Event ID / Source | What to look for |
|-----------|------------------|------------------|
| Indicator 1 | 4768 / Security | Detail |
| Indicator 2 | Sysmon | Detail |

## Mitigation

- Mitigation 1
- Mitigation 2

## References

- [Reference 1](URL)
- [Reference 2](URL)
