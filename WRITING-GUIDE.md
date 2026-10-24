# 0xOuss0xB Blog — Writing Guide

## Blog Architecture

### Categories

| Category | Slug | Description | Example Topics |
|----------|------|-------------|----------------|
| **Writeups** | `Writeups` | CTF and lab walkthroughs | HTB boxes, HackSmarter labs, TryHackMe |
| **Web Security** | `Web Security` | Web application exploitation | SQLi, XSS, SSRF, IDOR, deserialization, auth bypass |
| **Active Directory** | `Active Directory` | AD attack techniques | Kerberos, NTLM, ACL abuse, delegation, GPO abuse |
| **External Pentest** | `External Pentest` | External/network pentest | Recon, exposed services, network attacks |
| **CVE Analysis** | `CVE Analysis` | Vulnerability deep dives | CVE research, PoCs, patch analysis |
| **Tools** | `Tools` | Tool reviews & custom scripts | Offensive tools, automation, scripts |
| **AI & Cyber** | `AI & Cyber` | AI meets cybersecurity | LLM security, AI-assisted pentesting, prompt injection |
| **Mobile** | `Mobile` | Mobile app security | Android/iOS, static & dynamic analysis, Frida |
| **Cloud** | `Cloud` | Cloud security | AWS/Azure/GCP misconfig, IAM abuse, container escape |
| **Code Audit** | `Code Audit` | Source code review | Whitebox analysis, SAST, vuln discovery |
| **Articles** | `Articles` | General methodology & insights | Career tips, methodology, field observations |

> Chaque catégorie a son dossier d'images : `assets/img/posts/<slug-dossier>/`
> (`web`, `active-directory`, `external`, `cve`, `tools`, `ai-cyber`, `mobile`, `cloud`, `code-audit`, `articles`, `research`).

### Writeup Sub-categories (second level)

Use two-level categories for writeups:
- `categories: [Writeups, HTB]`
- `categories: [Writeups, HackSmarter]`
- `categories: [Writeups, TryHackMe]`
- `categories: [Writeups, VulnLab]`

**Convention d'images pour les writeups :** un dossier dédié par box/lab,
`assets/img/posts/<nom-de-box>/` (ex. `city-council/`, `stellarcomms/`),
et non le dossier d'une catégorie.

### Standard Tags

**Technique tags** (lowercase, hyphenated):
`sqli`, `xss`, `ssrf`, `idor`, `rce`, `lfi`, `deserialization`, `authentication-bypass`,
`kerberoasting`, `asreproasting`, `dcsync`, `ntlm`, `acl-abuse`, `delegation`,
`privilege-escalation`, `credential-theft`, `lateral-movement`, `persistence`

**Tool tags:**
`bloodhound`, `impacket`, `burpsuite`, `nuclei`, `nmap`, `responder`, `mimikatz`,
`rubeus`, `certipy`, `ffuf`, `sqlmap`, `hashcat`

**Platform tags:**
`active-directory`, `linux`, `windows`, `cloud`, `aws`, `azure`, `docker`, `kubernetes`

---

## Post Creation Checklist

### File Naming
```
_posts/YYYY-MM-DD-slug-title.md
```
- Date: publication date
- Slug: lowercase, hyphens, no special chars
- Example: `2026-10-25-kerberoasting-from-linux.md`

### Front Matter (required)
```yaml
---
title: "Clear, Descriptive Title"
date: YYYY-MM-DD HH:MM:SS +0200   # heure + timezone : évite les posts "futurs" non publiés
categories: [Category]           # or [Category, SubCategory]
tags: [tag1, tag2, tag3]         # 3-8 tags, lowercase
description: "One compelling sentence for SEO and social previews."
image:
  path: /assets/img/posts/CATEGORY/slug-banner.png
  alt: "Alt text for accessibility"
---
```

### Images
- **Banner:** 1200x630px (OG/social optimal), placed in `assets/img/posts/<category>/`
- **Screenshots:** place in same directory as banner
- **Format:** PNG for screenshots, WebP for photos if possible
- Reference with: `![Alt text](/assets/img/posts/category/filename.png)`

### Writing Style
- **Language:** English preferred, French acceptable (bilingual blog)
- **Tone:** Technical but accessible — explain *why*, not just *how*
- **Code blocks:** Always specify the language for syntax highlighting
- **TL;DR:** Start every article with a 2-3 sentence summary
- **Disclaimer:** Add for writeups and CVE PoCs
- **Lessons Learned / Detection:** Include a blue-team perspective when relevant

---

## Templates

All templates are in `_drafts/`:

| Template | Use for |
|----------|---------|
| `TEMPLATE-writeup.md` | CTF/lab writeups |
| `TEMPLATE-web-security.md` | Web exploitation articles |
| `TEMPLATE-active-directory.md` | AD attack techniques |
| `TEMPLATE-cve-analysis.md` | CVE deep dives |
| `TEMPLATE-tools.md` | Tool reviews |
| `TEMPLATE-ai-cyber.md` | AI & cybersecurity |
| `TEMPLATE-external-pentest.md` | External pentest techniques |

### How to use a template

```bash
cp _drafts/TEMPLATE-writeup.md _posts/2026-10-25-box-name-writeup.md
```

Then fill in the placeholders.

---

## Content Roadmap — Target: 20-30 articles by end of December 2026

### Priority Topics (suggested)

**Web Security:**
- SSRF exploitation patterns in modern apps
- JWT attack surface: none/alg confusion/key injection
- OAuth misconfigurations in the wild

**Active Directory:**
- Kerberoasting from Linux — full methodology
- ADCS abuse (ESC1-ESC8) cheat sheet
- BloodHound CE: what's new and how to use it

**CVE Analysis:**
- Pick 2-3 CVEs you've encountered in engagements
- Focus on CVEs with interesting root causes

**Tools:**
- Your pentesting toolkit walkthrough
- Custom scripts you've built

**AI & Cyber:**
- Using LLMs for recon automation
- AI-assisted code review: offensive perspective

---

## Quick Reference

```bash
# Create new post from template
cp _drafts/TEMPLATE-TYPE.md _posts/$(date +%Y-%m-%d)-slug-title.md

# Preview locally
bundle exec jekyll serve --drafts

# Build
bundle exec jekyll build
```
