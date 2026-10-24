---
title: "TITLE — Web Security Deep Dive"
date: YYYY-MM-DD
categories: [Web Security]
tags: [tag1, tag2, tag3]    # e.g.: sqli, xss, ssrf, idor, authentication, deserialization
description: "One-line summary."
image:
  path: /assets/img/posts/web/SLUG-banner.png
  alt: "TITLE"
---

## TL;DR

<!-- 2-3 sentences: what this is about, why it matters -->

## Context

<!-- Where this technique/vuln applies, threat model -->

## Technical Analysis

### How it works

<!-- Detailed explanation with diagrams if needed -->

### Vulnerable Code Pattern

```python
# Example of vulnerable code
```

### Exploitation

<!-- Step-by-step exploitation with code/commands -->

```http
POST /api/endpoint HTTP/1.1
Host: target.com
Content-Type: application/json

{"payload": "value"}
```

### Impact

<!-- What an attacker gains — data, access, RCE, etc. -->

## Detection & Mitigation

### For Defenders

- Mitigation 1
- Mitigation 2

### Secure Code Pattern

```python
# Fixed version
```

## References

- [Reference 1](URL)
- [Reference 2](URL)
