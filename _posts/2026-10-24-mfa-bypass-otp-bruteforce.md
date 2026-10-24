---
title: "Bypass MFA — Quand le TOTP remplace le mot de passe au lieu de le compléter"
date: 2026-10-24
categories: [Web Security]
tags: [authentication-bypass, mfa, otp, bruteforce, cwe-307]
description: "Bypass complet du MFA — l'endpoint TOTP ne vérifie jamais le mot de passe, un bruteforce de 6 chiffres suffit pour obtenir un JWT."
---

## TL;DR

Lors d'un pentest, on identifie que l'endpoint de vérification TOTP (`/api/authentication/verifyTotp`) est accessible **sans authentification préalable par mot de passe**. Il suffit de connaître l'email d'un utilisateur pour bruteforcer le code à 6 chiffres et récupérer un JWT. Aucun rate limiting, aucun lockout.

> **Disclaimer :** Test réalisé dans le cadre d'une mission autorisée.
{: .prompt-danger }

---

## La vulnérabilité

### L'endpoint est ouvert

En interceptant la requête de vérification TOTP :

```http
POST /api/authentication/verifyTotp HTTP/1.1
Content-Type: application/json

{
  "email": "target@example.com",
  "totpCode": "123456",
  "tokenDurationType": "STANDARD"
}
```

Pas de cookie de session, pas de header `Authorization`, pas de token issu d'un login préalable. Juste un email et un code TOTP.

On teste directement depuis un terminal, sans interaction préalable avec l'application :

```bash
curl -s https://[REDACTED]/api/authentication/verifyTotp \
  -H "Content-Type: application/json" \
  -d '{"email":"target@example.com","totpCode":"000000","tokenDurationType":"STANDARD"}'
```

```json
{"success":false,"message":"wrongTotp"}
```

Le serveur ne répond pas `401 Unauthorized`. Il accepte la requête et compare le code. **Le mot de passe n'est jamais vérifié.**

> Le MFA ici n'est pas du multi-factor. C'est du single-factor à 6 chiffres.
{: .prompt-warning }

### Pas de rate limiting

Il a été identifié qu'aucun mécanisme de rate limiting n'est en place sur cet endpoint. Pas de lockout, pas de CAPTCHA, pas d'invalidation du code après N échecs.

La réponse pour un mauvais code fait **93 octets**. Un bon code retourne le JWT dans un body plus large avec `"success":true`.

### Le pattern vulnérable (reconstitué)

```python
@app.route("/api/authentication/verifyTotp", methods=["POST"])
def verify_totp():
    email = request.json.get("email")
    code = request.json.get("totpCode")

    user = db.find_user(email)
    expected = get_current_totp(user.secret)

    if code == expected:
        token = generate_jwt(user)
        return {"success": True, "accountAuthDTO": {"accessToken": token}}

    return {"success": False, "message": "wrongTotp"}
```

---

## Impact

- Takeover de n'importe quel compte en connaissant juste l'email
- Le mot de passe est complètement contourné
- 1 000 000 de combinaisons (000000–999999) → bruteforceable en quelques minutes avec un script multi-threadé

CVSS 3.1 : `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` → **9.1 (Critique)**

---

## Remédiation

**Session binding** — l'endpoint TOTP ne doit être accessible qu'après validation du mot de passe. L'email doit venir de la session serveur, pas du body :

```python
@app.route("/api/authentication/verifyTotp", methods=["POST"])
def verify_totp():
    if not session.get("password_verified"):
        return {"message": "Unauthorized"}, 401

    email = session["authenticated_user"]
    code = request.json.get("totpCode", "")
    # ...
```

**Rate limiting** — lockout après 5 échecs, expiration du code à 2 min, usage unique.

---

## Références

- [CWE-307 — Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [OWASP MFA Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [PortSwigger — 2FA Bypass Using Brute Force](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-bypass-using-a-brute-force-attack)
