---
title: "JWT Attacks: A Pentester's Playbook Through Real Scenarios"
date: 2026-04-24 10:00:00 +0300
categories: [Web Security, Pentest]
tags: [jwt, authentication, web-security, offensive-security, pentest]
description: "From alg:none to kid injection, from algorithm confusion to jku manipulation — the JWT attack surface walked through real pentest scenarios."
image:
  path: /assets/rose.jpg
---

JWT (JSON Web Token) is the de facto standard for session handling in most modern web apps. It's stateless, plays nicely with microservices, and looks simple to implement. That last part is exactly why it's a goldmine on the offensive side. JWT itself isn't bad — what's bad is that almost every library ships with at least one default that will burn someone.

This post leans on scenarios rather than theory. Each section walks through the logic of an attack, how to spot it on a bug bounty or pentest, and a short working example.

## A Quick Refresher

A JWT has three parts separated by dots:

```
<base64url(header)>.<base64url(payload)>.<signature>
```

- **Header**: `alg` (signing algorithm) and `typ`.
- **Payload**: Claims — `sub`, `iat`, `exp`, `role`, etc.
- **Signature**: Header and payload signed with the chosen algorithm.

Header and payload are **not encrypted** — just base64url-encoded, so anyone can read them. All the security rides on signature verification. And that's exactly what almost every JWT attack goes after: *bypass the check, or re-sign the token with a key you control.*

To decode a token by hand:

```bash
echo "eyJhbGciOi..." | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

The first thing I do on any engagement: look at the header and payload. Sometimes no attack is needed — sensitive data is already sitting in plain view.

## Scenario 1 — `alg: none`

**Situation.** You log into an application and get handed this token:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIifQ.<signature>
```

You decode the payload and see `role: user`. If you could flip that to `admin`, the admin panel opens up — and with it, a whole new surface of IDORs to chain.

**Attack.** The JWT spec defines a value called `alg: none`. Translation: "this token isn't signed, don't bother verifying." Plenty of libraries — older versions of `node-jsonwebtoken`, certain `pyjwt` releases — accept this if the server doesn't pin the algorithm explicitly.

You can build the token by hand:

```python
import base64, json

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "user", "role": "admin"}

def b64(obj):
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

# No signature — just end with a dot
token = f"{b64(header)}.{b64(payload)}."
print(token)
```

**Things to watch for.** Don't stop at `none` — try `None`, `NONE`, `nOnE`. Plenty of libraries block the lowercase string but wave the capitalized versions right through. Also keep that trailing dot. A valid `alg:none` token still has two dots; the signature is just empty. Drop the last dot entirely and some parsers will reject the token outright.

**Defense.** Server-side: `jwt.verify(token, key, { algorithms: ['HS256'] })` — always pin the algorithm. `verify` calls without an algorithms list are still out there, and they still break.

## Scenario 2 — Weak Secret HS256 Brute-Force

**Situation.** Token is signed with `HS256`. `alg: none` doesn't work. You want to tamper with the header and payload, but you need the secret to forge a valid signature.

**Attack.** HS256 is symmetric — the same key signs and verifies. So if we can recover it, we can forge any token we want. And plenty of developers set this secret to `secret`, `password`, `changeme`, the app name, or something equally guessable.

Run offline brute-force with `hashcat` or `john`:

```bash
# hashcat mode 16500 = JWT
hashcat -m 16500 -a 0 token.txt /usr/share/wordlists/rockyou.txt
```

Drop the token straight into `token.txt`; hashcat splits the three parts itself. For wordlists, start with `rockyou.txt`. Then move to SecLists' `Passwords/Common-Credentials/10-million-password-list-top-1000000.txt`. What actually pays off most often, though, is a custom list built from app-specific terms — company name, domain, product variants.

Once you have the secret, you sign whatever payload you want:

```python
import jwt
token = jwt.encode({"sub": "user", "role": "admin"}, "recovered_secret", algorithm="HS256")
```

**Things to watch for.** Cracking is fully offline — millions of attempts per second per token. If the secret is under 12 characters and dictionary-based, your odds are strong. Didn't land on the first list? Run a second pass with a bigger list and rule-based mutations (hashcat's `-r` flag).

**Defense.** 256-bit random secret (`openssl rand -hex 32`), keep it in env/secret manager, rotate it.

## Scenario 3 — Algorithm Confusion (RS256 → HS256)

This is one of the most satisfying JWT bugs to find in the wild.

**Situation.** Token is signed with `RS256`. The server uses asymmetric signing: *private key* to sign, *public key* to verify. The public key is usually exposed on an endpoint — `/jwks.json`, `/.well-known/jwks.json`, or the discovery URL of an OAuth provider.

**Attack.** Some libraries just trust the `alg` header. Call `verify(token, key)` without pinning the algorithm, and they'll use whatever the token asks for. So the attacker flips `alg` to `HS256`, uses the public key as the HMAC secret, and re-signs the token. The server then feeds its own RS256 public key into its HS256 verifier — and the signature checks out.

Flow:

1. Fetch the public key: `curl https://target.com/.well-known/jwks.json`, or pull the PEM from the cert.
2. Save it in PEM format (`public.pem`).
3. Regenerate the token:

```python
import jwt

with open("public.pem", "rb") as f:
    public_key = f.read()

forged = jwt.encode(
    {"sub": "admin", "role": "admin"},
    public_key,       # used as HMAC secret
    algorithm="HS256"
)
```

**The critical detail.** The public key has to be in **exactly** the format the server uses — PEM, correct newlines, `-----BEGIN PUBLIC KEY-----` header. One byte off and the signature won't match. If you're pulling from JWKS and need to convert to PEM, `jwcrypto` or `cryptography` makes it painless:

```python
from jwcrypto import jwk
key = jwk.JWK.from_json(json.dumps(jwks_entry))
print(key.export_to_pem().decode())
```

**Defense.** Whitelist the accepted algorithm — `algorithms=["RS256"]`. And keep symmetric and asymmetric verification paths strictly separate, so the same key material can never end up in the wrong one.

## Scenario 4 — Injection Through the `kid` Header

**Situation.** You spot a `kid` (Key ID) field in the header:

```json
{"alg": "HS256", "typ": "JWT", "kid": "key-001"}
```

The server takes that `kid` and looks up the key in a file, a database, or a directory. If the value isn't sanitized, you've got three different injection vectors.

### 4a. Path Traversal

If the server reads the key file from disk using `kid`:

```python
kid = request_header["kid"]
key = open(f"/app/keys/{kid}").read()
```

Setting `kid` to `../../../../dev/null` makes the key an empty string. Some HMAC libraries happily accept an empty string as the secret — so you sign your token with `""`, and the signature verifies.

```python
import jwt
forged = jwt.encode(
    {"role": "admin"},
    "",
    algorithm="HS256",
    headers={"kid": "../../../../dev/null"}
)
```

The same idea works with any file whose contents you can predict — `/proc/sys/kernel/randomize_va_space` usually contains just `2`, so you'd sign the token with `"2\n"` instead of an empty string.

### 4b. SQL Injection

If the server looks up the key in a database:

```python
query = f"SELECT key FROM keys WHERE id = '{kid}'"
```

A `kid` payload like `' UNION SELECT 'knownSecret'-- -` makes the query return a secret of your choosing. Classic SQLi — the JWT flow is just the injection point.

### 4c. Command Injection

Rarer but it does show up: `kid` being passed into a shell command, giving you OS command injection.

**Defense.** Whitelist `kid` values, use parameterized queries, treat the field as user input. Being in a header doesn't make it safe.

## Scenario 5 — `jku` and `x5u` Manipulation

**Situation.** The header looks like this:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://target.com/jwks.json"
}
```

`jku` (JWK Set URL) tells the server "verify the signature with the public key at this URL." `x5u` is the same idea with an X.509 certificate.

**Attack.** If the server fetches `jku` without restriction:

1. Generate your own private/public key pair.
2. Publish the public key as JWKS on a server you control.
3. Sign the token with your private key and point `jku` at your URL.
4. The server fetches your key, verifies the signature, and accepts the token.

If there's a filter, common bypasses:

- **Open redirect**: `jku: https://target.com/redirect?url=https://attacker.com/jwks.json` — works when the server only validates the domain.
- **URL parsing discrepancies**: `https://target.com@attacker.com/jwks.json`, `https://target.com#@attacker.com/jwks.json` — some parsers read the host as `target.com` while the HTTP client actually reaches out to `attacker.com`.
- **Subdomain takeover**: if the target owns a subdomain it no longer controls, host JWKS there.

**Defense.** Strict whitelist of allowed `jku`/`x5u` values. Better yet, use a fixed key on the server and ignore these headers entirely.

## Scenario 6 — Claim Manipulation and Logic Flaws

Even when signature verification is rock solid, how the app reads the claims is a whole separate attack surface.

**No `exp` check.** Token expired a year ago, but the app still accepts it. Leaked tokens live forever.

**Trusting the wrong claim.** The app identifies users by the `username` claim instead of a stable identifier like `sub`. Change `username` in your own token to someone else's — if the server trusts that field, you're them.

**Role hierarchy confusion.** Send `role: admin` to a parser that expects `roles: ["admin"]` (or the other way around) and it might fall back to a default. Type confusion shows up too — `isAdmin: "false"` as a string, where `Boolean("false") === true`.

**Sensitive data inside JWTs.** The payload isn't encrypted. I've seen user IDs, emails, internal service names, and occasionally DB connection strings or API keys sitting in there. Not an attack per se, but it makes for a high-value informational finding.

## Scenario 7 — Replay and Missing Invalidation

Because JWTs are stateless, there's no "logout" at the library level. If a developer didn't build a blacklist manually, a stolen token stays valid until `exp`.

Test these on every engagement:

- Does the same token still work after logout?
- Is the old token still valid after a password change?
- Are tokens being rotated, or is there just a long `exp`?

An answer of "yes, still works" is a finding under most compliance frameworks.

## A Quick Pentest Checklist

When you see a JWT, in order:

1. Decode header and payload. Any sensitive data?
2. Try `alg: none` and its variants.
3. If HS256, kick off offline brute-force (hashcat mode 16500).
4. If RS256, hunt for the public key, try HS256 confusion.
5. If `kid`, `jku`, or `x5u` are present, test them for injection/SSRF.
6. Tamper authorization fields in the payload — `role`, `isAdmin`, `user_id`.
7. Verify that `exp`, `nbf`, `iss`, `aud` checks are enforced.
8. Test token validity after logout and password change.
9. Send different algorithms (`HS512`, `RS384`, etc.) and watch the library's behavior.

On the tooling side, [jwt_tool](https://github.com/ticarpi/jwt_tool) covers most of these and is great for quick triage. It doesn't replace manual checking — and it shouldn't — but it's a useful first sweep.

## Closing

Most JWT attacks ride on the same handful of developer mistakes: not pinning the algorithm, leaving the secret weak, trusting header fields. That's why when I see a JWT, I'm not thinking about the spec — I'm thinking about what the developer probably got wrong. Libraries change, frameworks change. Developers who forget to write `algorithms=[...]` don't.

If you're the one building the API: whitelist algorithms, use long random secrets, treat `kid`/`jku`/`x5u` like user input, keep `exp` short, and implement server-side invalidation for logout. JWT isn't something that feels secure — it's something that works when you configure it correctly.
