---
title: "GraphQL Vulnerabilities from an Attacker's Perspective"
date: 2026-06-06 16:20:00 +0300
categories: [Web Security, GraphQL]
tags: [graphql, bug-bounty, api-security, idor]
description: "What GraphQL vulnerabilities are and how to find them in bug bounty — introspection, IDOR/BOLA, injection, and rate-limit bypass via batching, explained from scratch with examples."
---

## Introduction

GraphQL is one of the most overlooked attack surfaces in bug bounty. The reason is simple: most developers assume authorization is enforced at the wrong layer, and the fact that everything lives behind a single endpoint misleads testers. In this post I'll build up what GraphQL actually is from scratch, then walk through its vulnerabilities with examples.

---

## First, What Is GraphQL For?

Think of it like a restaurant.

**The old-style API (REST)** is like a fixed menu. Every dish has a number. You order "dish number 5," and the kitchen brings out a ready-made plate. Want something different? You order a different number. In other words, every piece of data has its own address: one address returns the user, one returns products, one returns orders.

**GraphQL** is the opposite — you tell the kitchen exactly what you want on your plate. "I'll have chicken, but only the breast, sauce on the side, and add these two vegetables." One order, a result tailored to you. So there's a single address (`/graphql`), and you send it a list saying "I want these specific fields, in this shape," and it returns exactly that.

That list is called a **query**. There are two kinds of requests:

- **query** = "give me data" (read)
- **mutation** = "change something" (create, update, delete)

And this is exactly where the whole security problem comes from:

In REST, every address is its own door, so the check happens naturally at each door. In GraphQL there's a single door; the developer locks that door but often forgets the check on each piece of data inside it ("does this belong to you?"). Every vulnerability below traces back to those forgotten internal checks. Let's go through them one by one.

---

## 1. The API Describes Itself (Introspection)

GraphQL ships with a built-in feature: you can ask the API "what do you have, what can you do?" and it dumps its entire structure back to you. You can see every piece of data it holds and every operation (mutation) it exposes.

```graphql
query {
  __schema {
    queryType { name }
    mutationType { name }
  }
}
```

This query hands you a list of "here's what you can read, here's what you can do." The valuable part: you'll find hidden operations here that never appear in the UI but sit in the backend — things like "delete user" or "change role."

> Even when introspection is disabled, most servers return a "did you mean...?" suggestion when you mistype a field name. Those suggestions leak the schema too, so disabling introspection rarely amounts to full protection. (Tools like `clairvoyance` can rebuild a schema from these suggestions alone.)
{: .prompt-info }

---

## 2. Accessing Someone Else's Data

This is one of the highest-paying findings in GraphQL bug bounty. The logic is simple: you tell the API "fetch user number 1337," and the system hands the data over **without ever checking "are you this user?"**

```graphql
query {
  user(id: "1337") {
    email
    phone
    privateNotes
  }
}
```

If you're user number 842, and changing the id to 1337 lets you pull someone else's email and phone, you've got a vulnerability. The developer assumed "if you got through the door, you're authorized," but forgot to put a separate check on each individual piece of data.

This vulnerability is called **IDOR** or **BOLA** (short for "Broken Object Level Authorization" — the authorization check at the object level is broken). Don't let the name confuse you; it means exactly what I just described: when you ask for someone else's record, the system hands it over without objection.

---

## 3. Hidden Admin Operations

Take the hidden operations you discovered via introspection in step 1 and try them. Say there's an operation like "change a user's role" that a regular user should never be able to call:

```graphql
mutation {
  updateUserRole(userId: "842", role: "ADMIN") {
    role
  }
}
```

If this works and you can actually make yourself an admin, you've escalated from an ordinary user to an administrator. Same root cause again: the operation's door was left open, with no "are you allowed to do this?" check in place.

---

## 4. Your Input Becomes a Backend Command (Injection)

You send a filter or search value. That value gets used to build a database query behind the scenes. If you slip a malicious expression into it, you can bend that database query in your favor.

```graphql
query {
  products(filter: "1' OR '1'='1") {
    name
    price
  }
}
```

The `1' OR '1'='1` here is a classic SQLi trick that means "treat every condition as true." If the system embeds this value into the query as-is, you can disable the filter and pull data you were never meant to see. This is the GraphQL-borne version of the classic web SQL injection.

---

## 5. Bypassing Rate Limits with Batched Requests

Normally, if you try a wrong password or verification code too many times, the system blocks you (this is called **rate limiting**). But GraphQL has a feature: **you can pack hundreds, even thousands, of attempts into a single request.** The blocking mechanism counts it as "this person sent 1 request" and never blocks you, while thousands of attempts run inside that one request.

The thing that makes this possible is called an **alias** — basically the labels you assign so you can ask for the same operation multiple times within one request. For example, to crack a 4-digit SMS verification code:

```graphql
mutation {
  d0: verifyOtp(code: "0000") { token }
  d1: verifyOtp(code: "0001") { token }
  d2: verifyOtp(code: "0002") { token }
  # ... d9999: verifyOtp(code: "9999") { token }
}
```

The `d0`, `d1`, `d2` here are just labels. In a single request you try every code from 0000 to 9999. Since the system sees this as "one request," you never hit the attempt limit. Try this on SMS/email verification codes, password reset codes, discount coupons, and login screens. 2FA bypass and code cracking are generally rated high/critical.

> Don't fire all 10,000 attempts at once — ramp up gradually. Some systems also cap the number of operations allowed inside a single request, so a giant batch may get rejected outright.
{: .prompt-tip }

---

## Briefly, the Others

**Resource exhaustion (DoS):** Sending a deeply nested, very heavy query to overload the server. This is out of scope in most programs, and if you actually take the system down you'll get banned.

> Instead of running the destructive query, prove there's "no depth/complexity limit" with a small example and report that. The triage team will understand the mechanism — you don't need to actually take the system down.
{: .prompt-warning }

**Leaky error messages:** When you send a malformed query, the system sometimes says too much (which database, which version, internal file paths). That information gives you clues for an attack too.

---

## Summary

GraphQL has a single door, but real security has to be enforced inside that door — on every piece of data and every operation, individually. Developers frequently forget this, and that's exactly where we go probing.

> **Legal Disclaimer:** The techniques described in this post are intended solely for authorized penetration testing, bug bounty programs operating within a defined scope, and security research. Testing systems you do not own or do not have explicit written permission to test is illegal.
{: .prompt-danger }

---

## References

- [PortSwigger Web Security Academy — GraphQL API vulnerabilities](https://portswigger.net/web-security/graphql)
- [OWASP API Security Top 10 (2023)](https://owasp.org/www-project-api-security/)
- [GraphQL — Official Documentation](https://graphql.org/learn/)
