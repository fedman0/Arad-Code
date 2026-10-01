# SKILL: hunt-insecure-config-defaults

## Goal

Find every security feature that is disabled by default, every secret committed to the
repository, and every deployment misconfiguration. These bugs are high-impact because
they affect every deployment where the correct environment variable is not set.

---

## Step 1 — Read every settings file completely

Use `sqz_list_dir` and `sqz_read_file` to read ALL of:
- `settings.py`, `settings/`, `base.py`, `production.py`, `staging.py`
- `docker-compose.yml`, `docker-compose.*.yml`
- `env.local`, `.env`, `.env.example`, `env.example`
- `Dockerfile`, `docker-compose.override.yml`

Do not grep for specific variable names. Read entire files.

---

## Step 2 — For every `os.environ.get('X', default)` call, check the default

Pattern to look for:
```python
os.environ.get('VARIABLE_NAME', 'fallback_value')
os.getenv('VARIABLE_NAME', 'fallback_value')
config.get('X', 'fallback')
```

For each one, ask: if this variable is not set in production/staging, what security impact does
the default have?

**Critical defaults to flag:**
- `SIGNING_KEY` / `JWT_SECRET_KEY` defaulting to any non-empty string → token forgery
- `SECRET_KEY` / `DJANGO_SECRET_KEY` defaulting to any string → session forgery, CSRF bypass
- Any cryptographic key defaulting to a string instead of raising an error

**Security-off-by-default to flag:**
- Rate limiting / throttling disabled: `os.getenv('ENABLE_THROTTLING', 'False')` → `False` means off
- SSL verification disabled: `verify = not settings.DEBUG` (False when DEBUG=True)
- CORS permissive: `CORS_ALLOW_ALL_ORIGINS = True` or similar default
- Any authentication / authorization check conditioned on a flag that defaults to disabled

For each finding: quote the exact line with file:line, quote the default value, and explain
what an attacker can do if the variable is not set.

---

## Step 3 — Find secrets hardcoded in deployment files

Read `docker-compose.yml` and any `.env*` files completely.

Look for these keys in environment blocks:
- `SECRET_KEY`, `DJANGO_SECRET_KEY`
- `JWT_SECRET_KEY`, `SIGNING_KEY`
- Database passwords (`POSTGRES_PASSWORD`, `DB_PASSWORD`)
- API keys, tokens, credentials for external services

**Critical:** Are these the same values used in staging/production (copy-pasted from dev config)?
Are any of these files committed to the repository (not in `.gitignore`)?

Check `.gitignore` — does it exclude `docker-compose.yml`, `env.local`, `.env`?
If not, these credentials are in git history.

---

## Step 4 — Find ALLOWED_HOSTS and CORS misconfiguration

Find `ALLOWED_HOSTS` setting. If it is `["*"]` or `["*", ...]` under any condition that
can be true in production or staging, that allows Host header injection:
- Password reset links generated with attacker-controlled domain
- Cache poisoning if a reverse proxy caches responses

Find CORS settings. If `CORS_ALLOW_ALL_ORIGINS = True` or origin allowlist is absent for
authenticated endpoints, note as a finding.

---

## Step 5 — Find port bindings in deployment config

In `docker-compose.yml`, find every `ports:` block. For each port mapping:
- `"0.0.0.0:port:port"` or just `"port:port"` → exposed on ALL network interfaces
- `"127.0.0.1:port:port"` → localhost only (safe)

Services that should NEVER be exposed to all interfaces:
- Databases (PostgreSQL, MySQL, MongoDB, Redis)
- Message broker UIs (RabbitMQ management at 15672)
- Admin interfaces

If a database port is bound to `0.0.0.0` and docker-compose is used on a cloud VM, that
database is internet-accessible.

---

## Step 6 — Audit every "security-affecting feature flag"

Find every feature flag or env var that controls security-relevant behavior:
- Throttling / rate limiting
- SSL/TLS verification
- Authentication enforcement
- Logging of security events
- CSRF protection

For each: what is the default? Is it safe-when-absent or dangerous-when-absent?
A security feature that must be explicitly opted in to is a finding.

---

## What to produce

A hypothesis for EACH of:
- Cryptographic signing key has a hardcoded fallback value in source code
- Signing key or Django SECRET_KEY committed in plaintext in docker-compose or env file
- Security feature disabled by default (throttling, rate limiting, SSL verification)
- `ALLOWED_HOSTS = ["*"]` in any non-local environment configuration
- Database or message broker port bound to `0.0.0.0` in docker-compose
- `.env*` or deployment credential file not in `.gitignore` (committed to repository)
- Default CORS policy allows all origins for authenticated endpoints

For each, set `violated_invariant` to the specific security property violated
(e.g., "JWT signing keys must not be recoverable from repository access"),
`entry_point` to file:line, and `recommendation` to the exact fix.
