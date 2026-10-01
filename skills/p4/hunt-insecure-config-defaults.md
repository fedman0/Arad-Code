# SKILL: hunt-insecure-config-defaults

## Goal

Find security features that are off by default and credentials committed to the repository. Search, read, decide, submit immediately.

---

## Step 1 — Security feature disabled by default

Search for security-relevant feature flags with default values (search_code for `THROTTLING`, `RATE_LIMIT`, `ENABLE_THROTTLING`, `CORS_ALLOW`, `SSL_VERIFY`, `CSRF_ENABLED`, `AUTH_REQUIRED`; also look for environment variable reads with fallback values in settings files).
For each found: what is the default when the environment variable is not set?
**Finding condition**: a security feature (rate limiting, throttling, CORS restriction, TLS verification, auth enforcement) is OFF by default — the operator must explicitly enable it, rather than explicitly disable it. Pattern: `os.getenv('FEATURE', 'false')`, `process.env.FEATURE || false`, `config.get('feature', false)`.
→ **submit hypothesis per feature**: violated_invariant="[feature name] is disabled by default; deployment without explicit opt-in has no [rate limiting / TLS verification / etc.]", severity=7, confidence=9.

## Step 2 — ALLOWED_HOSTS / trusted origins wildcard

Search for host allowlist configuration (search_code for `ALLOWED_HOSTS`, `allowedHosts`, `trusted_origins`, `CORS_ALLOWED`, `allow_all_origins`).
**Finding condition**: value is a wildcard (`["*"]`, `*`, `/.*/`, `allow_all: true`) under any condition that could be true in a deployed environment (not strictly `ENV=local` or `ENV=dev`).
→ **submit hypothesis immediately**: violated_invariant="wildcard host/origin policy allows Host header injection; password reset links, cache poisoning, CSRF origin bypass", severity=5, confidence=9.

## Step 3 — Secrets hardcoded in deployment configuration

Read the deployment configuration files (search_code for `docker-compose`, `docker-compose.yml`; also look for `k8s/`, `helm/`, `.env`, `env.local`, `application.properties` in the repo).
Find environment variable blocks that define signing keys, database passwords, or API credentials.
**Finding condition**: a signing key (JWT, session, HMAC), database password, or third-party API key is a literal string value in a deployment file (not a `${VAR}` / `$(VAR)` reference that pulls from a secret manager).
→ **submit hypothesis per secret**: violated_invariant="[key type] hardcoded in deployment config; repository access gives attacker the key", severity=9, confidence=9.

## Step 4 — Network service exposed on all interfaces in deployment config

In the same deployment configuration files: find port mappings.
**Finding condition**: a database (PostgreSQL, MySQL, MongoDB, Redis), message broker (RabbitMQ, Kafka), or admin UI port is mapped to `0.0.0.0:PORT:PORT` or just `PORT:PORT` (not `127.0.0.1:PORT:PORT`), making it reachable from the network.
→ **submit hypothesis immediately**: violated_invariant="database/broker port bound to all network interfaces; directly reachable from the internet if this host is cloud-deployed", severity=8, confidence=9.

## Step 5 — Credential file not excluded from version control

Check whether the deployment configuration or environment files are excluded from version control (search_code for `.gitignore`, `.dockerignore`).
Read the ignore file. Is `env.local`, `.env`, `docker-compose.yml`, `application-prod.properties` listed?
**Finding condition**: a file that contains plaintext secrets (found in Step 3) is not listed in `.gitignore` — meaning it is committed to the repository.
→ **submit hypothesis immediately**: violated_invariant="secret-bearing file not in .gitignore; credentials committed to repository history", severity=8, confidence=9.

## Finish

Call finish() with all hypotheses found. Call it now even if the list is empty.
