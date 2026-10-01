# SKILL: hunt-insecure-config-defaults

## Goal

Find security features disabled by default and secrets committed to the repo. Read files directly. Submit hypotheses immediately.

---

## Step 1 — Throttling disabled by default

Read `hesaboai/settings.py`. Find `THROTTLING_ENABLED` or `ENABLE_THROTTLING`.
If `os.getenv('ENABLE_THROTTLING', 'False')` or similar defaults to False → **submit hypothesis**: violated_invariant="rate limiting disabled by default; authenticated users have no request rate limit", severity=7, confidence=9.

## Step 2 — ALLOWED_HOSTS wildcard

Read `hesaboai/settings.py`. Find `ALLOWED_HOSTS`.
If `ALLOWED_HOSTS = ["*"]` under any condition that can be true in staging/prod → **submit hypothesis**: violated_invariant="ALLOWED_HOSTS=* permits Host header injection; password reset links use attacker-controlled domain", severity=5, confidence=9.

## Step 3 — Hardcoded credentials in docker-compose

Read `docker-compose.yml` completely (use sqz_read_file).
Look for `DJANGO_SECRET_KEY`, `JWT_SECRET_KEY`, database passwords in the `environment:` blocks.
If any signing key or password is hardcoded (not a `${VAR}` reference) → **submit hypothesis**: violated_invariant="signing key hardcoded in docker-compose; repo access gives attacker the signing key", severity=9, confidence=9.

## Step 4 — Database ports exposed to all interfaces

Read `docker-compose.yml`. Find `ports:` blocks for postgresql and rabbitmq.
If any port is `"0.0.0.0:PORT:PORT"` or just `"PORT:PORT"` (not `"127.0.0.1:PORT:PORT"`) → **submit hypothesis**: violated_invariant="database/broker port bound to 0.0.0.0; internet-accessible if docker-compose used on cloud VM", severity=8, confidence=9.

## Step 5 — env.local committed

Check `.gitignore` for `env.local` or `*.env` entries.
Read `env.local` if it exists — does it contain `SECRET_KEY`, `JWT_SECRET_KEY`, API keys?
If `env.local` is not gitignored and contains secrets → **submit hypothesis**: violated_invariant="secret keys committed to repository in env.local", severity=8, confidence=9.

## Finish

Call finish() with all hypotheses found. Call it even with an empty list.
