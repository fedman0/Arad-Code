# SKILL: hunt-insecure-config-defaults

You are a security researcher. Find insecure default settings, committed secrets, and exposed network services. For each step: (1) locate the code/config, (2) read it, (3) look for the exact pattern described, (4) submit if found, (5) move on. Do not conclude early — work through every check.

---

## Step 1 — Find and read application configuration

Call `search_graph` with `name_pattern="settings|config|configuration|environment|defaults"` and `label="Module"`. Read every configuration module found. Also call `get_architecture` and identify where the application loads its settings (any file named settings.py, config.py, app.config.js, application.yml, appsettings.json, etc.).

---

## Step 2 — Check: security features disabled by default

In the configuration code, search for environment variable reads with a default value of `False`, `false`, `"False"`, `0`, or `""` for any security-related feature. The dangerous pattern:

```python
THROTTLING_ENABLED = os.getenv('ENABLE_THROTTLING', 'False')   ← default off
TOKEN_LIMIT = os.getenv('ENABLE_TOKEN_LIMIT', 'False')          ← default off
RATE_LIMIT = os.getenv('RATE_LIMIT_ENABLED', 'false')           ← default off
```

These mean any deployment without explicit configuration has that security feature disabled.

**A — Security feature off by default**:
→ Submit per feature: violated_invariant="[feature name] reads from environment variable with default 'False'; any deployment without explicit configuration has no [rate limiting / throttling / token checking / etc.]", severity=7, confidence=9.

---

## Step 3 — Check: wildcard allowed hosts/origins

In the configuration, look for `ALLOWED_HOSTS`, `CORS_ALLOWED_ORIGINS`, `CORS_ORIGIN_WHITELIST`, or equivalent, set to `["*"]` or `"*"` under any condition that could be true in a deployed environment:

```python
if LOCAL_TESTING or ENV == 'dev':
    ALLOWED_HOSTS = ["*"]   ← wildcard under a condition that may be true in staging
```

**B — Wildcard host allowlist**:
→ Submit: violated_invariant="host/origin allowlist is set to wildcard under [condition]; Host header injection enables cache poisoning and password-reset link hijacking", severity=5, confidence=9.

---

## Step 4 — Check: secrets as literal strings in deployment config

Read the deployment configuration file (look for docker-compose.yml, docker-compose.yaml, Helm values.yaml, Kubernetes manifests, .env.example). In environment variable definitions, look for lines where a signing key, session secret, or API credential is defined with a literal default:

```yaml
SECRET_KEY: ${SECRET_KEY:-django-insecure-LITERAL_VALUE_HERE}
JWT_SECRET: ${JWT_SECRET:-MLC+KgPZpHX$2.6R6s}
DB_PASSWORD: ${DB_PASSWORD:-default_password}
```

Any `:-something` fallback that is a non-empty credential string means any deployment without environment variables uses this literal as the production secret.

**C — Credential as literal in deployment config**:
→ Submit per credential: violated_invariant="[credential] in [file] has a non-empty literal fallback value; any deployment without explicit environment variable configuration uses this known secret", severity=9, confidence=9.

---

## Step 5 — Check: credential files not gitignored

Find all files in the repository root or configuration directories named `.env`, `.env.local`, `env.local`, `.env.development`, `secrets.json`, `credentials.json`, or similar. Read the `.gitignore` file. Is any of these credential-containing files absent from `.gitignore`?

The dangerous pattern: a file like `env.local` contains real API keys or credentials AND is not listed in `.gitignore`, meaning it was likely committed to the repository.

**D — Credential file not gitignored**:
→ Submit: violated_invariant="[filename] contains plaintext credentials and is not in .gitignore; the file is committed to the repository and its secrets are in version control history", severity=8, confidence=9.

---

## Step 6 — Check: internal services exposed on all network interfaces

In the deployment configuration, read port mapping definitions. For each service (database, cache, message broker, admin UI): is the host port mapped so that it's accessible from all interfaces (the mapping is `"XXXX:YYYY"` without specifying a host IP like `"127.0.0.1:XXXX:YYYY"`)?

```yaml
ports:
  - "5432:5432"    ← binds to 0.0.0.0, accessible from anywhere
  - "127.0.0.1:5432:5432"  ← binds only to localhost, safe
```

**E — Internal service on all interfaces**:
→ Submit per service: violated_invariant="[service] port [port] is bound to all network interfaces via [port mapping]; directly reachable from the internet on any cloud-deployed host", severity=8, confidence=9.

---

## Step 7 — Check: development server in production command

In the deployment configuration, find the `command:` or startup script for the main application container. Is it using a development server?

Dangerous patterns (one per language/framework):
```
python manage.py runserver    ← Django dev server
npm run dev                   ← Node dev mode
flask run                     ← Flask dev server
php -S                        ← PHP built-in server
go run main.go                ← Go non-compiled run
```

**F — Dev server in production**:
→ Submit: violated_invariant="application starts with [development server command]; development servers are single-threaded, not production-safe, and expose debug information", severity=6, confidence=9.

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this. Call it even if the list is empty.
