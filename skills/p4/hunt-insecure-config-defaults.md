# SKILL: hunt-insecure-config-defaults

## Goal

Find security features that are disabled by default, secrets committed to the repository, and network services exposed to untrusted networks. Navigate to the configuration files — do not keyword-search. Read the settings, check the conditions, submit or skip immediately.

---

## Step 1 — Read the application settings and check security feature defaults

Use `get_architecture` to find the project structure. Find the main application settings or configuration file (settings.py, application.yml, config.js, appsettings.json, or equivalent). Read it completely.

Look for security-related features: rate limiting, throttling, CORS restrictions, request size limits, session security, TLS enforcement, CSRF protection, content security policies. For each:

What is the default value when the environment variable or config key is not set? Look for the "get with fallback" pattern:
```
os.getenv('FEATURE', 'false')
process.env.FEATURE || false
config.get('feature', False)
```

**Finding condition**: A security feature (rate limiting, throttling, TLS verification, auth enforcement) is **off** by default — the operator must explicitly set an env var to enable it, rather than explicitly setting one to disable it.
→ **submit immediately**: violated_invariant="[feature] is disabled by default (default value: [default]); any deployment without explicit opt-in has no [rate limiting / throttling / etc.]", severity=7, confidence=9.

## Step 2 — Host/origin allowlist configuration

In the same settings file: find the configuration for allowed hosts, trusted origins, or CORS allowed origins.

**Finding condition**: The value is a wildcard (`["*"]`, `*`, `/.*/`, `allow_all: true`) under any condition that could be true in a deployed environment (not strictly a condition that is impossible in staging or prod).
→ **submit immediately**: violated_invariant="host/origin allowlist is wildcard under [condition]; Host header injection possible, enabling cache poisoning and password-reset link hijacking", severity=5, confidence=9.

## Step 3 — Secrets in deployment configuration

Find the deployment configuration files — Docker Compose files, Kubernetes manifests, Helm values, or environment configuration files. Read the environment variable blocks.

Look for signing keys (JWT, session, HMAC), database passwords, third-party API credentials.

**Finding condition A**: A key is a literal string value in the deployment file (not a reference like `${VAR}` or `secretKeyRef` that pulls from a secrets manager).
→ **submit immediately**: violated_invariant="[key type: JWT signing key / DB password / API key] committed as literal string in deployment config [file]; any developer with repo access has the secret", severity=9, confidence=9.

**Finding condition B**: A credential file (env file, properties file) that contains plaintext secrets is not listed in `.gitignore`. Read the `.gitignore` to verify.
→ **submit immediately**: violated_invariant="[file name] containing plaintext secrets is not in .gitignore; credentials are committed to git history", severity=8, confidence=9.

## Step 4 — Network services exposed on all interfaces

In the same deployment configuration files: read the port mapping blocks.

**Finding condition**: A database, message broker, cache server, or admin UI port is mapped to all network interfaces (`0.0.0.0:PORT:PORT` or simply `PORT:PORT`) rather than localhost-only (`127.0.0.1:PORT:PORT`).
→ **submit immediately**: violated_invariant="[service: PostgreSQL / Redis / RabbitMQ / etc.] port [PORT] bound to all network interfaces in deployment config; directly reachable from the internet if this host is cloud-deployed", severity=8, confidence=9.

## Step 5 — Application running in development server mode in deployment

In the deployment configuration or startup scripts: find how the application server is launched. Is it using the framework's built-in development server (Django `runserver`, Flask dev server, Express default, Rails WEBrick) rather than a production-grade server (gunicorn, uvicorn, nginx, puma)?

**Finding condition**: The deployment config or start command runs the development server, not a production server.
→ **submit immediately**: violated_invariant="application deployed using development server [server name]; development servers are single-threaded, not designed for production load, and may expose debug interfaces", severity=6, confidence=8.

## Finish

Call finish() with all hypotheses. Call it now even if the list is empty.
