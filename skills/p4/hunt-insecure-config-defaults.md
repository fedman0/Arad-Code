# SKILL: hunt-insecure-config-defaults

## Goal

Find security features that are off by default, secrets committed to the repository, and infrastructure services exposed to untrusted networks. Read the project's configuration system — wherever and however this specific project manages its settings.

---

## Step 0 — Find the configuration system

Call `get_architecture`. Every project has a configuration system — a place where environment variables are read and settings are defined. It might be a settings file, a config class, an environment loader, a YAML/TOML/JSON config, or settings scattered across multiple modules. Find it.

Read the configuration code that handles security-relevant settings: authentication enforcement, rate limiting, throttling, CORS policy, TLS, allowed hosts, content security. This is your source for Step 1 and Step 2.

Also find the infrastructure/deployment configuration — how this application is packaged and run in a deployed environment (container config, orchestration manifests, environment files, startup scripts). This is your source for Steps 3, 4, and 5.

---

## Step 1 — Security features with insecure defaults

In the configuration code: for each security feature (rate limiting, throttling, request authentication enforcement, TLS verification, CORS restriction) — what is the value when the environment variable or config key is NOT set?

The dangerous pattern looks like this in any language:
```
read_env('FEATURE_ENABLED', default=false)   // Python, JS, Go, etc.
env.getOrDefault('FEATURE', 'false')
config.getBoolean('feature.enabled', false)
```

Reason about the default: is the security feature ON or OFF when no one explicitly configures it? A feature that is OFF by default means every deployment that doesn't explicitly set the variable has no protection. An operator has to know to opt in.

→ **Submit per feature with insecure default**: violated_invariant="[feature name] is disabled by default (default value: [value]); any deployment without explicit configuration has no [rate limiting / throttling / etc.]. Operators must opt in, not opt out.", severity=7, confidence=9.

---

## Step 2 — Host or origin allowlist with wildcard

In the configuration code: find the setting that controls which HTTP Host headers or cross-origin requests the application accepts. Read the value and the condition under which each value is used.

If the value is a wildcard (`*`, `["*"]`, `allow_all`, a catch-all regex) under ANY condition that could be true in a deployed environment (not only purely local dev): this enables Host header injection, which allows cache poisoning and password-reset link hijacking.

→ **Submit if found**: violated_invariant="host/origin allowlist is wildcard under condition [condition]; Host header injection is possible, enabling cache poisoning, password-reset link hijacking", severity=5, confidence=9.

---

## Step 3 — Signing secrets and credentials in version-controlled files

Read the infrastructure/deployment configuration files.

Look for environment variable definitions that set signing keys (JWT, session, HMAC), database passwords, third-party API credentials, or service account keys. For each:

- Is the value a literal string (hardcoded), or is it a reference to an external secret store (`${VAR}`, `secretKeyRef`, `vault:path`, etc.)?
- Is the configuration file itself committed to version control? Check whether it appears in the version control ignore file (`.gitignore`, `.hgignore`, similar). If a file containing literal secrets is not in the ignore list, it is committed.

→ **Submit per literal secret in deployment config**: violated_invariant="[key type: signing key / DB password / API credential] is a literal string in [file]; any person with repository access has this secret", severity=9, confidence=9.

→ **Submit if credential file is not ignored**: violated_invariant="[file] containing plaintext secrets is not in the version control ignore file; the credentials are committed to repository history", severity=8, confidence=9.

---

## Step 4 — Network services exposed on all interfaces

In the infrastructure/deployment configuration: find where network ports are defined — which interfaces each service binds to.

For internal services (database, cache, message broker, admin UI): is the port bound to all network interfaces (equivalent to `0.0.0.0`) or only to the loopback interface (localhost / `127.0.0.1`)?

A database or message broker bound to all interfaces is directly reachable from the internet if this host is deployed on a cloud VM — even if you think it's "internal."

→ **Submit per exposed internal service**: violated_invariant="[service: database / cache / broker / admin UI] port [port] is bound to all network interfaces in deployment configuration; directly internet-reachable on a cloud-deployed host", severity=8, confidence=9.

---

## Step 5 — Application started with development server

In the infrastructure/deployment configuration or startup scripts: find how the application server process is launched. 

Every framework has a development server for local use (it's convenient, hot-reloads, gives stack traces). The same framework has a production-grade server (handles concurrent connections, no debug output, no hot reload). The development server is never appropriate for a deployed environment.

Reason about what the startup command does: is it launching the framework's built-in development server, or a production server (gunicorn, uvicorn, nginx unit, puma, pm2 in cluster mode, etc.)?

→ **Submit if development server in deployment config**: violated_invariant="deployment configuration starts the application using the framework's development server [server name]; development servers are single-threaded, expose debug output, and are not designed for concurrent production traffic", severity=6, confidence=8.

---

## Finish

Call finish() with all hypotheses. Do it now even if the list is empty.
