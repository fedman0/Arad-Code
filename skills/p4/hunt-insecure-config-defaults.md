# SKILL: hunt-insecure-config-defaults

You are a security researcher. Find insecure default settings, committed secrets, and exposed network services. Work in this order for every step: find the code → read it → check the condition → submit if found → move to the next step.

---

## Step 1 — Find and read the application configuration

Call `get_architecture` to understand the project structure.

Then use `search_graph` to find configuration and settings code — search for nodes whose name contains terms like `config`, `settings`, `configuration`, `environment`, `defaults`, `options`. Read every configuration file or class you find. Also read any infrastructure/deployment configuration that `get_architecture` identifies (container definitions, orchestration manifests, environment files).

---

## Step 2 — Check security feature defaults

In every configuration file you read: for every security-relevant feature (rate limiting, throttling, authentication enforcement, CORS policy, TLS verification, allowed hosts, debug mode, content security), look at what value is active when the corresponding environment variable is NOT set.

**A — Security feature disabled by default**
If the feature is disabled by default (the operator must explicitly enable it rather than explicitly disable it):

→ Submit per feature: violated_invariant="[feature name] is disabled by default (default value: [value]); any deployment without explicit configuration has no [rate limiting / throttling / TLS enforcement / etc.]", severity=7, confidence=9.

**B — Host/origin allowlist is a wildcard**
If the allowed-hosts or allowed-origins configuration is set to a wildcard (`*`, `["*"]`, allow-all) under any condition that could be true in a deployed environment:

→ Submit: violated_invariant="host/origin allowlist is wildcard under [condition]; Host header injection enables cache poisoning and password-reset link hijacking", severity=5, confidence=9.

---

## Step 3 — Check for literal secrets in deployment configuration

In the infrastructure/deployment configuration you read: find environment variable blocks that define signing keys, session secrets, database passwords, or API credentials. Is the value a literal string, rather than a reference to an external secrets manager?

**C — Signing key or credential as literal string**
→ Submit per credential: violated_invariant="[credential type] is written as a literal string in [file]; repository access gives any developer the production secret", severity=9, confidence=9.

**D — Credential file not in version control ignore list**
Is the configuration file that contains literal secrets listed in the version control ignore file? Read the ignore file. If the credential file is not listed:

→ Submit: violated_invariant="[file] with plaintext secrets is not in the version control ignore file; credentials are in repository history", severity=8, confidence=9.

---

## Step 4 — Check network interface bindings

In the infrastructure configuration: find port mapping definitions. For each internal service (database, cache, message broker, admin UI):

**E — Internal service bound to all network interfaces**
Is the port bound to all interfaces (equivalent to `0.0.0.0`) rather than localhost only?

→ Submit per service: violated_invariant="[service] port [port] is bound to all network interfaces; directly reachable from the internet on a cloud-deployed host", severity=8, confidence=9.

---

## Step 5 — Check the startup command

In the infrastructure configuration or startup scripts: find how the application server process is started.

**F — Development server in deployment config**
Is the startup command using the framework's built-in development server (designed for local use only, typically named with words like `dev`, `runserver`, `develop`) rather than a production-grade application server?

→ Submit: violated_invariant="deployment starts the application with [development server name]; development servers are single-threaded and not designed for concurrent production traffic", severity=6, confidence=8.

---

## Finish

Call `finish()` now with all hypotheses found. Even if the list is empty.
