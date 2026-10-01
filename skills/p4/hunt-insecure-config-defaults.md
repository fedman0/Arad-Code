# SKILL: hunt-insecure-config-defaults

## ⚡ BREADTH SCAN — grep-first, pattern-confirmed

Each step gives an exact grep pattern. Run it, read the match context, submit if confirmed. 2 tool calls per step maximum.

---

## Step 1 — Security feature disabled by default via environment variable

```
grep(pattern="os\\.getenv.*False|os\\.environ\\.get.*False|getenv.*false|process\\.env\\.*||.*false|config\\.get.*false", max_matches=20)
```

Also:
```
grep(pattern="ENABLED.*False|THROTTL.*False|RATE_LIMIT.*False|LIMIT.*False|BLOCK.*False", max_matches=10)
```

For each match: is the variable name security-related (throttling, rate limiting, token limits, blocking, verification, auth, ssl, tls, captcha)? If yes — any deployment without explicit configuration has that security feature OFF.

**A — Security feature off by default**:
→ Submit per feature: violated_invariant="[feature] reads from environment variable with default 'False'; any deployment without explicit configuration has [feature] disabled", severity=7, confidence=7, exposure="internet"

---

## Step 2 — Wildcard allowed hosts or origins

```
grep(pattern="ALLOWED_HOSTS.*\\*|CORS_ORIGIN.*\\*|allowed_origins.*\\*|AllowedHosts.*\\*|cors.*\\*.*allow", max_matches=10)
```

Also:
```
grep(pattern="\\[\"\\*\"\\]|\\[\"\\*\", |= \\[\\\"\\*\\\"\\]|= \\['\\*'\\]", max_matches=10)
```

If found: under what condition is this set? Even if inside an `if LOCAL_TESTING or ENV == 'dev'` block, if that condition can be true in a staging environment, host header injection becomes possible.

**B — Wildcard host/origin allowlist**:
→ Submit: violated_invariant="host/origin allowlist set to wildcard; Host header injection enables cache poisoning and password-reset link hijacking", severity=5, confidence=7, exposure="internet"

---

## Step 3 — Secret with hardcoded fallback in deployment config

```
grep(pattern=":-[a-zA-Z0-9+/=$@#!]{8,}", max_matches=20)
```

Also:
```
grep(pattern="SECRET.*:-|KEY.*:-|PASSWORD.*:-|TOKEN.*:-|PASS.*:-", max_matches=10)
```

For each match in a deployment file (docker-compose.yml, .env.example, Helm values, Kubernetes secret manifest): the `:-value` pattern is a shell default — if the environment variable is not set, this literal string becomes the production secret.

**C — Credential as literal fallback in deployment config**:
→ Submit per credential: violated_invariant="[credential name] in [file] has a non-empty literal fallback value; any deployment without explicit environment variables uses this known string as the production secret", severity=9, confidence=7, exposure="internet"

---

## Step 4 — Credential file committed to repository

```
grep(pattern="\\.env\\.local|env\\.local|\\.env\\.dev|\\.env\\.development|secrets\\.json|credentials\\.json", max_matches=10)
```

For each file found: check `.gitignore` for that filename. Run:
```
grep(pattern="env\\.local|\\.env\\.local|secrets\\.json", file_glob=".gitignore", max_matches=5)
```

If the credential file exists but is NOT in `.gitignore`, its contents are in version control history.

**D — Credential file not gitignored**:
→ Submit: violated_invariant="[filename] contains plaintext credentials and is not in .gitignore; the file and its secrets are in version control history", severity=8, confidence=7, exposure="internet"

---

## Step 5 — Internal service exposed on all network interfaces

```
grep(pattern="\"\\d+:\\d+\"|'\\d+:\\d+'", file_glob="docker-compose*", max_matches=20)
```

Also:
```
grep(pattern="ports:", file_glob="docker-compose*", max_matches=10)
```

For each port mapping: does it specify a host IP like `"127.0.0.1:5432:5432"`? If it's just `"5432:5432"` without a host IP, it binds to `0.0.0.0` — accessible from any network interface.

**E — Internal service on all interfaces**:
→ Submit per service: violated_invariant="[service] port [port] bound to all network interfaces; directly reachable from the internet on any cloud-deployed host", severity=8, confidence=7, exposure="internet"

---

## Step 6 — Development server in production startup command

```
grep(pattern="manage\\.py runserver|flask run|php -S localhost|npm run dev|go run main|yarn dev|nodemon", file_glob="docker-compose*", max_matches=10)
```

Also check Dockerfile and entrypoint scripts:
```
grep(pattern="manage\\.py runserver|flask run|php -S|npm run dev|go run", max_matches=10)
```

If found as the `command:` or `CMD` / `ENTRYPOINT` for the main application container:

**F — Dev server in production**:
→ Submit: violated_invariant="application container uses development server command; dev servers are single-threaded, not production-safe, and expose debug information", severity=6, confidence=7, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
