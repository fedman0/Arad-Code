# SKILL: hunt-insecure-config-defaults

## ⚡ BREADTH SCAN — grep-first, multi-language, pattern-confirmed

Patterns cover Python/Django, JavaScript/Node, Go, Java/Spring, PHP, Ruby/Rails, and deployment configs. Run grep, read context, submit immediately. 2 tool calls per step maximum.

---

## Step 1 — Security feature disabled by default via environment variable

```
grep(pattern="getenv.*[Ff]alse|os\\.environ.*[Ff]alse|process\\.env\\..*\\|\\|.*false|config\\.get.*false|ENV\\.fetch.*false", max_matches=30)
```

Also:
```
grep(pattern="ENABLED.*[Ff]alse|THROTTL.*[Ff]alse|RATE.*[Ff]alse|LIMIT.*[Ff]alse|BLOCK.*[Ff]alse|CAPTCHA.*[Ff]alse|VERIFY.*[Ff]alse", max_matches=20)
```

For each match: is the variable name security-related (rate limiting, throttling, token limits, blocking, verification, auth, captcha, ssl, tls)? If the default value is `False`/`false`/`0`/`""`, any deployment without explicit configuration has that security feature **off**.

**A — Security feature off by default**:
→ Submit per feature: violated_invariant="[feature name] reads from environment variable with default false/disabled; any deployment without explicit configuration has [feature] disabled", severity=7, confidence=7, exposure="internet"

---

## Step 2 — Wildcard allowed hosts or CORS origins

```
grep(pattern="ALLOWED_HOSTS.*\\*|CORS.*origin.*\\*|allowedOrigins.*\\*|cors.*\\*|origin.*\\[.*\\*|Access-Control-Allow-Origin.*\\*", max_matches=20)
```

Also:
```
grep(pattern="cors\\(\\{.*origin.*\\*|app\\.use.*cors.*\\*|addAllowedOrigin.*\\*|setAllowedOrigins.*\\*", max_matches=10)
```

Even if behind a conditional (`if LOCAL or ENV == 'dev'`), if the wildcard could apply to staging, Host header injection enables cache poisoning and password-reset link hijacking.

**B — Wildcard host/CORS allowlist**:
→ Submit: violated_invariant="host or CORS origin allowlist set to wildcard; Host header injection enables cache poisoning and may hijack password-reset links", severity=5, confidence=7, exposure="internet"

---

## Step 3 — Secret or credential with hardcoded fallback value

```
grep(pattern=":-[a-zA-Z0-9+/=$@#!_-]{8,}", max_matches=30)
```

Also:
```
grep(pattern="SECRET.*:-|KEY.*:-|PASSWORD.*:-|TOKEN.*:-|PASS.*:-|CREDENTIAL.*:-", max_matches=20)
```

Also check for hardcoded literals in application code:
```
grep(pattern="jwtSecret\\s*[:=]\\s*['\"][^'\"]{8,}['\"]|secretKey\\s*[:=]\\s*['\"][^'\"]{8,}['\"]|secret\\s*[:=]\\s*['\"][^'\"]{16,}['\"]", max_matches=10)
```

Any non-empty literal after `:-` in a deployment config (docker-compose, Helm values, k8s manifest) means that literal is the production secret when the env var is unset.

**C — Credential with hardcoded fallback**:
→ Submit per credential: violated_invariant="[credential name] in [file] has a non-empty literal fallback value; any deployment without explicit env vars uses this known value — forging tokens or connecting to databases is trivial", severity=9, confidence=7, exposure="internet"

---

## Step 4 — Credential file committed to repository (not in .gitignore)

```
grep(pattern="\\.env\\.local|\\.env\\.dev|\\.env\\.development|env\\.local|secrets\\.json|credentials\\.json|\\.env\\.staging", max_matches=10)
```

For each file found that is NOT `.gitignore` itself: check `.gitignore`:
```
grep(pattern="env\\.local|\\.env\\.local|secrets\\.json|credentials", file_glob=".gitignore", max_matches=5)
```

If the credential file exists but is absent from `.gitignore`, it is likely committed and its contents are in version control history.

**D — Credential file not gitignored**:
→ Submit: violated_invariant="[filename] contains plaintext credentials and is not in .gitignore; secrets are in version control history and accessible to anyone with repo read access", severity=8, confidence=7, exposure="internet"

---

## Step 5 — Internal service exposed on all network interfaces

```
grep(pattern="\"[0-9]{2,5}:[0-9]{2,5}\"|'[0-9]{2,5}:[0-9]{2,5}'", max_matches=30)
```

For each port mapping match in a deployment config: does it specify a host IP (`127.0.0.1:5432:5432`) or not (`5432:5432`)? Without a host IP, the port binds to `0.0.0.0` — reachable from any network interface.

**E — Internal service exposed on all interfaces**:
→ Submit per service: violated_invariant="[service] port mapped without host IP binding; the port is bound to 0.0.0.0 and directly reachable from the internet on any cloud host", severity=8, confidence=7, exposure="internet"

---

## Step 6 — Development server in production startup command

```
grep(pattern="manage\\.py runserver|flask run|php -S|npm run dev|go run main|nodemon|yarn dev|rails server|rackup|puma.*development|mvn spring-boot:run|dotnet watch", max_matches=20)
```

If found in a deployment file (docker-compose.yml, Dockerfile, Procfile, supervisord.conf, Kubernetes command field, or shell entrypoint script):

**F — Dev server in production**:
→ Submit: violated_invariant="application container starts with a development server command; dev servers are single-threaded, expose debug pages, and are not production-safe", severity=6, confidence=7, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
