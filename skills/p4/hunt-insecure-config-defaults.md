# SKILL: hunt-insecure-config-defaults

## ⚡ BREADTH SCAN — grep-first, semgrep-derived patterns, multi-language

Run grep, read context, submit immediately. 2 tool calls per step max.

---

## Step 1 — Security feature disabled by default via environment variable

```
grep(pattern="getenv.*[Ff]alse|os\.environ.*[Ff]alse|process\.env\..*\|\|.*false|ENV\.fetch.*false|config\.get.*false|System\.getenv.*false", max_matches=30)
```

Also:
```
grep(pattern="THROTTL.*[Ff]alse|RATE.*LIMIT.*[Ff]alse|CAPTCHA.*[Ff]alse|VERIFY.*[Ff]alse|ENABLED.*=.*[Ff]alse|SSL_VERIFY.*[Ff]alse|CSRF.*[Ff]alse", max_matches=20)
```

Is the variable name security-related (rate limiting, throttling, blocking, captcha, TLS, auth, CSRF)? If the default is `False`/`false`/`0`/`""`, any deployment without explicit config has that feature **off**.

**A — Security feature off by default**:
→ Submit per feature: violated_invariant="[feature] reads from env var with default false/disabled; any deployment without explicit config has [feature] disabled", severity=7, confidence=7, exposure="internet"

---

## Step 2 — Wildcard CORS or allowed hosts

**Django:**
```
grep(pattern="ALLOWED_HOSTS\s*=\s*\[.*\*|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True", max_matches=15)
```

**FastAPI (CORSMiddleware):**
```
grep(pattern="CORSMiddleware.*allow_origins.*\*|allow_origins=\[.*\*.*\]|allow_origins=\[\"?\*\"?\]", max_matches=15)
```

**Flask (flask-cors):**
```
grep(pattern="CORS\(.*origins.*\*|resources.*origins.*\*|@cross_origin\(\)|cross_origin\(.*\*", max_matches=15)
```

**Express / Node.js:**
```
grep(pattern="cors\(\{.*origin.*\*|cors\(\{.*origin.*true|res\.setHeader\(.*Access-Control.*\*|res\.header\(.*Access-Control.*\*", max_matches=15)
```

**Java (Spring / Servlet):**
```
grep(pattern="addAllowedOrigin\(\"?\*\"?\)|setAllowedOrigins.*\*|addHeader.*[Aa]ccess-[Cc]ontrol.*\*|setHeader.*[Aa]ccess-[Cc]ontrol.*\*", max_matches=15)
```

**PHP:**
```
grep(pattern="header\(.*Access-Control-Allow-Origin.*\*|header\(.*access-control-allow-origin.*\*", max_matches=15)
```

**Ruby/Rails:**
```
grep(pattern="allow_any_origin!|origins\s+['\"][*]['\"]|cors.*origins.*\*", max_matches=15)
```

**B — Wildcard host/CORS allowlist**:
→ Submit: violated_invariant="host or CORS origin allowlist set to wildcard; Host header injection enables cache poisoning and may hijack password-reset links", severity=5, confidence=7, exposure="internet"

---

## Step 3 — Secret or credential with hardcoded fallback value

**Shell variable substitution (docker-compose, Helm, k8s manifests):**
```
grep(pattern=":-[a-zA-Z0-9+/=$@#!_-]{8,}", max_matches=30)
```

Also name-scoped:
```
grep(pattern="SECRET\s*:-|KEY\s*:-|PASSWORD\s*:-|TOKEN\s*:-|PASS\s*:-|CREDENTIAL\s*:-|SIGNING\s*:-", max_matches=20)
```

**Python (PyJWT literal):**
```
grep(pattern="jwt\.encode\([^,]+,\s*['\"][^'\"]{8,}['\"]|SECRET_KEY\s*=\s*['\"][^'\"]{8,}['\"]", max_matches=15)
```

**JavaScript (jwt / express-jwt literal):**
```
grep(pattern="jwt\.sign\([^,]+,\s*['\"][^'\"]{8,}['\"]|express-jwt.*secret.*['\"][^'\"]{8,}['\"]|secretOrKey\s*:\s*['\"][^'\"]{8,}['\"]", max_matches=15)
```

**Java (HMAC literal):**
```
grep(pattern="HMAC256\(['\"][^'\"]{8,}['\"]|HMAC384\(['\"][^'\"]{8,}['\"]|HMAC512\(['\"][^'\"]{8,}['\"]", max_matches=15)
```

**C# (SymmetricSecurityKey literal):**
```
grep(pattern="SymmetricSecurityKey\(Encoding\.[^.]+\.GetBytes\(['\"][^'\"]{8,}['\"]", max_matches=15)
```

Any non-empty literal after `:-` in a deployment config means that literal is the production secret when the env var is unset.

**C — Credential with hardcoded fallback**:
→ Submit per credential: violated_invariant="[credential] in [file] has a non-empty literal fallback; any deployment without explicit env vars uses this known value — forging tokens or DB access is trivial", severity=9, confidence=7, exposure="internet"

---

## Step 4 — Credential file committed to repository (not in .gitignore)

```
grep(pattern="\.env\.local|\.env\.dev|\.env\.development|\.env\.staging|env\.local|secrets\.json|credentials\.json|\.env\.test", max_matches=10)
```

For each file found that is NOT `.gitignore` itself: check `.gitignore`:
```
grep(pattern="env\.local|\.env\.local|secrets\.json|credentials|\.env\.dev", file_glob=".gitignore", max_matches=5)
```

**D — Credential file not gitignored**:
→ Submit: violated_invariant="[filename] contains plaintext credentials and is not in .gitignore; secrets are in version control history accessible to anyone with repo read access", severity=8, confidence=7, exposure="internet"

---

## Step 5 — Internal service exposed on all network interfaces

**Docker Compose port mappings without host IP binding:**
```
grep(pattern="\"[0-9]{2,5}:[0-9]{2,5}\"|'[0-9]{2,5}:[0-9]{2,5}'", max_matches=30)
```

For each match in a docker-compose or deployment config: does it specify a host IP (`127.0.0.1:5432:5432`) or is it bare (`5432:5432`)? Without a host IP, the port binds to `0.0.0.0`.

**E — Internal service on all interfaces**:
→ Submit per service: violated_invariant="[service] port mapped without host IP binding; port bound to 0.0.0.0 and directly reachable from the internet on any cloud host", severity=8, confidence=7, exposure="internet"

---

## Step 6 — Development server in production startup command

**Python (Django/Flask):**
```
grep(pattern="manage\.py runserver|flask run|flask.*--debug|uvicorn.*--reload|python -m flask", max_matches=20)
```

**JavaScript / Node:**
```
grep(pattern="npm run dev|yarn dev|nodemon|node.*--inspect|ts-node-dev", max_matches=20)
```

**Java (Spring Boot / Maven):**
```
grep(pattern="mvn spring-boot:run|./mvnw spring-boot:run|gradle bootRun|java.*-jar.*SNAPSHOT", max_matches=15)
```

**Go:**
```
grep(pattern="go run main|go run \.", max_matches=15)
```

**PHP:**
```
grep(pattern="php -S |php artisan serve", max_matches=15)
```

**Ruby:**
```
grep(pattern="rails server|rails s|rackup|puma.*development|bundle exec rails", max_matches=15)
```

**C# / .NET:**
```
grep(pattern="dotnet watch|dotnet run.*Development|ASPNETCORE_ENVIRONMENT.*Development", max_matches=15)
```

If found in a deployment file (Dockerfile, docker-compose.yml, Procfile, supervisord.conf, Kubernetes command field):

**F — Dev server in production**:
→ Submit: violated_invariant="application container starts with a development server command; dev servers are single-threaded, expose debug pages, and are not production-safe", severity=6, confidence=7, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
