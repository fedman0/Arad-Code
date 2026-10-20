# SKILL: understand-config-and-deployment

## Goal

Read every configuration and deployment file completely. Understand the security
implications of every setting, default, and flag. Find anywhere the application's
security posture degrades silently when configuration is absent or misconfigured.

Do NOT grep for specific variable names. Read the files completely and reason about
what each setting means for security.

---

## Phase 1 — Find and read all configuration files

Use `list_dir` (it shows hidden files such as `.env`) and `shell("find . -name '*.yml' -not -path '*/node_modules/*'")`
style searches to find configuration files, then `read_file` each one completely — `read_file` returns at most
200 lines per call, so page through longer files with `start_line`/`end_line`.
Configuration file names vary by stack:
- **Python**: `settings.py`, `config.py`, `*.cfg`, `pyproject.toml`, `*.ini`
- **Java/Spring**: `application.properties`, `application.yml`, profile-specific variants
- **.NET**: `appsettings.json`, `appsettings.*.json`, `web.config`
- **Node.js**: `config/`, any file loaded with dotenv, `*.config.js`
- **Ruby/Rails**: `config/environments/*.rb`, `config/credentials.yml.enc`
- **Go**: any config file read at startup, `.env`
- **PHP/Laravel**: `.env`, `config/*.php`
- **All stacks**: `docker-compose.yml`, `docker-compose.*.yml`, `k8s/`, `helm/`, `.env`,
  `env.local`, `.env.example`, `Dockerfile`, CI/CD files (`.github/`, `.gitlab-ci.yml`),
  reverse proxy config (`nginx.conf`, `traefik.yml`, etc.)

Read each file fully. Do not stop at the first interesting line.

---

## Phase 2 — Analyze every security-relevant setting

For each setting that affects security, answer:

**Default value analysis:**
- What is the value if the environment variable / config key is absent?
  Every framework has a "get with default" pattern:
  - Python: `os.getenv('X', 'default')`, `config.get('X', 'default')`
  - Node.js: `process.env.X || 'default'`
  - Java/Spring: `@Value("${x:default}")`, `environment.getProperty("x", "default")`
  - .NET: `config["X"] ?? "default"`, `config.GetValue<string>("X", "default")`
  - Go: `os.Getenv("X")` (returns `""` if not set — read what the code does with an empty value)
  - PHP: `env('X', 'default')`
  - Ruby: `ENV.fetch('X', 'default')`
- Is the default value safe for production?
- A missing value that causes a hard failure is safer than a silent fallback to an insecure default.

**Feature flags that affect security:**
- What does enabling vs. disabling this flag do to the security model?
- Is security opt-in (disabled by default, must be explicitly enabled) or opt-out (enabled by default)?
- Rate limiting, throttling, SSL verification, CORS, authentication enforcement —
  these should be enabled by default, not disabled.

**Scope of effect:**
- Does this setting only affect the local development environment, or can it reach staging/production?
- A check like `if settings.DEBUG:` prevents production exposure only if DEBUG is always False in production.
  If DEBUG could be True on staging, the protection is weaker than it looks.

---

## Phase 3 — Analyze deployment files

For `docker-compose.yml` and similar:

**Port exposure:**
- What ports are mapped to the host? (`"0.0.0.0:port:port"` — and a mapping without an IP, `"port:port"` — binds all interfaces)
- Should any of these be localhost-only (`"127.0.0.1:port:port"`)?
- Databases, message brokers, admin UIs should never be on 0.0.0.0 in production-like environments.

**Hardcoded credentials:**
- Are secrets (passwords, API keys, signing keys) hardcoded in environment blocks?
- Are these the same values that reach production (via copy-paste or default config)?

**Committed files:**
- Are `.env`, `env.local`, or similar files committed to the repository?
- Check `.gitignore` — does it exclude sensitive files? `shell("git ls-files")` lists what is actually
  committed; `shell("git check-ignore -v <path>")` shows which ignore rule (if any) covers a file.

---

## Phase 4 — Trace test/debug code paths to production

For every test or debug feature (test middleware, auth injection, debug endpoints):
- Under what exact conditions does it activate?
- Can that condition be true in a non-local deployment?
- What does it allow when active?

---

## What to produce

A hypothesis for each:
- Security feature disabled by default (opt-in rather than opt-out)
- Insecure fallback value for a missing environment variable
- Port or service exposed to all interfaces in deployment config
- Credentials hardcoded in deployment files
- Debug/test feature that can activate outside local development
- Settings file committed to version control containing secrets

For each finding: what does an attacker gain? What environments are affected?

Set `cwe` on each hypothesis (e.g. CWE-1188 insecure default or fallback, CWE-1327 service bound to all
interfaces, CWE-798 hardcoded credential, CWE-489 debug/test feature active outside development, CWE-540
secrets in committed files).

## Forbidden

- Do not grep for specific variable names as the primary method — read the full file
- Do not assume a file is gitignored without checking `.gitignore`
- Do not assume `DEBUG=False` in production without verifying the deployment config
