---
parallel: true
requires: [web, multiservice]
---

# SKILL: understand-infrastructure-security

## Goal

Read the complete URL routing, middleware stack, and infrastructure configuration.
Build a full map of every endpoint and its security posture. Find endpoints with
no authentication, debug/diagnostic endpoints reachable in production-like environments,
and gaps in the middleware security model.

---

## Phase 1 — Read the complete URL/route configuration

Use `list_dir` (and `search_graph(label="Route")` when the graph is indexed) to find all routing configuration
files. The file names vary by framework:
- Python/Django: `urls.py`, `routers.py`
- Java/Spring: classes with `@RequestMapping`, `@GetMapping` etc., or XML route config
- .NET/ASP.NET: `Program.cs`, `Startup.cs`, controller attributes, `MapControllerRoute`
- Node.js/Express: files with `router.get/post/use`, `app.get/post/use`
- Ruby/Rails: `routes.rb`
- Go/Gin: files with `router.GET/POST/Group`
- PHP/Laravel: `routes/web.php`, `routes/api.php`

Read each routing file completely. Do not skim. (`read_file` returns at most 200 lines per call — page through
longer files with `start_line`/`end_line`.)

For every registered route, record:
- Path pattern (including dynamic segments)
- HTTP methods accepted
- Handler (controller, view, function)
- Any inline authentication/authorization settings

Group routes by how they are registered:
- Unconditional (always registered, regardless of environment)
- Conditional on debug flag, environment name, or feature flag
- Conditional on other runtime configuration

---

## Phase 2 — Determine the authentication requirement for every endpoint

For each view, find its permission classes or auth requirements.
Do not search by name — read the view class and its parent classes.

For each endpoint, answer:
- Is authentication required? If not: is that intentional?
- What authentication is accepted? (JWT, session, API key, none?)
- Are there any HTTP methods on this endpoint that are less protected than others?
  (GET requires auth, POST does not — or vice versa)

For endpoints with no authentication:
- What does this endpoint do?
- Is it intentionally public, or was authentication forgotten?
- Can an attacker trigger meaningful side effects through it?

---

## Phase 3 — Read the complete middleware stack

Find the middleware registration (Django `MIDDLEWARE`, ASP.NET Core `app.Use*`, Express `app.use`, Spring filter
chain, etc.) and read every middleware class it references.
Use `get_code_snippet` on each one.

For each middleware:
- What does it do?
- Can it be bypassed by a specific request property (header, path, method)?
- Can it be conditionally disabled by an environment variable?
- If it is a security middleware (auth, CORS, rate limiting, CSP): what happens if it is
  absent or disabled?

---

## Phase 4 — Analyze debug and diagnostic endpoints

For every endpoint registered conditionally:
- What condition controls its registration?
- Read that condition in the settings: what value triggers it?
- Is that value ever True in non-local environments?

Important: `if settings.DEBUG:` is NOT production-safe if DEBUG=True on staging.
Read the deployment configuration (from understand-config-and-deployment) to know
whether the condition actually prevents staging/production exposure.

For every debug/diagnostic endpoint that IS reachable:
- What does it expose or allow?
- Is it authenticated?
- Can it trigger side effects (send notifications, execute operations, expose user data)?

Also find:
- Monitoring endpoints (`/metrics`, `/health`, `/status`, `/actuator`) and their auth requirements
- Documentation endpoints (`/swagger/`, `/openapi/`, `/api-docs`, GraphQL introspection,
  `/graphiql`, `/playground`) and under what conditions they are served
- Any admin UI endpoints (framework admin interfaces, management UIs)

---

## Phase 5 — Dependency security

Find the dependency manifest(s):
- Python: `requirements.txt`, `Pipfile.lock`, `pyproject.toml`
- Node.js: `package.json`, `package-lock.json`
- Java: `pom.xml`, `build.gradle`
- .NET: `.csproj`, `packages.config`, `Directory.Build.props`
- Ruby: `Gemfile.lock`
- Go: `go.mod`, `go.sum`
- PHP: `composer.json`, `composer.lock`

Read the dependency list. Look specifically for:
- Dependencies pinned to old major or minor versions (e.g. a cryptography or auth library
  that had known CVEs in earlier versions)
- Authentication and cryptography libraries — these are highest risk if outdated
- Serialization libraries (especially Java XStream, Jackson, Ruby Marshal-related)
- XML parsing libraries
- Security-sensitive libraries that are no longer actively maintained — a last release several
  years ago in a security-sensitive area is a finding

Do NOT attempt to enumerate all CVEs yourself. Instead: identify library name + version, and
flag specific categories (auth, crypto, serialization, XML) where outdated versions are known
to carry critical vulnerabilities.

---

## Phase 6 — Brute force and rate limiting

For authentication endpoints (login, OTP verification, API key validation, password reset code):
- Is there rate limiting per-user AND per-IP on authentication attempts?
- Is there account lockout after N failed attempts?
  If yes: can the lockout itself be used for denial-of-service against all accounts?
- For OTP codes (6 digits = 1,000,000 values): without rate limiting, all values are
  testable. Read whether the rate limiter is applied BEFORE the OTP is checked.
- Does the rate limiter count by HTTP request, or by individual operation? (alias/batching bypass)

---

## Phase 7 — Dependency confusion

- Does the application install packages from a private registry?
  (Artifactory, Nexus, GitHub Packages, private npm/PyPI mirror)
- For each private package name: is it also registered on the public registry?
  If not: an attacker can register a malicious package under the same name.
  Most package managers prefer the highest version number, which an attacker controls.
- Read the registry configuration:
  - npm: `.npmrc` — does it pin each private scope to the private registry?
  - Python: `pip.conf`, `pyproject.toml` `[[tool.poetry.source]]`
  - NuGet: `nuget.config` — are all private packages in a scoped source?
  - Maven/Gradle: `settings.xml` — mirror/repository order

---

## Phase 8 — CI/CD pipeline security

Read CI/CD configuration files (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`,
`.circleci/config.yml`, `.drone.yml`):

- Are secrets passed to jobs triggered by pull requests from external forks?
  GitHub: a `pull_request_target` (or `workflow_run`) workflow runs with the base repository's
  secrets and write token. It is exploitable when it checks out and runs the PR's code
  (`actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}` or `head.ref`) or
  interpolates PR-controlled fields (`github.event.pull_request.title`, `github.head_ref`) into `run:` steps.
- Are deployment credentials embedded in workflow files instead of using the platform's
  secret management (GitHub Secrets, GitLab Variables, Vault)?
- Are action/step versions pinned to a specific commit SHA?
  A mutable version tag (`uses: some-action@v2`) can be changed by the action author
  to execute malicious code. SHA pinning is the only reliable protection.

---

## What to produce

A hypothesis for each:
- Endpoint with no authentication that allows meaningful actions or data access
- Debug/diagnostic endpoint reachable in staging or production
- Monitoring or documentation endpoint accessible without authentication
- HTTP method inconsistency (safe methods protected, unsafe not — or vice versa)
- Security middleware that can be bypassed or is conditionally disabled
- Authentication, cryptography, or deserialization library pinned to a version with critical CVEs
- No rate limiting on authentication endpoint → brute-force possible
- Private package name not registered on public registry → dependency confusion
- CI/CD: secrets accessible to fork pull requests

For each: specify the exact URL path, dependency, or CI config section, what it exposes, and
under what conditions an attacker can reach it.

Set `cwe` on each hypothesis (e.g. CWE-306 unauthenticated endpoint, CWE-489 debug endpoint reachable, CWE-200
monitoring or documentation exposure, CWE-862 method-level authorization gap, CWE-693 bypassable security
middleware, CWE-1395 vulnerable dependency, CWE-307 no brute-force limit, CWE-427 dependency confusion,
CWE-829 fork PR code running with secrets).

## Forbidden

- Do not search for specific URL substrings — read the full route configuration
- Do not assume conditional registration prevents staging exposure without verifying
  the condition's value in the deployment config
- Do not report an endpoint as unprotected without checking its middleware/guard configuration
  and any global default authentication settings
- Do not enumerate CVEs speculatively — only flag dependencies where you have reasonable
  knowledge of version-specific critical vulnerabilities
