# SKILL: hunt-debug-production-exposure

## Goal

Find every place where debug, test, or development code can reach a production or
staging deployment. These bugs cause authentication bypass, information disclosure,
and DoS vulnerabilities in environments where developers assume debug features are off.

---

## Step 1 — Map all URL registration that is conditional on DEBUG or ENV

Read every `urls.py` file in the project. For each URL pattern block, note whether it is:
- **Unconditional** (always registered, regardless of DEBUG/ENV)
- **Conditional on DEBUG**: `if settings.DEBUG:`
- **Conditional on ENV**: `if settings.ENV in ('dev', 'stage'):` etc.

For conditionally registered URLs: can the condition be True in a non-local deployment?
- `DEBUG=True` on staging is common when developers forget to set it
- `ENV != 'prod'` includes staging — URLs registered this way are reachable in staging

For unconditionally registered debug URLs: this is always a finding.

---

## Step 2 — Audit each debug/test URL for impact

For every debug endpoint found in Step 1, read its view class or handler function completely.

**High-impact patterns:**
- Endpoints that trigger Celery tasks for ALL users (no per-user scope)
- Endpoints that compute unbounded CPU-intensive operations (fibonacci, factorial, recursion)
  without an upper-bound check on the input parameter → DoS
- Endpoints that return internal state (memory usage, CPU stats, process info)
- Endpoints that accept arbitrary code execution or shell commands

For each: what is the permission_classes? Is `is_admin()` checked? If not — any authenticated
user can call it.

---

## Step 3 — Find middleware that activates conditionally

Read every middleware in MIDDLEWARE settings. For each middleware class, read its __call__
or process_request method. Look for:

```python
if os.environ.get('LOCAL_TESTING') == 'True':
if settings.TESTING:
if getattr(settings, 'TEST_MODE', False):
```

For each: what does the middleware do when the condition is True?
- If it injects an authentication token for unauthenticated requests → authentication bypass
- If it disables security checks → broad vulnerability

Can the enabling condition be set in a deployed server environment (not just `runserver`)?
An env var like `LOCAL_TESTING=True` can be accidentally set in a staging deployment.

---

## Step 4 — Find OTP / test codes leaked in response headers

Search for patterns like:
```python
headers = {'X-Test-Code': code}  # or X-Debug-OTP, X-Verification-Code
Response(..., headers=headers)
```

Note the condition: is this inside `if settings.DEBUG:` only, or `if settings.ENV != 'prod':`?
The latter runs in staging. Leaking an OTP or verification code in response headers allows
account takeover for any phone/email on staging.

---

## Step 5 — Find Swagger/OpenAPI exposed in non-prod environments

Search for Swagger/schema URL registration. Common patterns:
```python
path('swagger/', schema_view...)
path('api-docs/', ...)
```

What is the condition? `if settings.DEBUG:` or `if settings.ENV in ('dev', 'stage'):` or unconditional?
If staging is accessible to external users, Swagger exposure is an information disclosure finding.

---

## Step 6 — Audit Prometheus / monitoring endpoint exposure

Search for:
```python
include('django_prometheus.urls')
path('metrics', ...)
path('actuator/', ...)  # Spring Boot
```

Is there authentication middleware on this path? Is it behind an IP allowlist?
If `/metrics` is reachable without authentication, it exposes request counts per endpoint,
error rates, DB query timings, cache stats — aiding targeted attacks.

---

## What to produce

A hypothesis for EACH of:
- Debug endpoint unconditionally registered in production URLconf (not inside `if DEBUG:`)
- Debug endpoint registered with `ENV != prod` condition (reachable in staging)
- Debug endpoint with no admin check — any authenticated user can trigger it
- Debug endpoint with unbounded CPU operation (DoS) — even with admin check, note as finding
- Test middleware that can activate in staging (condition based on env var, not just DEBUG)
- OTP or verification code leaked in response header in non-prod environments
- Swagger/OpenAPI served in staging environment without access control
- Prometheus /metrics served without authentication

For each, set `entry_point` to the specific file:line where the URL is registered,
and `execution_path` to show what the endpoint does and why it is dangerous.
