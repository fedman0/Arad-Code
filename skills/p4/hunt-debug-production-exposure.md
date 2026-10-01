# SKILL: hunt-debug-production-exposure

## Goal

Find debug/test code that reaches production or staging. Read files directly. Submit hypotheses immediately when a pattern is found.

---

## Step 1 — Debug URLs unconditionally registered

Read `coreapi/web/urls.py`. Look for URL patterns outside of any `if settings.DEBUG:` or `if settings.ENV` block. Specifically look for `notification-debug`, `debug/interact`, `load-test`, `memory-test`.
If any debug URL is registered unconditionally → **submit hypothesis**: violated_invariant="debug endpoint registered unconditionally in production URLconf", severity=7, confidence=9.

## Step 2 — OTP leaked in response header

Search for `X-Test-Code` in the codebase (search_code or grep).
If found in a response `headers=` dict, note the condition — is it `if settings.DEBUG:` only, or `if settings.ENV != 'prod':`?
If the condition includes staging → **submit hypothesis**: violated_invariant="OTP/verification code returned in X-Test-Code response header; any request to staging can read it", severity=8, confidence=9.

## Step 3 — Swagger on staging

Read `hesaboai/urls.py`. Find where Swagger is registered.
If the condition is `if settings.ENV in ('dev', 'stage')` or similar (not `if settings.DEBUG:` only) → **submit hypothesis**: violated_invariant="Swagger/OpenAPI docs served in staging environment without access control", severity=5, confidence=9.

## Step 4 — Debug endpoints behind DEBUG only

Read `agents/urls.py`. Look for `if settings.DEBUG:` blocks registering `load-test`, `memory-test`, `debug/interact`, `cpu-usage`.
If any of these includes an unbounded computation (e.g., fibonacci without upper bound) → **submit hypothesis**: violated_invariant="load-test endpoint behind DEBUG check only; unbounded fib(N) is DoS if DEBUG=True on server", severity=4, confidence=8.

## Step 5 — Prometheus /metrics no auth

Read `hesaboai/urls.py` for `django_prometheus.urls` include.
Is there any authentication wrapper or IP restriction around it?
If metrics exposed with no auth → **submit hypothesis**: violated_invariant="Prometheus /metrics endpoint served without authentication", severity=6, confidence=9.

## Finish

Call finish() with all hypotheses found. Call it even with an empty list.
