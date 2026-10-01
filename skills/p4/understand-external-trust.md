# SKILL: understand-external-trust

## Goal

Read every interaction between this application and external systems. Find where
the application trusts data from external sources without adequate verification,
where outbound requests are insecure, and where callbacks can be forged or replayed.

---

## Phase 1 — Find all external interactions

Use `get_architecture` to identify external systems this application communicates with.
Then use `search_graph` and `trace_path` to find the actual code for each interaction.
Do not search by library name — find the code by tracing from the places that initiate
or receive external communication.

Categories to find:
- Outbound HTTP requests (to payment gateways, identity providers, third-party APIs)
- Inbound callbacks (payment confirmation, webhook events, OIDC redirects)
- Message queue consumers (Celery tasks, RabbitMQ consumers, etc.)
- Any other place where data arrives from a system outside this application

---

## Phase 2 — Analyze outbound HTTP requests

For each outbound HTTP call, read the code that makes it. Check:

**SSL/TLS verification:**
- Is certificate verification enabled? This setting exists in every HTTP client library —
  the language-agnostic pattern is: is there any parameter that disables hostname or
  certificate verification?
  - Python requests: `verify=False`
  - Node.js https: `rejectUnauthorized: false`
  - Java HttpClient: custom TrustManager that trusts all certs
  - .NET HttpClient: `DangerousAcceptAnyServerCertificateValidator`
  - Go: `TLSClientConfig: &tls.Config{InsecureSkipVerify: true}`
  - curl/libcurl: `-k` / `--insecure`
- Is verification disabled conditionally on an environment variable?
  Even `if debug: disable_ssl_verify()` is dangerous if the condition is true on staging.

**What is trusted in the response:**
- Does the response contain keys, tokens, identity data, or access control decisions
  that are then trusted by the application?
- Is the response validated (signature, schema, expected format) before being used?
- For OIDC JWKS endpoints: is the fetched public key accepted blindly, or is the
  key ID and algorithm verified against expected values?

**Server-Side Request Forgery (SSRF):**
- Find every place the application constructs a URL for an outbound request where any
  part of the URL is influenced by user-supplied data.
  (URL, hostname, path, port, schema — any user-controlled component)
- Can an attacker redirect the outbound request to:
  - Internal services (metadata APIs at 169.254.169.254, internal microservices, databases)
  - Local network addresses (10.x, 172.16.x, 192.168.x, 127.0.0.1)
  - Other protocols via scheme change (file://, dict://, gopher://, ldap://)
- Read the URL construction and any filtering applied before the request is made.
  Is the hostname resolved BEFORE or AFTER the validation check?
  (DNS rebinding: validate hostname → hostname resolves to public IP → DNS changes → request
  resolves to internal IP)
- Find every feature that fetches user-provided URLs: file import, webhook registration,
  avatar upload from URL, link preview, URL shortener, import-from-URL, etc.

- *Blind SSRF:* If the application does not return the response body to the attacker,
  is the request still detectable?
  - Timing difference: a connection to an internal vs external host may differ in response time.
  - Error codes: "connection refused" (internal port closed) vs "timeout" (no route) are different.
  - Out-of-band: DNS lookup to an attacker-controlled domain (even without HTTP response).
  Blind SSRF is still exploitable for internal network enumeration and, in some cases, RCE.

---

## Phase 3 — Analyze inbound callbacks and webhooks

For each endpoint that receives data from an external system:

**Authentication of the caller:**
Read the view/handler completely. Before the application processes the callback data:
- Is there a signature/HMAC verification step?
- Is a shared secret checked?
- Or is the endpoint entirely unauthenticated (any caller can trigger it)?

**Order of operations:**
- Is authentication verified BEFORE any database writes or state changes?
- Can an attacker trigger the callback handler without the external system's involvement?

**Test/sandbox bypass:**
- Is there a code path for `provider=sandbox` or similar that skips real verification?
- Can an attacker choose the sandbox path in production?

**Replay protection:**
- Can the same callback be processed multiple times?
- Is there an idempotency check before state changes?

---

## Phase 4 — Analyze OIDC/OAuth flows

Read the complete OIDC/OAuth implementation. Verify each check is actually present:
- Is `state` parameter verified (CSRF protection)?
- Is `nonce` verified if using ID tokens?
- Is `audience` (`aud` claim) verified against the expected value?
- Is `issuer` (`iss` claim) verified with exact equality (not prefix match)?
- Are JWKs fetched with SSL verification enabled?

**Authorization code injection (mix-up attack):**
- If the application supports multiple OAuth providers: can a code issued by provider A
  be submitted to the endpoint that expects a code from provider B?
- The `iss` (issuer) in the token response must be verified before accepting the code.

**Authorization code leakage via Referer:**
- After the OAuth callback (e.g. `/callback?code=ABC123`): does the page load any external
  resources (analytics scripts, CDN images, third-party widgets)?
- If yes: the `code=ABC123` in the URL is sent in the `Referer` header to those external
  servers. Read whether the callback URL is cleared before loading external resources,
  or whether a `Referrer-Policy: no-referrer` header is set on the callback response.

---

## What to produce

A hypothesis for each:
- Outbound request with TLS/SSL verification disabled or conditionally disabled
- SSRF: user-controlled data used in outbound URL construction (any component)
- Inbound callback/webhook with no authentication of the caller
- Authentication check that occurs after state-changing operations
- Sandbox/test mode that bypasses real verification and can be triggered by an attacker
- OIDC/OAuth check that is absent or uses loose matching
- Replay attack possible due to missing idempotency

## Forbidden

- Do not search for library imports as a proxy for finding external calls
- Do not assume an OIDC library verifies audience/algorithm without reading the code
- Do not report a callback as unprotected without reading its complete handler
- Do not report SSRF without tracing the user-controlled component to the actual HTTP call
