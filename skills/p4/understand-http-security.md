# SKILL: understand-http-security

## Goal

Read and understand how this application handles HTTP at the protocol level.
Find where CORS policy, CSRF protection, header trust decisions, caching, and
HTTP method handling can be exploited.

This skill is language-agnostic. CORS misconfigurations, CSRF issues, and Host header injection
exist identically in Django, Spring, ASP.NET Core, Express, Rails, Laravel, Go/Gin, and any
other framework. Focus on the pattern, not the framework API name.

---

## Phase 1 — CORS policy

Find the CORS configuration. Regardless of framework, CORS is configured by a middleware,
filter, or decorator that sets `Access-Control-Allow-Origin` (and related headers) on responses.

Read the configuration completely. Then answer:

**Origin allowlist:**
- Is any origin allowed? (`Access-Control-Allow-Origin: *` or equivalent wildcard)
  With wildcard origins, credentialed cross-origin requests are blocked by browsers —
  but non-credentialed requests (including reading public data) are open to any site.
- Is the origin validated from a list? Read the exact validation:
  - Regex/pattern: `.*example\.com` matches `evil-example.com`; `^https://example\.com$` is safe.
  - Prefix check: `origin.startsWith("https://example.com")` matches `https://example.com.evil.com`.
  - Is the `null` origin accepted? (Sandbox iframes send `Origin: null`)
- Is there a reflected origin policy? (`Access-Control-Allow-Origin: <whatever the client sent>`)
  This is equivalent to `*` but also enables credentialed CORS exploitation.

**Credentials:**
- Is `Access-Control-Allow-Credentials: true` set?
- If yes: the origin validation must be exact — any bypass allows full cross-origin reads
  with the victim's cookies/session.

**What can be read cross-origin?**
- Even with strict origin validation: is there any sensitive data in responses that a
  permitted origin could exfiltrate? If a subdomain is trusted, compromising that subdomain
  gives full CORS access.

---

## Phase 2 — CSRF protection

Find how CSRF is handled for state-changing operations.

**For session-based authentication:**
- Is there a CSRF token mechanism? (synchronizer token, double-submit cookie, custom header)
- Are state-changing endpoints (POST, PUT, PATCH, DELETE) protected by CSRF validation?
- Are any endpoints explicitly exempted? Read the exemption list — is every exemption safe?
- What is the SameSite attribute on session cookies?
  - `SameSite=Strict`: POST from another origin is blocked by browser.
  - `SameSite=Lax`: GET+redirect is allowed; state-changing methods are blocked.
  - `SameSite=None; Secure`: no browser-level CSRF protection.
  - Missing SameSite (browser default): varies by browser, often treated as `Lax`.

**For token-based (Bearer/JWT) authentication:**
- Bearer tokens sent in the `Authorization` header are NOT automatically sent by the browser
  on cross-origin requests — so CSRF is not applicable for these endpoints, UNLESS the
  application also accepts the token from a cookie. If so: same CSRF considerations apply.

**The danger combination:**
- Session cookie with `SameSite=None` or missing + no CSRF token + state-changing endpoint
  = a third-party site can perform actions on behalf of a logged-in user.

---

## Phase 3 — Header-based trust decisions

Find every place the application reads from HTTP headers to make a security-relevant decision.
Use `search_code` to find where headers are read (`request.headers`, `req.get()`,
`HttpContext.Request.Headers`, `request.getHeader()`, `$_SERVER['HTTP_X_']`, etc.).
Read each usage in its full context.

**IP address extraction:**
- Find where the "client IP" is determined. Is it from the connection's remote address
  (the actual TCP peer) or from a header?
- Headers that carry client IP (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`,
  `True-Client-IP`, `X-Client-IP`, `Forwarded`) can be set by an attacker unless a
  trusted reverse proxy strips/overwrites them.
- If IP is used for rate limiting, geo-blocking, allowlisting, or audit logging:
  an attacker can spoof their IP by sending the appropriate header.
- Read exactly what the application does when the header contains multiple values
  (comma-separated IPs in `X-Forwarded-For` — which one is taken: first, last, all?).

**Host header:**
- Find where `Host` (or a derived value: absolute URL, `request.build_absolute_uri()`,
  `Request.Url`, `HttpContext.Request.Host`, `req.hostname`, etc.) is used to generate URLs.
- Common uses: password reset emails, email confirmation links, API callback URLs,
  payment return URLs, webhook delivery URLs.
- If the Host header influences a URL that is sent externally (email, API callback),
  an attacker can poison the link to point to their own server.
- Is there a strict allowlist of accepted Host values? Read it.
  `ALLOWED_HOSTS = ['*']` (Django), no `allowedHosts` in development config, etc. = any Host accepted.

**HTTP method override:**
- Does any middleware or the application code check for `X-HTTP-Method-Override`,
  `X-Method-Override`, or a `_method` form parameter to change the effective HTTP method?
- If a DELETE endpoint requires admin privilege but a POST endpoint does not, and method
  override is trusted, an attacker may escalate by sending `POST ... X-HTTP-Method-Override: DELETE`.

**Other trusted headers:**
- Are there any headers that grant elevated trust or bypass checks?
  (`X-Internal-Request`, `X-Service-Token`, `X-Admin-Override`, `X-Authenticated-User`, etc.)
  Read if these can be set by an external client.

---

## Phase 4 — HTTP response caching

Find where HTTP caching headers are set on responses.

**Authenticated or user-specific responses:**
- Are they marked `Cache-Control: private, no-store`?
- A shared cache (CDN, reverse proxy, load balancer) that stores an authenticated response
  can serve it to the next unauthenticated visitor.

**Cache poisoning:**
- Can an attacker cause a response to be cached that another user will then receive?
- An unkeyed header (used in generating the response but not in the cache key) can poison:
  the attacker sends a crafted header, the poisoned response is cached, other users receive it.

**Web cache deception:**
- Can an attacker trick the cache into storing a response that contains the victim's data?
  (Requesting `/profile/photo.jpg` if the server serves the profile but the cache stores it
  as a static asset accessible to anyone)

---

## Phase 5 — HTTP security headers

Find what security-related HTTP headers are set on responses (check middleware or response
builders that apply to all responses):
- `Strict-Transport-Security` (HSTS): enforces HTTPS; absence means downgrade attacks possible.
- `Content-Security-Policy` (CSP): limits what scripts/resources can be loaded; absence
  means XSS is easier to exploit.
- `X-Frame-Options` or `frame-ancestors` CSP directive: prevents clickjacking.
- `X-Content-Type-Options: nosniff`: prevents MIME-type sniffing.
- `Referrer-Policy`: limits URL sent in Referer header (can leak sensitive path parameters).

A missing security header is a finding IF it materially affects exploitability.
(Missing HSTS on a login endpoint = real risk; missing on a fully static page = lower risk)

---

## Phase 6 — Open redirect

Find every redirect operation where the destination is influenced by user input.
(`next`, `returnUrl`, `redirect_uri`, `goto`, `url`, `continue`, `target` — any parameter
that causes a redirect)

- Is the destination validated? Is it restricted to the same origin (same host + scheme)?
  Or is it an explicit allowlist of allowed destination URLs?
- An open redirect to any external URL enables phishing and OAuth abuse.
- Bypass patterns to check: `//evil.com`, `https:evil.com`, `https://trusted.com@evil.com`,
  `https://trusted.com.evil.com`, URL-encoded scheme (`%68ttps://`), whitespace before scheme.
- For OAuth `redirect_uri`: is it validated against an exact registered allowlist?
  Subdirectory or wildcard matches (`https://app.com/*`) allow open redirect attacks.

---

## Phase 7 — HTTP request smuggling surface

This applies when a reverse proxy or load balancer sits in front of the application.
Check deployment config (`nginx.conf`, `traefik.yml`, `haproxy.cfg`, k8s ingress annotations):
- Does the proxy forward requests to the backend over HTTP/1.1 with keep-alive?
- Does it forward both `Content-Length` and `Transfer-Encoding` headers to the backend?
  If so: CL.TE or TE.CL smuggling may be possible.
- If no proxy is identifiable: note as not applicable.

---

## What to produce

A hypothesis for each:
- CORS origin validation bypassable by a crafted origin (regex, prefix, or reflection)
- `Allow-Credentials: true` with a permissive or bypassable origin check
- Session-authenticated state-changing endpoint with no CSRF protection and weak SameSite
- IP address extracted from an attacker-controllable header for security decisions
- Host header accepted without strict validation in URL generation for external delivery
- HTTP method override enabling access control bypass
- Authenticated responses cached by a shared/public cache
- Missing security header with material security impact
- Open redirect: user-controlled redirect destination without origin restriction
- OAuth redirect_uri without exact-match validation

## Forbidden

- Do not report a finding without reading the actual configuration or code that implements it
- Do not report CSRF on Bearer-token-only endpoints where the token cannot be sent by the browser
- Do not report a missing security header as a finding without assessing its actual impact
- Do not assume a CDN or proxy strips attacker-controlled headers without finding evidence
- Do not report open redirect without tracing the redirect destination to actual user input
