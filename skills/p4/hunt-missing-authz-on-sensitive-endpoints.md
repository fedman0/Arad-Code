# SKILL: hunt-missing-authz-on-sensitive-endpoints

## ⚡ BREADTH SCAN — grep-first, multi-language, pattern-confirmed

Patterns cover Python/Django/DRF, JavaScript/Express, Go, Java/Spring, PHP, Ruby/Rails. Run grep, read context, submit immediately. 2 tool calls per step maximum.

---

## Step 1 — Financial handler with no authentication enforcement

```
grep(pattern="payment|callback|wallet|checkout|billing|subscribe|transaction|purchase|charge|refund", max_matches=40)
```

For each match in a route handler file: call `get_code_snippet` on the class or function. Look for the absence of:
- Python/DRF: `permission_classes`, `@login_required`, `@permission_required`, `IsAuthenticated`
- Express: `passport.authenticate`, `auth.required`, `ensureLoggedIn`, `requireAuth`, `verifyToken` middleware before the handler
- Go: `AuthMiddleware`, `RequireAuth`, `JWTMiddleware` in the route chain
- Java/Spring: `@Secured`, `@PreAuthorize`, `SecurityConfig` rule for this path
- PHP/Laravel: `auth` middleware group, `$this->middleware('auth')`
- Rails: `before_action :authenticate_user!`, `before_action :require_login`

If NONE of these are present:

**A — Financial handler without authentication**:
→ Submit: violated_invariant="financial handler processes payment state or account changes but has no authentication requirement; any unauthenticated caller can trigger it", severity=9, confidence=7, exposure="internet"

---

## Step 2 — Sandbox/test mode bypasses payment gateway verification

```
grep(pattern="sandbox|is_sandbox|isSandbox|test.*mode|mode.*test|provider.*test|testMode|fake.*payment|mock.*payment", max_matches=20)
```

For each match in a payment handler: call `get_code_snippet`. Look for a branch where the sandbox/test condition causes the gateway signature or payment verification step to be **skipped**, with execution going directly to account credit or subscription activation.

Dangerous pattern (any language):
```python
if provider == "sandbox":
    is_sandbox = True          # no verify_payment() call
if verify_result or is_sandbox:
    activate_subscription()    # sandbox short-circuits verification
```
```js
if (req.body.testMode) {
  // skip gateway.verify()
  return activateSubscription(userId);
}
```

**B — Sandbox mode bypasses payment verification**:
→ Submit: violated_invariant="sandbox/test path skips gateway signature verification and directly activates subscriptions or credits; caller sends sandbox=true to obtain paid service for free", severity=9, confidence=7, exposure="authenticated"

---

## Step 3 — Actor identity for financial operation read from request input

```
grep(pattern="req\\.body\\.[a-z_]*[Ii]d|request\\.data\\.get.*_id|request\\.json.*_id|body\\.[a-z_]*[Ii]d|params\\.[a-z_]*[Ii]d|request\\.form\\.get.*_id", max_matches=20)
```

For each match inside a financial/payment/transfer handler: is the value used to determine WHICH ACCOUNT to charge, credit, or transfer from/to? The attacker supplies their victim's ID in the request body.

**C — Financial actor identity from caller-controlled input**:
→ Submit: violated_invariant="financial handler reads the account to debit/credit from caller-supplied request field; any authenticated user can charge or credit any account by specifying its ID", severity=9, confidence=7, exposure="authenticated"

---

## Step 4 — File or object access without ownership verification

```
grep(pattern="signed_url|presigned_url|getSignedUrl|createPresignedPost|get_object|getObject|signedUrl|downloadUrl|fileUrl", max_matches=20)
```

For each match in a handler: trace from where the file key/identifier is extracted from the request to where the URL or content is returned. Is there a query that filters by BOTH the file key AND the requesting user's identity? If only the file key is used:

**D — File access without ownership check**:
→ Submit: violated_invariant="handler returns file access URL for any caller-supplied identifier without verifying the requesting user owns that resource; any authenticated user can access any file", severity=7, confidence=7, exposure="authenticated"

---

## Step 5 — Monitoring or admin endpoint without authentication

```
grep(pattern="/metrics|/health|/admin|/status|/stats|/monitor|/actuator|/debug", max_matches=30)
```

For each route: check if an authentication middleware is applied specifically to that path. Routes that match broad `*` or are registered before auth middleware run without authentication.

**E — Sensitive endpoint without authentication**:
→ Submit: violated_invariant="[endpoint] registered without authentication; internal state or administrative functionality publicly accessible", severity=6, confidence=7, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
