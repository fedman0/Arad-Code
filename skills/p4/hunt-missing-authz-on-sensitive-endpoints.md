# SKILL: hunt-missing-authz-on-sensitive-endpoints

## ⚡ BREADTH SCAN — grep-first, semgrep-derived patterns, multi-language

Run grep, read context with `get_code_snippet`, submit immediately. 2 tool calls per step max.

---

## Step 1 — Financial handler with no authentication enforcement

```
grep(pattern="payment|callback|wallet|checkout|billing|subscribe|transaction|purchase|charge|refund|transfer|deposit|withdraw", max_matches=40)
```

For each match in a route handler file: call `get_code_snippet` on the class or function. Look for the **absence** of:

- **Python/Django DRF**: `permission_classes`, `@login_required`, `@permission_required`, `IsAuthenticated`, `get_permissions`
- **FastAPI**: `Depends(get_current_user)`, `Security(...)`, `HTTPBearer`
- **Express / Node**: `passport.authenticate`, `requireAuth`, `ensureLoggedIn`, `verifyToken`, `authenticate` middleware in router chain
- **Go**: `AuthMiddleware`, `RequireAuth`, `JWTMiddleware`, `jwt.New` in route group
- **Java / Spring**: `@Secured`, `@PreAuthorize`, `hasRole`, `SecurityConfig.configure` rule for this path, `@RolesAllowed`
- **PHP / Laravel**: `$this->middleware('auth')`, `Route::middleware(['auth'])`, `auth:api`
- **Ruby / Rails**: `before_action :authenticate_user!`, `before_action :require_login`, `before_action :authenticate!`
- **C# / .NET**: `[Authorize]`, `RequireAuthorization()`, `policy.RequireAuthenticatedUser()`

If NONE of these are present:

**A — Financial handler without authentication**:
→ Submit: violated_invariant="financial handler processes payment state or account changes but has no authentication requirement; any unauthenticated caller can trigger it", severity=9, confidence=7, exposure="internet"

---

## Step 2 — Sandbox/test mode bypasses payment gateway verification

```
grep(pattern="sandbox|is_sandbox|isSandbox|test.*mode|mode.*test|provider.*test|testMode|fake.*payment|mock.*payment|isDev.*pay|TEST_PAYMENT", max_matches=20)
```

For each match in a payment handler: call `get_code_snippet`. Look for a branch where sandbox/test condition causes the gateway signature or verification to be **skipped**, with execution going directly to account credit or subscription activation:

```python
if provider == "sandbox":
    is_sandbox = True          # no verify_payment() call
if verify_result or is_sandbox:
    activate_subscription()    # sandbox short-circuits verification
```
```js
if (req.body.testMode || req.body.sandbox) {
    return activateSubscription(userId);   // skip gateway.verify()
}
```
```csharp
if (request.IsSandbox) {
    // skip IPaymentGateway.Verify()
    await ActivateSubscriptionAsync(userId);
}
```

**B — Sandbox mode bypasses payment verification**:
→ Submit: violated_invariant="sandbox/test path skips gateway signature verification and directly activates subscriptions or credits; caller sends sandbox=true to obtain paid service for free", severity=9, confidence=7, exposure="authenticated"

---

## Step 3 — Actor identity for financial operation read from request input

```
grep(pattern="req\.body\.[a-z_]*[Ii]d|request\.data\.get.*_id|request\.json\(\)\[.*[Ii]d|body\.[a-z_]*[Ii]d|params\.[a-z_]*[Ii]d|request\.form\.get.*_id|\$request->input.*_id|params\[:.*_id\]", max_matches=20)
```

For each match inside a financial/payment/transfer handler: is the value used to determine WHICH ACCOUNT to charge, credit, or transfer from/to?

```python
user_id = request.data.get('user_id')        # caller-controlled
transfer_from = request.json.get('from_id')
```
```csharp
var targetUserId = request.Body.UserId;      // not from ClaimsPrincipal
```

**C — Financial actor identity from caller-supplied input**:
→ Submit: violated_invariant="financial handler reads account to debit/credit from caller-supplied request field; any authenticated user can charge or credit any account by specifying its ID", severity=9, confidence=7, exposure="authenticated"

---

## Step 4 — File or object access without ownership verification

```
grep(pattern="signed_url|presigned_url|getSignedUrl|createPresignedPost|get_object|getObject|signedUrl|downloadUrl|fileUrl|generateDownloadUrl|GetBlobSasUri|GetSharedAccessSignature", max_matches=20)
```

For each match in a handler: trace from where the file key/identifier is extracted from the request to where the URL or content is returned. Is there a query that filters by BOTH the file key AND the requesting user's identity?

```python
key = request.query_params.get('key')
url = s3.generate_presigned_url(key)          # no user_id filter
```
```csharp
var blobName = request.Query["file"];
var sas = container.GetBlobSasUri(blobName);  # no ownership check
```

If only the file key is used:

**D — File access without ownership check**:
→ Submit: violated_invariant="handler returns file access URL for any caller-supplied identifier without verifying the requesting user owns that resource; any authenticated user can access any file", severity=7, confidence=7, exposure="authenticated"

---

## Step 5 — Admin or monitoring endpoint without authentication

```
grep(pattern="/metrics|/health|/admin|/status|/stats|/monitor|/actuator|/debug|/internal|/management|/sys|/ops", max_matches=30)
```

**C# / .NET — [AllowAnonymous] on sensitive endpoint:**
```
grep(pattern="\[AllowAnonymous\]", max_matches=15)
```

For each [AllowAnonymous] match: call `get_code_snippet`. Is it on an admin, management, or financial controller?

For route-level matches: check if an authentication middleware is applied specifically to that path. Routes that match broad `*` or are registered before auth middleware run without authentication.

**E — Sensitive endpoint without authentication**:
→ Submit: violated_invariant="[endpoint] registered without authentication or with [AllowAnonymous]; internal state or administrative functionality publicly accessible", severity=6, confidence=7, exposure="internet"

---

## Step 6 — IDOR: database record fetched by caller-supplied ID without ownership filter

```
grep(pattern="FindById|findById|GetById|getById|find_by_id|first_or_404|get_object_or_404|SingleOrDefault.*Id|FirstOrDefault.*Id|Where.*Id.*==", max_matches=30)
```

For each match in a handler: does the query include the current user's identity as a filter condition?

```python
order = Order.objects.get(pk=order_id)         # missing: user=request.user
```
```csharp
var order = await _repo.FindByIdAsync(orderId); // missing: .Where(o => o.UserId == userId)
```
```java
Order order = orderRepo.findById(orderId).get(); // no ownership predicate
```

**F — Record fetched without ownership filter (IDOR)**:
→ Submit: violated_invariant="handler fetches record by caller-supplied ID without filtering by the requesting user's identity; any authenticated user can access any record of that type", severity=8, confidence=7, exposure="authenticated"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
