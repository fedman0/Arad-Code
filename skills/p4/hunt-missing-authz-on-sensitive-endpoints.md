# SKILL: hunt-missing-authz-on-sensitive-endpoints

## Goal

Find every endpoint that handles sensitive operations (payments, file access, admin actions,
mass notifications) but is missing authentication, authorization, or ownership verification.

---

## Step 1 — Find payment and webhook callback endpoints

Search for view classes or functions with names containing: `callback`, `webhook`, `notify`,
`return`, `ipn`, `confirm`, `verify_payment`.

For each:
1. What is `permission_classes`? If absent, DRF defaults to `DEFAULT_PERMISSION_CLASSES`
   — read what that is. If empty or AllowAny, it is unauthenticated.
2. Is there a gateway signature or HMAC verification?
   - The payment gateway sends a secret in headers or body that proves the request came from them
   - Search for the gateway name + "signature", "hmac", "token", "secret"
   - If the callback body/params are accepted without any cryptographic proof of origin,
     an attacker can forge callbacks
3. Does the endpoint accept a `provider` or `type` parameter from the query string?
   - If different providers take different code paths, check whether `provider=sandbox` or
     `provider=test` can be used in production to skip real gateway verification

---

## Step 2 — Find endpoints with admin operations but weak permission checks

Find views that call `is_admin()` or `request.user.is_superuser`. Read the `is_admin`
function completely. Then for each endpoint:
- Is `permission_classes = [IsAuthenticated]` used when `[IsAdminUser]` should be?
- Is there any secondary check after `is_admin()` returns True?
- Can `is_admin()` return True for a non-superuser (see also: hunt-auth-bypass-patterns)?

---

## Step 3 — Find file access endpoints without ownership verification

Search for views that:
- Accept a file path, file name, file key, or object key from the request (query params or body)
- Then call a storage client (MinIO, S3, GCS, local filesystem) to generate a signed URL or return content

For each: is there a database lookup that verifies the requesting user owns the file?
Pattern to look for:
```python
file_name = request.GET.get('file_name')  # attacker-controlled
signed_url = storage.get_signed_url(file_name)  # no ownership check between these
```
If the user can supply any file key and get a signed URL for it, that is a horizontal
privilege escalation / IDOR.

---

## Step 4 — Find mass-action endpoints

Search for views that trigger operations for ALL users or many users at once:
- Sending notifications to all users
- Triggering background tasks for all users (Celery tasks iterating over user list)
- Bulk data export without scoping

For each: what is the authentication/authorization? Is it admin-only? Is there a rate limit?
An endpoint that triggers LLM API calls for ALL users is especially high-impact (unbounded cost).

---

## Step 5 — Find monitoring/metrics endpoints without auth

Search for:
- `django_prometheus` or `prometheus_client` URL registration
- `/metrics`, `/health`, `/actuator`, `/status` endpoints
- Any endpoint that returns system internals (memory, CPU, DB stats, request counts)

For each: is there authentication or IP allowlisting? If not, these expose internal metrics
that aid targeted attacks.

---

## What to produce

A hypothesis for EACH of:
- Payment/webhook callback endpoint with no gateway signature verification
- Payment callback that accepts `provider=sandbox` or similar bypass in any environment
- File/object access endpoint that issues signed URLs without ownership verification
- Admin operation endpoint with permission check that can be bypassed (weak `is_admin`)
- Mass-action endpoint (triggers for all users) without admin-only access control
- Monitoring/metrics endpoint without authentication
- Any endpoint with `AllowAny` permission class (or no permission class) that writes data
  or accesses sensitive resources

For each, `entry_point` = the view class and endpoint URL, `execution_path` = the exact
steps from HTTP request to the dangerous operation, `violated_invariant` = the specific
authorization property that is missing.
