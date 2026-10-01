# SKILL: hunt-missing-authz-on-sensitive-endpoints

## Goal

Find endpoints that handle sensitive operations (payments, file access, privileged actions) but lack authentication, ownership verification, or gateway signature validation. Search, read, decide, submit immediately.

---

## Step 1 — Payment or webhook callback without gateway signature

Search for payment callback, webhook receiver, or IPN handler (search_code for `callback`, `webhook`, `notify`, `ipn`, `payment.*return`, `gateway.*confirm`; or search_graph for classes/functions handling payment provider redirects).
Read the handler. Check:
1. Is `permission_classes`, `authentication_required`, or equivalent set? If absent or `AllowAny` → unauthenticated.
2. Is the request body/headers verified against a gateway-provided HMAC or signature? Look for HMAC computation, signature header extraction, or calls to the gateway SDK's verification method.
3. Does the endpoint accept a `provider`, `type`, or `mode` parameter that selects different code paths — including a sandbox/test path?
**Finding condition**: callback endpoint (a) has no authentication AND no gateway signature verification, OR (b) accepts a `sandbox`/`test` provider value that bypasses real verification.
→ **submit hypothesis immediately**: violated_invariant="payment callback accepts unauthenticated requests without gateway signature verification; attacker can forge payment confirmation for arbitrary transactions", severity=9, confidence=8.

## Step 2 — File/object storage access without ownership check

Search for views or handlers that issue presigned/signed URLs for object storage (search_code for `get_signed_url`, `presigned_url`, `generate_presigned`, `getObject`, `createSignedUrl`, `blob_url`; or search_graph for MinIO/S3/GCS client usage).
Read the handler that accepts a file identifier from the request and returns the URL.
**Finding condition**: between accepting the file key/name/id from the request and calling the storage client, there is NO database lookup that verifies the requesting user owns or has permission to access that specific file.
→ **submit hypothesis immediately**: violated_invariant="signed storage URL issued for user-supplied file key without ownership verification; any authenticated user can access any file by key", severity=6, confidence=8.

## Step 3 — Admin operation with permission check bypassable by header

Search for admin permission check function (search_graph for `is_admin`, `isAdmin`, `checkAdmin`, `hasAdminRole`).
Read it. If it grants admin based on a user-controlled HTTP header (see also hunt-auth-bypass-patterns Step 1), search for all call sites (search_code for `is_admin(` or `isAdmin(`).
For each endpoint that calls this function: note that the permission check is bypassable.
**Finding condition**: at least one endpoint grants access to sensitive data (all users' records, financial data, support tickets) based solely on the bypassable admin check with no secondary defense.
→ **submit hypothesis per endpoint category**: violated_invariant="admin endpoint relies solely on bypassable admin check; any user who can send arbitrary headers accesses [admin resource]", severity=9, confidence=8.

## Finish

Call finish() with all hypotheses found. Call it now even if the list is empty. Set confidence lower rather than raising blocking open questions.
