# SKILL: hunt-missing-authz-on-sensitive-endpoints

## Goal

Find endpoints handling sensitive operations that lack authentication or ownership verification. Read files directly. Submit hypotheses immediately.

---

## Step 1 — Payment callback no auth / no signature

Search for `PaymentCallBackView` or `callback` in `coreapi/web/views/PaymentViews.py`.
Read the class. Check: is `permission_classes` set? Is there HMAC/signature verification of the gateway request body?
Does the endpoint accept `provider=sandbox` query parameter?
If no signature verification → **submit hypothesis**: violated_invariant="payment callback accepts unauthenticated requests with no gateway signature verification; attacker can forge payment confirmations", severity=9, confidence=8.

## Step 2 — FileManager ownership check

Read `coreapi/web/views/FileManager.py` (search_graph for `FileManager` if needed).
In the GET handler: between `request.GET.get('file_name')` and `MinioClient.get_signed_url(file_name)`, is there a DB lookup verifying the requesting user owns that file?
If no ownership check → **submit hypothesis**: violated_invariant="FileManager GET issues MinIO signed URL for any file_key without verifying the requester owns the file", severity=6, confidence=8.

## Step 3 — Admin endpoints with weak is_admin

Read `coreapi/application/utilities/AdminCheck.py` for `is_admin`.
Then find one admin endpoint (search for `is_admin(request)` call site).
Does the endpoint have `permission_classes = [IsAuthenticated]` (not `[IsAdminUser]`) and rely solely on `is_admin()` for the admin check?
If is_admin() is the only gate → note this is coupled to the header bypass finding.
Submit a hypothesis only if `is_admin()` has a bug (see hunt-auth-bypass-patterns Step 1).

## Finish

Call finish() with all hypotheses found. Call it even with an empty list. Do NOT raise open questions for anything you could not verify — just set confidence lower.
