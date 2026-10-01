# SKILL: hunt-missing-authz-on-sensitive-endpoints

## ⚡ BREADTH SCAN — grep-first, pattern-confirmed

Each step gives an exact grep pattern. Run it, read the match context, submit if confirmed. 2 tool calls per step maximum.

---

## Step 1 — Financial handler with no authentication requirement

```
grep(pattern="class.*[Pp]ayment.*[Vv]iew|class.*[Cc]allback.*[Vv]iew|class.*[Ww]allet.*[Vv]iew|class.*[Cc]heckout.*[Vv]iew|class.*[Bb]illing.*[Vv]iew", max_matches=10)
```

For each match: call `get_code_snippet` on that class. Look for the presence of `permission_classes`, `@login_required`, `@require_auth`, `IsAuthenticated`, `auth.required`, or equivalent authentication decorator/annotation. If NONE of these are present in the class body:

**A — Payment handler without authentication**:
→ Submit: violated_invariant="financial handler processes payment state changes but has no authentication requirement; any unauthenticated caller can trigger payment confirmation", severity=9, confidence=7, exposure="internet"

---

## Step 2 — Sandbox/test mode bypasses payment verification

```
grep(pattern="sandbox|is_sandbox|test.*mode|mode.*test|provider.*test", max_matches=20)
```

For each match in a payment-related file: call `get_code_snippet` on the surrounding function. Look for a branch where `provider == "sandbox"` or `mode == "test"` causes the payment gateway verification step to be SKIPPED, and directly triggers account credit or subscription activation.

Dangerous pattern:
```
if provider == "sandbox":
    is_sandbox = True
    # ... verify_payment() is NOT called
if verify_result or is_sandbox:    ← sandbox value short-circuits
    activate_subscription(...)
```

**B — Sandbox mode bypasses payment verification**:
→ Submit: violated_invariant="sandbox/test path skips gateway signature verification and directly activates subscriptions; caller sends provider=sandbox to get a paid subscription for free", severity=9, confidence=7, exposure="authenticated"

---

## Step 3 — Actor identity for financial operation read from request body

```
grep(pattern="validated_data\\[.*id\\]|data\\[.*account.*id\\]|request\\.data\\.get.*employee|request\\.data\\.get.*user_id|body\\[.*account\\]", max_matches=10)
```

For each match in a payment/wallet handler: is the value used to determine WHICH ACCOUNT to charge? If the actor identity (who to debit) comes from caller-controlled request fields rather than from the verified token/session:

**C — Actor identity from request input**:
→ Submit: violated_invariant="financial handler reads the account to debit from a caller-controlled request field; any authenticated user can charge any account by specifying its ID", severity=9, confidence=7, exposure="authenticated"

---

## Step 4 — File access without ownership verification

```
grep(pattern="signed_url|get_signed_url|presigned_url|generate_url.*key|get_object.*key", max_matches=10)
```

For each match: call `get_code_snippet` on the surrounding function. Trace from where the file key/identifier is extracted from the request (`request.query_params.get`, `data["key"]`, etc.) to where the signed URL is returned. Is there a database query that filters by BOTH the file key AND the requesting user's identity? If only the file key is checked:

**D — No ownership check before file access**:
→ Submit: violated_invariant="handler returns signed file access URL for any caller-supplied file identifier without verifying the requesting user owns that file", severity=7, confidence=7, exposure="authenticated"

---

## Step 5 — Privilege decision from request header

```
grep(pattern="request\\.headers\\.get.*return.*True|if.*in.*request\\.headers.*return|META\\.get.*return True|getHeader.*==.*return true|r\\.Header\\.Get.*return nil", max_matches=10)
```

Also:
```
grep(pattern="permission.*header|auth.*header.*value|header.*grant|header.*privilege|header.*admin", max_matches=10)
```

If found: a function that reads an HTTP header and returns a boolean authorization decision without checking a database record or cryptographic token.

**F — Header-based privilege grant**:
→ Submit: violated_invariant="authorization decision made from caller-controlled request header value rather than a verified server-side record; any caller adds the header to gain elevated access", severity=10, confidence=7, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
