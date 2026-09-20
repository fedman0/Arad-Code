# review-webhook-and-callback-trust

Audit inbound webhook and async callback endpoints for signature verification bypass, replay attacks, and SSRF via attacker-controlled callback URLs.

## Scope

- Inbound webhooks: Stripe, GitHub, Slack, Twilio, custom — signature verification
- Callback URLs: OAuth callbacks, payment return URLs, async job notifications
- Replay protection: timestamp window, nonce deduplication
- SSRF via callback: attacker-controlled `callback_url` parameter reaching internal services

## Methodology

1. `search_graph(name_pattern="webhook|callback|notify|hook", label="Route")` to enumerate endpoints.
2. For each webhook endpoint:
   a. Read the handler function fully.
   b. Check: is the signature header read before the body is processed?
   c. Check: is the HMAC computed over the raw body (not parsed JSON)?
   d. Check: is the timestamp validated against a short window (≤5 minutes)?
   e. Check: is the nonce/event-id stored and deduplicated?
   f. If signature check absent or bypassable: create hypothesis.
3. For callback URL parameters:
   a. `search_graph(name_pattern="callback_url|redirect_url|return_url", label="Parameter")`
   b. Trace: does the callback URL reach `fetch()`, `HttpClient`, `requests.get()`?
   c. Check: is the URL validated against an allowlist of trusted origins?
   d. Check: is internal IP range / metadata endpoint blocked?

## Required proof_obligations

- `reachability`: can an external caller send a request to this endpoint?
- `input_control`: can the attacker forge the payload or supply a malicious callback URL?
- `guard`: is signature verification absent, bypassable, or computed over wrong data?
- `impact`: SSRF to internal services, unauthorized order state change, account takeover

## anchor_text requirement

For signature bypass: anchor to the exact line where the body is processed before signature verification, or where the signature comparison is skipped.

## Common FP reasons

- Signature check present but conditional: verify the condition covers all code paths.
- Allowlist present for callback URLs: verify it is not bypassable via URL parsing confusion.

Call `reject_hypothesis` with `rejection_condition` citing the specific verification line.
Call `finish()` when complete.
