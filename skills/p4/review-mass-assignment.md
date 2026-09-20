# review-mass-assignment

Audit mass assignment / over-posting vulnerabilities in ORM-bound request models. An attacker supplies unexpected fields in a JSON/form body that get bound to a sensitive model property (e.g. `role`, `is_admin`, `balance`, `owner_id`).

## Scope

- ORM model binding: Entity Framework `FromBody`, Django `ModelForm`, ActiveRecord, Laravel Eloquent `fill()`, Spring `@ModelAttribute`
- GraphQL input types with wildcard binding
- Explicit `[BindProperty]`, `[Bind(Include=...)]`, `$fillable` vs `$guarded` audit

## Methodology

1. Call `get_architecture()` to identify ORM and framework.
2. Search for controller/handler methods that bind request body to a model object:
   - `search_graph(name_pattern="Create|Update|Patch|Put", label="Function")`
   - `grep(pattern="FromBody|ModelForm|fill(|mass_assignment")`
3. For each binding site:
   a. Read the bound model definition — what properties exist?
   b. Check for an allowlist (`[Bind(Include)]`, `$fillable`, `select_related`).
   c. Check for a denylist (`$guarded`, `[JsonIgnore]`). Denylists are weaker — enumerate what they exclude and verify it is exhaustive.
   d. Verify which properties are security-sensitive: `role`, `is_admin`, `owner_id`, `price`, `credit`, `confirmed_at`.
   e. Check if the model is used directly in a DB save or if it goes through a DTO/mapper.
4. Confirm control: can an unauthenticated or low-privilege user reach this endpoint?

## Required proof_obligations

- `reachability`: endpoint reachable by the actor without special privilege
- `input_control`: actor can supply arbitrary JSON fields to the binding point
- `guard`: no allowlist or validator strips the sensitive field before persistence
- `impact`: which business invariant does setting this field violate?

## anchor_text requirement

Provide `anchor_text` pointing to the exact line where the model is bound without filtering (e.g. `context.SaveChanges()` after `model = request.body`).

## Common FP reasons

- DTOs: if the request body is deserialized into a DTO (not the entity), check whether the mapper copies the sensitive field.
- Allowlist present: even if partial, verify the sensitive field is excluded.
- Framework auto-excludes: e.g. Rails `strong_parameters` — confirm `permit()` is called.

Call `reject_hypothesis` with `rejection_condition` when allowlist is exhaustive.
Call `finish()` when complete.
