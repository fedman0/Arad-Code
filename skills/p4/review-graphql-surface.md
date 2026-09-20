# review-graphql-surface

Audit GraphQL endpoints for introspection exposure, missing field-level authorization, query depth/complexity abuse, batching attacks, and type confusion.

## Scope

- Introspection: enabled in production? reveals schema, mutations, internal types
- Field-level authorization: each field resolver must enforce its own authz independently
- Query depth/complexity: unbounded nested queries → DoS
- Batching: multiple queries in one request bypass rate limiting
- Subscription / websocket: authentication persists across reconnects?
- Input type validation: mass-assignment via input objects, injection via string inputs

## Methodology

1. `get_architecture()` to identify GraphQL library (Apollo, Strawberry, graphene, graphql-java).
2. Search for the schema definition and resolver map.
3. Introspection check:
   - `grep(pattern="introspection|INTROSPECTION_DISABLED|disableIntrospection")`
   - Read server config to confirm setting applies in production environment.
4. For each resolver returning sensitive data (user data, financials, admin info):
   a. Read the resolver function.
   b. Check: is `ctx.user` or equivalent checked before data is returned?
   c. Check: is tenant scoping applied (not just object ownership)?
   d. Cross-reference with `model-authorization` skill findings.
5. Depth/complexity:
   - `grep(pattern="maxDepth|depthLimit|complexityLimit|queryComplexity")`
   - If absent, create a finding.
6. Batching: check if the server accepts an array of queries in one request.

## Required proof_obligations

- `reachability`: is the GraphQL endpoint publicly accessible (no prior auth)?
- `input_control`: can the attacker craft the query to trigger the issue?
- `guard`: is there no per-field authz check or depth limiter?
- `impact`: what data is exposed or what action can be performed without authorization?

## anchor_text requirement

Point to the resolver function line where the authz check is absent, or to the config line where a security setting is missing.

Call `reject_hypothesis` with `rejection_condition` when a global middleware enforces authz uniformly.
Call `finish()` when complete.
