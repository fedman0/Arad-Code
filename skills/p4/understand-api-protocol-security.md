---
parallel: true
requires: [web, multiservice]
---

# SKILL: understand-api-protocol-security

## Goal

Determine which API protocol(s) this application exposes (REST, GraphQL, gRPC, WebSocket,
JSON-RPC, XML-RPC, SOAP, or others). Read the implementation of each protocol layer completely.
Find security issues that are unique to each protocol's model — issues that REST-focused
skills will not catch.

This skill is language-agnostic. Every pattern described here applies regardless of
which library implements the protocol.

---

## Step 0 — Identify all protocols in use

Use `get_architecture` and `list_dir` to find which protocols are exposed.
Look for:
- GraphQL: schema files (`*.graphql`, `*.gql`), resolver directories, schema builder code
- gRPC: `.proto` files, generated stub directories, server registration code
- WebSocket: upgrade handlers, `ws://` or `wss://` connection setup, message dispatch code
- JSON-RPC: endpoint registered to handle `method` + `params` + `id` payloads
- XML-RPC / SOAP: WSDL files, SOAP envelope handlers
- REST: the baseline — covered by other skills; note version prefixes (`/v1/`, `/v2/`)

For each protocol found: complete the corresponding phase below.

---

## Phase 1 — GraphQL

### 1.1 Schema exposure
- Is introspection enabled in production?
  Introspection allows any client to enumerate every type, field, and directive in the schema —
  including deprecated or internal fields. It should be disabled outside development.
- Is schema-level documentation (descriptions) included in production builds?
  These often reveal internal system names, business logic, and data model details.

### 1.2 Query resource controls
Read the GraphQL server configuration and middleware. For each:

**Query depth limit:**
- Is there a maximum nesting depth enforced?
- Without it: a client sends `{ a { a { a { a { ... } } } } }` to exponential depth, causing
  recursive database joins or object traversals.

**Query complexity limit:**
- Is there a complexity budget per query?
- Without it: requesting thousands of fields or items in one query exhausts database and memory.

**Query timeout:**
- Is there a timeout on query execution?

**Batching:**
- Does the server accept batched requests (array of operations in one HTTP request)?
- If yes: can a client send 500 mutations in one request to bypass rate limiting?

**Aliases:**
- GraphQL aliases allow the same field to be requested multiple times under different names:
  `{ a1: login(user:"x",pass:"p1") a2: login(user:"x",pass:"p2") ... }`
- Does the rate limiter count by HTTP request, or by individual field resolution?
  If by request: aliases bypass it.

### 1.3 Field-level authorization
**This is the most common and critical GraphQL vulnerability.**
- Root-level auth (the top resolver checks auth) does NOT protect nested fields.
- Each resolver/field that returns sensitive data must independently verify authorization.
- Read the resolver implementation for each type that handles sensitive data.
- Ask: if an authenticated user requests this field on someone else's object, does the
  resolver check ownership — or does it return the data if any user is authenticated?
- Find resolvers that fetch by ID without verifying the requesting user owns that ID.

### 1.4 Mutations over GET
- Does the server accept GraphQL queries over HTTP GET?
- GET requests can be triggered cross-origin without preflight (no CORS protection).
- If mutations are allowed over GET: CSRF is possible regardless of CORS policy.

### 1.5 Subscription security (WebSocket)
- GraphQL subscriptions use WebSocket. Apply all WebSocket checks (Phase 3) to the
  subscription connection.
- Is auth checked when a subscription is established? Or only on the initial HTTP upgrade?
- Can a user subscribe to events for another user's resources?

### 1.6 Error exposure
- Do GraphQL errors include stack traces, internal paths, or database error messages?
- Read the error handler/formatter — what fields are included in error responses?

---

## Phase 2 — gRPC

### 2.1 TLS enforcement
- Is TLS required for all gRPC connections?
  gRPC can operate in plaintext mode (`grpc.Dial(addr, grpc.WithInsecure())`).
  Find the server and client setup — is TLS explicitly configured and required?
- In any language: look for "insecure" or "no TLS" options in the connection setup.

### 2.2 Authentication model
gRPC has two levels of credentials:
- **Channel credentials**: applied to the connection (TLS client certificates, token at connect time)
- **Call credentials**: metadata attached to each RPC call (per-call auth tokens)

Find how authentication is implemented:
- Is it a per-call interceptor (runs on every RPC call)? Read its implementation.
- Or is it only at connection time? Connection-time auth does not re-verify on each call;
  a connection held open after a token expires may still execute RPCs.
- For streaming RPCs: is auth checked once at stream open, or per-message?

### 2.3 Authorization per RPC method
- Find the server-side interceptor (or equivalent: middleware, filter, decorator).
- Does it apply to EVERY RPC method, or only some?
- Are any methods explicitly excluded from auth enforcement?
- Is authorization (what the authenticated identity can do) enforced inside each handler,
  or only by the interceptor?
- Read each handler for sensitive operations: does it verify the caller has access to
  the specific resource, or only that they are authenticated?

### 2.4 gRPC reflection
- Is the gRPC reflection service registered on the production server?
  Reflection allows any client to enumerate all services, methods, and message schemas —
  the equivalent of GraphQL introspection.
- In Go: `reflection.Register(server)`
- In Java: `ProtoReflectionService`
- In Python: `reflection.enable_server_reflection`
- In .NET: `app.MapGrpcReflectionService()`
- Should be disabled in production.

### 2.5 Deadline enforcement
- gRPC calls can run indefinitely unless a deadline is set.
  Find whether the server enforces maximum call duration.
  An attacker opening many long-running streams (especially bidirectional streaming) can
  exhaust server resources.

### 2.6 Input validation
- Proto3 fields have no required/optional at the wire level — all fields are optional,
  missing fields get zero values.
- Does the application validate that required business fields are present and within range
  before processing?
- Is there validation middleware, or does each handler validate its own inputs?

### 2.7 Error detail exposure
- gRPC status details (`google.rpc.Status` with `details`) can carry structured error info.
- Read the error handling — do error details include internal paths, database messages,
  or stack traces?

---

## Phase 3 — WebSocket

### 3.1 Authentication at connection time
- Find the HTTP upgrade handler (the endpoint that accepts WebSocket connections).
- Is the user authenticated before the upgrade is accepted?
- Read the exact check: is the session/token validated from the handshake request?
- If auth is skipped or lenient during upgrade: an unauthenticated attacker can open a
  WebSocket connection.

### 3.2 Origin validation
- Unlike CORS for HTTP requests, browsers do NOT enforce same-origin policy for WebSocket.
  Any page on any origin can open a WebSocket connection.
- Does the server check the `Origin` header on the upgrade request?
- Is the check an exact allowlist, or is it prefix/pattern-based (bypassable)?
- A WebSocket without Origin validation + cookie auth = CSRF over WebSocket.

### 3.3 Message-level authorization
- After connection: does the server validate that each incoming message is authorized?
- Can an authenticated user send a message type intended only for admins?
- Can a user subscribe to or receive messages for another user's data?
- Read the message dispatch logic — what happens with each message type?

### 3.4 Input validation per message
- Each message received over WebSocket is untrusted input.
- Are message payloads validated (schema, type, size) before processing?
- Is there a maximum message size enforced? (no limit = memory exhaustion)

### 3.5 Connection limits and rate limiting
- Is there a maximum number of concurrent connections per user or per IP?
- Is there per-connection or per-message rate limiting?

---

## Phase 4 — REST API versioning

- Find all active API versions (`/v1/`, `/v2/`, `/api/v3/`, etc.).
- Older versions are often less maintained and carry security regressions.
- For each version: do the same authentication and authorization checks apply?
  Are older versions more permissive?
- Are deprecated endpoints still reachable? What do they expose?
- Is there a version that exposes more fields or skips validation that current versions do not?

---

## Phase 5 — JSON-RPC / XML-RPC / SOAP

If the application exposes any of these protocols:

- Is the endpoint authenticated? Read the handler.
- Can a caller enumerate available methods?
- Is each method independently authorized?
- For SOAP: is the WSDL exposed publicly? It reveals the full API surface.
- For XML-RPC: are XML payloads processed with XXE protection? (apply the XML parsing checks in understand-data-flows Phase 2)
- For batch/multicall patterns: can a client execute many operations in one request to bypass
  rate limiting?

---

## What to produce

A hypothesis for each:
- **GraphQL**: introspection enabled in production
- **GraphQL**: no depth/complexity/timeout limit → resource exhaustion
- **GraphQL**: field-level authorization missing — authenticated user can read another user's data
- **GraphQL**: mutations accepted over GET → CSRF
- **GraphQL**: alias-based rate limit bypass
- **gRPC**: plaintext connections allowed (no TLS enforcement)
- **gRPC**: auth interceptor not applied to all RPC methods
- **gRPC**: reflection service enabled in production
- **gRPC**: streaming RPC with no deadline → resource exhaustion
- **WebSocket**: no authentication check on upgrade
- **WebSocket**: no Origin validation → CSRF over WebSocket
- **WebSocket**: message dispatch without per-message authorization
- **REST versioning**: older API version with weaker security still reachable

Set `cwe` on each hypothesis (e.g. CWE-200 introspection or reflection exposure, CWE-770 missing
depth/complexity/deadline limits, CWE-862 or CWE-639 missing field, method or message authorization,
CWE-306 unauthenticated upgrade or RPC, CWE-352 mutations over GET, CWE-1385 WebSocket without Origin
validation, CWE-319 plaintext gRPC, CWE-307 alias-based brute force).

## Forbidden

- Do not assume a protocol is not used without reading the routing and architecture
- Do not report GraphQL field-level auth issues without reading the actual resolver code
- Do not report gRPC reflection as a finding without verifying it is registered in the server setup
- Do not skip older API versions — they are often the path of least resistance
