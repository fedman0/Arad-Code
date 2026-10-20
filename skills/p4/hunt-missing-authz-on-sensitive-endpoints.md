# SKILL: hunt-missing-authz-on-sensitive-endpoints

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

**grep = CANDIDATES only.** Never submit from a grep match alone.

---

## FLOW VERIFICATION PROTOCOL — run for every candidate before submitting

For each grep match:

**a.** `get_code_snippet("containing_function_or_class")` — read the full route handler AND any middleware chain.

**b.** Determine authorization coverage for this endpoint:
- Framework-level auth middleware applied globally (e.g. `@app.before_request` → `require_login()`) — check if the endpoint is excluded → **may be OK**
- Route-level decorator (`@login_required`, `@auth.login_required`, `@PreAuthorize(...)`) → **SKIP**
- No auth decorator AND not covered by middleware → **CONTINUE**

**c.** For IDOR specifically: check whether object retrieval uses the authenticated user's ID:
- `Object.query.filter_by(id=id, owner=current_user.id)` — scoped to user → **SKIP**
- `Object.query.filter_by(id=id)` — not scoped → **SUBMIT** (IDOR)

**d.** For mass assignment: does the framework bind all request fields to the model including sensitive ones (admin, role, owner_id)?
- Explicit field allowlist (`fields=["name", "email"]`) → **SKIP**
- Bind-all without exclusion → **SUBMIT**

**Submit only when confirmed**: name the route, the missing auth decorator/middleware, and the impact (e.g. `DELETE /api/posts/<id> in delete_post() has no @login_required — any anonymous caller can delete any post`).

---

---

## Step 1 — FastAPI routes missing auth dependency

```
grep(pattern="@\w*(app|router)\.(get|post|put|patch|delete)\s*\(\s*['\"][^'\"]*['\"]", max_matches=40)
```

For each route on sensitive paths (account, admin, user, order, payment, profile, transfer): does the handler signature lack `Depends(get_current_user)`, `Security(...)`, `HTTPBearer()`, or `OAuth2PasswordBearer`? Router-level dependencies (`APIRouter(dependencies=[Depends(...)])`, `app.include_router(router, dependencies=[...])`) cover every route on that router — check them before submitting.

```
async def endpoint():               # no dependency injection — unauthed
async def endpoint(request: Request): # no user dep — unauthed
async def endpoint(db: Session = Depends(get_db)):  # DB only, no auth
```

→ Submit: violated_invariant="FastAPI endpoint [path] has no authentication dependency; unauthenticated callers access sensitive functionality", severity=9, confidence=7, exposure="internet", cwe="CWE-306"

---

## Step 2 — Express / Node routes without auth middleware

```
grep(pattern="\b\w*(app|router|Router)\.(get|post|put|patch|delete|all)\s*\(\s*['\"][^'\"]*['\"]\s*,\s*(async\s+)?(\(|function\b|\w+\s*\))", max_matches=40)
```

This grep returns routes whose handler directly follows the path (no middleware argument). For each sensitive route: is there a middleware argument between the path and the handler, or an earlier `app.use(auth)` / `router.use(auth)` that covers it? Look for `passport.authenticate`, `authenticate`, `requireAuth`, `isAuthenticated`, `jwtMiddleware`, `verifyToken`.

```
app.get('/admin', handler)                          # no middleware
app.delete('/user/:id', deleteUser)                 # no middleware
router.post('/transfer', async (req, res) => {      # no middleware
```

→ Submit: violated_invariant="Express route [path] has no authentication middleware; requests execute handler without identity verification", severity=9, confidence=7, exposure="internet", cwe="CWE-306"

---

## Step 3 — Spring controllers missing authorization annotations

```
grep(pattern="@(Get|Post|Put|Delete|Patch|Request)Mapping\b", max_matches=40)
```

For each sensitive mapping: is there `@PreAuthorize`, `@Secured`, `@RolesAllowed`, or a method-level security annotation on the method or class?

```
grep(pattern="@PreAuthorize|@PostAuthorize|@Secured|@RolesAllowed|authorizeHttpRequests|authorizeRequests|\.(requestMatchers|antMatchers|mvcMatchers)\s*\(.*\)\s*\.(permitAll|authenticated|hasRole|hasAnyRole|hasAuthority)", max_matches=30)
```

`@WithMockUser` is a test annotation and never counts as authorization; `@PreAuthorize("permitAll()")` is no check at all. A global `SecurityFilterChain` rule (`requestMatchers("/api/**").authenticated()`) does cover matching endpoints — check it before submitting.

→ Submit: violated_invariant="Spring controller method [method] has no method-level security annotation; Spring Security config may not cover this endpoint", severity=8, confidence=6, exposure="internet", cwe="CWE-862"

---

## Step 4 — Django views missing authentication

```
grep(pattern="def\s+\w+\s*\(\s*request\b|class\s+\w+\s*\(.*\b(View|APIView|GenericAPIView|ViewSet|ModelViewSet)\b", max_matches=40)
```

For each view handling sensitive operations: is there `@login_required`, `@permission_required`, `LoginRequiredMixin`, `PermissionRequiredMixin`, or a manual `request.user.is_authenticated` check?

```
grep(pattern="@login_required|@permission_required|LoginRequiredMixin|PermissionRequiredMixin|is_authenticated|permission_classes\s*=|DEFAULT_PERMISSION_CLASSES", max_matches=30)
```

Django REST framework defaults to `AllowAny` unless `DEFAULT_PERMISSION_CLASSES` is set — a view/ViewSet without `permission_classes` under that default is unauthenticated.

→ Submit: violated_invariant="Django view [view] has no authentication decorator or mixin; any HTTP client accesses sensitive data", severity=9, confidence=7, exposure="internet", cwe="CWE-306"

---

## Step 5 — Rails controllers missing before_action auth filter

```
grep(pattern="class\s+\w+Controller\s*<", max_matches=30)
```

For each controller: does it define or inherit `before_action :authenticate_user!` / `before_action :require_login` / `before_action :authorize!`? Check for `skip_before_action :authenticate_user!` that removes inherited protection.

```
grep(pattern="skip_before_action\s*:(authenticate|require_login|require_user|authorize|logged_in|ensure_logged_in)\w*!?|before_action.*only.*\[\s*\]", max_matches=20)
```

→ Submit: violated_invariant="Rails controller [controller] skips authentication filter for [actions]; unauthenticated access to sensitive endpoints", severity=9, confidence=7, exposure="internet", cwe="CWE-306"

---

## Step 6 — C# actions with [AllowAnonymous] on sensitive paths

```
grep(pattern="\[AllowAnonymous\]", max_matches=20)
```

For each `[AllowAnonymous]` attribute: what does the next method name indicate? `Delete`, `Update`, `Admin`, `Transfer`, `Reset` + AllowAnonymous = critical.

```
grep(pattern="\[AllowAnonymous\]\s*\n(\s*\[[^\]\n]*\]\s*\n)*\s*public[^\n(]*\b(Delete|Admin|Transfer|Reset|Update|Create)\w*\s*\(", multiline=true, max_matches=15)
```

→ Submit: violated_invariant="ASP.NET action [action] marked [AllowAnonymous]; bypasses controller-level [Authorize] for sensitive operation", severity=9, confidence=8, exposure="internet", cwe="CWE-306"

---

## Step 7 — PHP Laravel routes missing auth middleware

```
grep(pattern="Route::(get|post|put|patch|delete|any|match|resource|apiResource)\s*\(\s*['\"][^'\"]*['\"]", max_matches=40)
```

For each route: is it inside a `Route::middleware(['auth'])` group, or does it have `->middleware('auth')` chained?

```
grep(pattern="middleware\s*\(\s*\[?[^)]*['\"]auth(:[\w,]+)?['\"]", max_matches=20)
```

→ Submit: violated_invariant="Laravel route [path] not in auth middleware group; unauthenticated requests reach the controller", severity=9, confidence=7, exposure="internet", cwe="CWE-306"

---

## Step 8 — Go Gin routes outside auth middleware group

```
grep(pattern="\b\w+\.(GET|POST|PUT|PATCH|DELETE)\s*\(\s*\"[^\"]*\"", max_matches=40)
```

For each route: is it defined inside a `r.Group(...)` that applies a JWT/auth middleware, or directly on the root router with no middleware?

```
grep(pattern="\w+\.Group\s*\(\s*\"[^\"]*\"|gin\.New\s*\(\s*\)|\w+\.Use\s*\(.*(?i:auth|jwt|token|session)", max_matches=20)
```

→ Submit: violated_invariant="Gin route [path] registered on router without auth middleware group; JWT not validated", severity=9, confidence=6, exposure="internet", cwe="CWE-306"

---

## Step 9 — IDOR: object lookup by user-supplied ID without ownership check

**Python (Django ORM):**
```
grep(pattern="get_object_or_404\s*\(\w+,\s*pk\s*=|get_object_or_404\s*\(\w+,\s*id\s*=|\.objects\.get\s*\(\s*id\s*=|\.objects\.get\s*\(\s*pk\s*=", max_matches=25)
```

**JavaScript / TypeScript:**
```
grep(pattern="findById\s*\(\s*req\.(params|body|query)|findByPk\s*\(\s*req\.(params|body|query)|findOne\s*\(\s*\{.*req\.(params|body|query)", max_matches=25)
```

**Java:**
```
grep(pattern="findById\s*\(\s*\w+\s*\)|get(Reference)?ById\s*\(\s*\w+\s*\)|findOne\s*\(\s*\w+\s*\)|repository\.find\s*\(\s*\w+\s*\)", max_matches=25)
```

**Go:**
```
grep(pattern="First\s*\(\s*&\w+\s*,\s*[^,)]+\)|Find\s*\(\s*&\w+\s*,\s*[^,)]+\)|Where\s*\(\s*['\"]id\s*=\s*\?['\"]\s*,\s*[^)]+\)", max_matches=25)
```

**Ruby:**
```
grep(pattern="find\s*\(\s*params\[|find_by_id\s*\(\s*params\[|find_by\s*\(\s*id:\s*params\[|where\s*\(\s*id:\s*params\[", max_matches=25)
```

**PHP:**
```
grep(pattern="(find|findOrFail)\s*\(\s*\$(request->|id\b)|where\s*\(\s*['\"]id['\"]\s*,\s*\$(request->|id\b)", max_matches=25)
```

For each match: does the code verify `result.user_id == current_user.id` or equivalent before returning? IDOR confirmed if the caller's identity is never compared to the fetched record's owner.

→ Submit: violated_invariant="Object [model] fetched by caller-supplied ID without ownership check; IDOR exposes any record to any authenticated user", severity=8, confidence=7, exposure="authenticated", cwe="CWE-639"

---

## Step 10 — Mass assignment (no attribute whitelist)

**Ruby (Rails):**
```
grep(pattern="\.permit!|to_unsafe_h|update_attributes\s*\(\s*params\b|update\s*\(\s*params\s*[\)\[]|\.(new|create)\s*\(\s*params\s*[\)\[]", max_matches=15)
```

**Python (Django):**
```
grep(pattern="\*\*request\.(data|POST|GET|json|form|get_json\s*\(\s*\))|\*\*(await\s+)?request\.json\s*\(\s*\)|fields\s*=\s*['\"]__all__['\"]", max_matches=15)
```

**PHP (Laravel):**
```
grep(pattern="->(fill|update|forceFill)\s*\(\s*(\$request->(all|input)|request\(\)->all)\s*\(\s*\)\s*\)|::(create|forceCreate)\s*\(\s*(\$request->(all|input)|request\(\)->all)\s*\(\s*\)\s*\)|\$guarded\s*=\s*\[\s*\]", max_matches=15)
```

For each match: is there a `$guarded`, `$fillable`, `permit(:field1, :field2)`, or explicit field whitelist? (`protected $guarded = [];` makes every column fillable.) Rails ≥ 4 raises `ForbiddenAttributesError` when an unpermitted `params` hash reaches `new`/`create`/`update` — those calls are only vulnerable with `permit!`, `to_unsafe_h`, or a `permit(...)` list that includes sensitive fields.

→ Submit: violated_invariant="Mass assignment with no attribute whitelist; caller sets any model field including [role/is_admin/balance]", severity=8, confidence=7, exposure="authenticated", cwe="CWE-915"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
