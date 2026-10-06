# SKILL: hunt-privilege-escalation-bola

## Strategy — map first, then trace gaps

This skill has three phases:

**Phase 1 — Role Landscape (recon, no submitting yet)**
Build a complete map: what roles exist, how they're assigned, how they're checked.

**Phase 2 — Assignment Flow Analysis**
For every role assignment path: can a lower-privileged caller reach it?

**Phase 3 — Object-Level Authorization (BOLA)**
For every object fetch by caller-supplied ID: is ownership verified against the caller's identity?

---

## FLOW VERIFICATION PROTOCOL

For each candidate:

**a.** `get_code_snippet("function_or_handler")` — read the full function.

**b.** Identify the authorization check:
- Is the **caller's** role/identity verified (not just the target's)?
- Is the check on every code path, or only on the happy path?

**c.** `trace_path("function", mode="calls")` — follow who calls this function. Can an unauthenticated or low-privilege caller reach it through any route?

**d.** For object access: does the query filter include the caller's user ID?
- `filter_by(id=id, user_id=current_user.id)` → **SKIP**
- `filter_by(id=id)` alone → **SUBMIT** (BOLA)

**Submit only when confirmed**: name the endpoint, the missing check, the caller who can abuse it, and the impact (which role they can reach or whose data they can access).

---

# Phase 1 — Role Landscape Mapping

## Step 1 — Enumerate role/permission definitions

**Python (Django / Flask / FastAPI):**
```
grep(pattern="ROLES\s*=\s*\{|PERMISSIONS\s*=\s*\{|class\s+Role\s*\(|class\s+Permission\s*\(|choices\s*=\s*\[.*admin.*\]|UserRole\.(ADMIN|MODERATOR|STAFF|SUPER)", max_matches=30)
```

**JavaScript / TypeScript:**
```
grep(pattern="enum\s+Role\s*\{|const\s+ROLES\s*=|UserRole\.(ADMIN|MODERATOR|STAFF)|roles:\s*\[['\"]admin['\"]|['\"]superuser['\"]|['\"]moderator['\"]", max_matches=30)
```

**Java / Kotlin / Spring:**
```
grep(pattern="@RolesAllowed\s*\(\s*['\"]ADMIN['\"]|GrantedAuthority|hasRole\s*\(['\"]ADMIN['\"]|hasAuthority\s*\(['\"]|enum\s+Role\s*\{|ROLE_ADMIN|ROLE_STAFF", max_matches=30)
```

**Go:**
```
grep(pattern="const\s+\(\s*\n.*Role|type\s+Role\s+(string|int)|RoleAdmin\s*=|RoleModerator\s*=", max_matches=20)
```

**Ruby / Rails:**
```
grep(pattern="enum\s+role\s*:|ROLES\s*=\s*\[|role\s*=\s*['\"]admin['\"]|has_role\?|can\?\s*:admin", max_matches=20)
```

**PHP / Laravel:**
```
grep(pattern="Gate::define\s*\(|can\s*\(['\"]admin['\"]|\\\$user->hasRole\s*\(|Spatie.*Role|enum.*role.*admin", max_matches=20)
```

→ **Do not submit yet.** Record all roles found: typically `admin`, `moderator`, `staff`, `superuser`, `system`, `internal`, `service`, `god`. These are the escalation targets. Note which roles grant destructive privileges (delete_user, manage_billing, impersonate, etc.).

---

## Step 2 — Find all role-checking middleware / decorators

**Python:**
```
grep(pattern="@require_role\s*\(|@admin_required|@staff_required|@permission_required\s*\(['\"].*admin|def\s+check_role\s*\(|def\s+require_admin\s*\(", max_matches=30)
```

**JavaScript:**
```
grep(pattern="requireRole\s*\(|checkRole\s*\(|hasRole\s*\(|assertRole\s*\(|roleGuard\s*\(|authorize\s*\(\s*['\"]admin", max_matches=30)
```

**Java / Kotlin:**
```
grep(pattern="@PreAuthorize\s*\(['\"]hasRole|@Secured\s*\(\s*['\"]ROLE_ADMIN|SecurityContextHolder.*getAuthentication\s*\(\s*\)\.getAuthorities", max_matches=20)
```

→ **Do not submit yet.** For each check found: note the exact function name. These are the guards you'll verify are ACTUALLY called on the routes you trace in Phase 2.

---

## Step 3 — Find role ASSIGNMENT endpoints (highest value targets)

These are the endpoints that SET or MODIFY a user's role. If any are reachable by lower-privileged callers, that's direct PE.

**Python:**
```
grep(pattern="\.role\s*=\s*|update_role\s*\(|set_role\s*\(|assign_role\s*\(|grant_role\s*\(|promote\s*\(|user\.update\s*\(.*role|serializer.*role", max_matches=25)
```

**JavaScript:**
```
grep(pattern="\.role\s*=\s*|updateRole\s*\(|setRole\s*\(|assignRole\s*\(|grantRole\s*\(|promote\s*\(|user\.update\s*\(.*role|body\.role", max_matches=25)
```

**Java / Kotlin:**
```
grep(pattern="setRole\s*\(|addRole\s*\(|grantAuthority\s*\(|user\.setRoles\s*\(|\.roles\s*=\s*|roleRepository\.save", max_matches=25)
```

**Go:**
```
grep(pattern="user\.Role\s*=\s*|SetRole\s*\(|UpdateRole\s*\(|db\.Model.*Update.*role", max_matches=20)
```

**Ruby:**
```
grep(pattern="user\.update\s*\(\s*role:|user\.role\s*=\s*|assign_role\s*\(|params\s*\[.*:role\]", max_matches=20)
```

**PHP:**
```
grep(pattern="\\\$user->role\s*=|\\\$user->assignRole\s*\(|\\\$user->update\s*\(\s*\[.*role|syncRoles\s*\(", max_matches=20)
```

→ **For each assignment point found:** immediately go to Phase 2 and trace the caller chain.

---

# Phase 2 — Assignment Flow Verification (Privilege Escalation)

## Step 4 — Trace role assignment caller chain

For each role assignment from Step 3:

**a.** `get_code_snippet("function_containing_role_assignment")` — read the full handler.

**b.** Check: is there a caller-role check BEFORE the assignment?
```
# VULNERABLE — no check on who's calling
def update_user(user_id, data):
    user = User.get(user_id)
    user.update(**data)          # if data contains role=admin, PE achieved

# SAFE
@require_role("admin")
def update_user(user_id, data):
    user = User.get(user_id)
    user.update(**data)
```

**c.** If check exists: is it on the **caller** or the **target**? A check that verifies `target.role == admin` is NOT an authorization check — it verifies the target's current state, not the caller's privilege.

**d.** `trace_path("handler_function", mode="calls")` — who calls this? Is there another route (e.g. admin bulk endpoint, webhook, internal API) that bypasses the check?

→ Submit if: role assignment reachable without caller-role verification, or the check is on wrong subject.
violated_invariant="[endpoint] assigns role=[role] without verifying caller has [required_role]; any authenticated user achieves vertical PE to [target_role]", severity=10, confidence=9, exposure="authenticated"

---

## Step 5 — Mass assignment PE (role field not protected)

When user updates their own profile, can they set their own `role` field?

**Python (Django REST / FastAPI):**
```
grep(pattern="class\s+\w+Serializer.*Meta.*fields.*=.*'__all__'|class\s+\w+Serializer.*Meta.*exclude\s*=\s*\[\]|extra_kwargs\s*=\s*\{[^}]*['\"]role['\"].*['\"]read_only['\"]:\s*False", max_matches=20)
```

**JavaScript (Mongoose / Sequelize):**
```
grep(pattern="user\.save\s*\(\s*\)|user\.update\s*\(\s*req\.body\s*\)|updateOne\s*\(\s*\{.*\},\s*req\.body", max_matches=20)
```

**Ruby (Rails strong parameters):**
```
grep(pattern="params\.permit!\s*\(\s*\)|params\.require\s*\(.*\)\.permit\s*\(.*:role", max_matches=15)
```

**Verify**: does the user-update endpoint accept a `role` field from the request body?
- If `role` is in the serializer's writable fields AND the caller sets it on their own account → **SUBMIT** (self-role-assignment PE)
- If `role` is explicitly `read_only=True` or excluded from `fields` → **SKIP**

→ Submit: violated_invariant="User profile update endpoint accepts role field from request body without admin check; any user sets own role to admin via PATCH /api/users/me with {role: 'admin'}", severity=10, confidence=9, exposure="authenticated"

---

## Step 6 — JWT / session role claim tampering flow

Can the role in the token/session be elevated without server-side re-issuance?

**Find where role is embedded in JWT at issuance:**
```
grep(pattern="jwt\.sign\s*\(.*role|jwt\.encode\s*\(.*role|create_access_token\s*\(.*role|claims\[.*role.*\]\s*=", max_matches=20)
```

**Find where role is READ from token (not from DB):**
```
grep(pattern="payload\[['\"]role['\"]|decoded\[['\"]role['\"]|jwt_data\[.*role|current_user\.role\s*=.*payload", max_matches=20)
```

**Verify**: is the role taken directly from the JWT payload WITHOUT re-fetching the user's actual role from the database on each request?

```python
# VULNERABLE: role read from token, not from DB
user_role = jwt_payload["role"]   # attacker forges this if signing is weak

# SAFE: role re-fetched from DB on each request
user = db.get(jwt_payload["user_id"])
user_role = user.role             # DB is authoritative
```

`trace_path` from the JWT decode function to confirm: is `role` value from token used directly, or is it discarded and re-loaded from DB?

→ Submit: violated_invariant="Role claim read directly from JWT payload without DB re-fetch; if signing key is weak/leaked, or if token replay from old admin session, attacker forges role=admin", severity=9, confidence=8, exposure="authenticated"

---

## Step 7 — Tenant/org boundary: cross-tenant role PE

In multi-tenant apps, can a user in Tenant A act as admin in Tenant B?

**Find tenant-scoped role queries:**
```
grep(pattern="org_id|tenant_id|workspace_id|team_id", max_matches=20)
```

For each role check found in Step 2: does it scope by tenant?

```python
# VULNERABLE: checks role but not tenant
if user.role == "admin":   # user is admin in their own org, not this one
    ...

# SAFE: scopes check to current tenant
membership = OrgMember.get(org_id=current_org.id, user_id=current_user.id)
if membership.role == "admin":
    ...
```

`get_code_snippet` for each admin check: is `org_id`/`tenant_id` included in the role lookup?

→ Submit: violated_invariant="Role check uses global user.role without scoping to current tenant; user with admin role in Org A acts as admin in Org B", severity=9, confidence=8, exposure="authenticated"

---

# Phase 3 — BOLA (Broken Object Level Authorization)

## Step 8 — API object fetch without ownership scope (BOLA core)

Any API that fetches an object by a caller-supplied ID must verify the caller owns (or has permission to access) that object.

**Python:**
```
grep(pattern="get_object_or_404\s*\(\w+,\s*(pk|id)\s*=|\.objects\.get\s*\(\s*(pk|id)\s*=|\.objects\.filter\s*\(\s*(pk|id)\s*=\s*\w+\s*\)\s*\.first", max_matches=30)
```

**JavaScript:**
```
grep(pattern="findById\s*\(\s*req\.(params|body|query)\.|findByPk\s*\(\s*req\.(params|body|query)\.|findOne\s*\(\s*\{\s*id\s*:", max_matches=30)
```

**Java / Kotlin:**
```
grep(pattern="findById\s*\(\s*\w+\s*\)|getById\s*\(\s*\w+\s*\)|findOne\s*\(.*id\s*=\s*\w+\s*\)", max_matches=30)
```

**Go (GORM):**
```
grep(pattern="First\s*\(\s*&\w+,\s*\w+\s*\)|Find\s*\(\s*&\w+,\s*['\"]id\s*=\s*\?['\"]|Where\s*\(['\"]id\s*=\s*\?['\"],\s*\w+\s*\)", max_matches=30)
```

**Ruby:**
```
grep(pattern="find\s*\(\s*params\[|find_by\s*\(\s*id:\s*params\[|where\s*\(\s*id:\s*params\[", max_matches=30)
```

**PHP:**
```
grep(pattern="find\s*\(\s*\\\$request->|findOrFail\s*\(\s*\\\$request->|where\s*\(['\"]id['\"],\s*\\\$request->", max_matches=30)
```

**Verify** for each match (the most important step):

`get_code_snippet("containing_function")` and check: after the fetch, is there an ownership comparison?

```python
# VULNERABLE (BOLA):
post = Post.objects.get(id=post_id)       # fetches ANY post
return PostSerializer(post).data           # returns it to whoever asked

# SAFE:
post = Post.objects.get(id=post_id, author=request.user)  # scoped query
# OR:
post = Post.objects.get(id=post_id)
if post.author != request.user:
    raise PermissionDenied
```

Objects that frequently have BOLA: orders, invoices, messages, tickets, medical records, documents, payments, API keys, OAuth tokens, SSH keys. Flag these specifically.

→ Submit: violated_invariant="[Model] fetched by caller-supplied [id_param] without verifying caller is [owner/participant]; any authenticated user accesses any [Model] by enumerating IDs", severity=9, confidence=9, exposure="authenticated"

---

## Step 9 — Admin-scoped objects accessible via regular API

Some objects belong to admins or other users but are exposed through the same API surface.

**Find admin/internal object types:**
```
grep(pattern="is_staff\s*=\s*True|is_superuser|AdminOnly|InternalOnly|system_created|created_by_admin", max_matches=20)
```

For each admin-created object type: is there a separate API endpoint for it, or is it returned by the same generic listing/fetch endpoint that regular users call?

`get_code_snippet` for the list/fetch handler: does the query have `.filter(is_staff=False)` / `.filter(internal=False)` to exclude admin objects?

→ Submit: violated_invariant="Generic [Model] listing/fetch returns admin-created objects to regular users; user reads system config, other users' private data, or admin-only resources", severity=8, confidence=7, exposure="authenticated"

---

## Step 10 — BOLA via indirect reference (relationship traversal)

An object the caller can access legitimately may have a relationship pointer to a restricted object.

**Find nested resource access:**
```
grep(pattern="request\.(params|body|query)\.\w+_id|req\.(params|body|query)\.\w+_id|params\[:\w+_id\]|\\\$request->\w+_id", max_matches=30)
```

For each `*_id` parameter:

`get_code_snippet` — is the referenced object fetched with only its ID, or is the caller's access to that object also verified?

```python
# Example: user can access their order, but order has payment_id
# VULNERABLE: payment fetched by payment_id without checking payment.order.user == caller
payment = Payment.get(id=request.params["payment_id"])
return payment.card_last4, payment.billing_address

# SAFE:
payment = Payment.get(id=request.params["payment_id"])
if payment.order.user != current_user:
    raise Forbidden
```

→ Submit: violated_invariant="Nested resource [ChildModel] fetched by [child_id] param without verifying caller owns parent [ParentModel]; attacker traverses ownership boundary to read [ChildModel] data", severity=8, confidence=7, exposure="authenticated"

---

## Step 11 — Role-based data filter missing (data-level authz gap)

API returns records but doesn't apply role-appropriate filter.

**Python / Django:**
```
grep(pattern="\.objects\.all\s*\(\s*\)|\.objects\.filter\s*\(\s*\)\s*\.order_by|serializer\.data.*request\.user", max_matches=20)
```

**JavaScript:**
```
grep(pattern="find\s*\(\s*\{\s*\}\s*\)|findAll\s*\(\s*\)|\.find\s*\(\s*\{\s*\}\s*\)", max_matches=20)
```

**Verify**: is `Model.objects.all()` (or equivalent "fetch everything") used in an endpoint that regular users call? Should it be filtered to `filter(user=request.user)` or `filter(tenant=current_tenant)`?

→ Submit: violated_invariant="[endpoint] returns all [Model] records with no user-scope filter; any authenticated user enumerates all users'/tenants' [Model] records", severity=8, confidence=8, exposure="authenticated"

---

## Step 12 — PE via account takeover flow (password/email reset without auth)

Can a user reset another user's email or password without being admin?

**Find account update endpoints:**
```
grep(pattern="change_password\s*\(|reset_password\s*\(|update_email\s*\(|change_email\s*\(|\\.email\s*=\s*request\.|password_reset\s*\(", max_matches=20)
```

**Verify**:
1. `get_code_snippet` — does the endpoint require the caller to provide their current password for self-updates?
2. Does the endpoint scope the update to `current_user` only, or does it accept a `user_id` parameter?
3. `trace_path` — is there an admin endpoint that also resets passwords? Is it admin-checked?

```python
# VULNERABLE: accepts user_id from body — attacker resets anyone's password
def reset_password(user_id, new_password):
    user = User.get(user_id)
    user.set_password(new_password)

# SAFE: only resets the caller's own password
def reset_password(new_password):
    current_user.set_password(new_password)
```

→ Submit: violated_invariant="Password/email reset endpoint accepts arbitrary user_id without admin check; any authenticated user takes over any account by resetting their credentials", severity=10, confidence=9, exposure="authenticated"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
