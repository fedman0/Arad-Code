# SKILL: hunt-nosql-spel-crlf

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns (p_expressjs, p_golang, p_java, p_findsecbugs, p_kotlin)

**grep = CANDIDATES only.** Follow flow to confirm before submitting.

---

## FLOW VERIFICATION PROTOCOL — run for every candidate before submitting

For each grep match:

**a.** `get_code_snippet("containing_function")` — read the full enclosing function.

**b.** Identify the variable fed to the dangerous call and trace its origin:
- Constant / config / server-internal → **SKIP**
- HTTP request: body / query / path / header / cookie → **CONTINUE**
- Unclear → `trace_path("function_name", mode="data_flow")` upstream

**c.** Check for sanitization:
- MongoDB operator injection: typed schema validation (`mongooseSchema.strict`) or manual `$`-prefix strip → **SKIP**
- SpEL: no user data in expression string → **SKIP**; user data present → **SUBMIT immediately** (SpEL = RCE)
- CRLF: `\r` / `\n` stripped from header value → **SKIP**

**Submit only when confirmed**: name function, variable, source, and missing guard.

---

# Part A — NoSQL Injection (MongoDB operator injection)

## Step 1 — MongoDB operator injection: JavaScript / TypeScript (Express / Koa)

**Direct user object passed to find/findOne (allows $gt/$regex/$where):**
```
grep(pattern="\.find\s*\(\s*req\.(body|query|params)\b|\.findOne\s*\(\s*req\.(body|query|params)\b|\.findById\s*\(\s*req\.(body|query|params)\b", max_matches=20)
```

```
grep(pattern="collection\.find\s*\(\s*\{[^}]*req\.(body|query)\[|db\.\w+\.find\s*\(\s*\{[^}]*req\.(body|query)\[", max_matches=20)
```

**Verify**: is the entire `req.body`/`req.query` object passed as the MongoDB query filter? If so, an attacker sends `{"password": {"$gt": ""}}` to bypass authentication. Look for:
- `User.findOne({ username: req.body.username, password: req.body.password })` — if `req.body.password` is `{"$gt":""}`, login bypassed
- Explicit type check (`typeof req.body.password !== "string"`) → **SKIP**
- Mongoose strict schema validation → **SKIP** (but verify `strict` not set to false)

→ Submit: violated_invariant="MongoDB query filter receives untyped user object; operator injection via {\"$gt\":\"\"} or {\"$regex\":\".*\"} bypasses authentication or returns all records", severity=9, confidence=9, exposure="internet"

---

## Step 2 — MongoDB operator injection: Python (pymongo — Django / Flask / FastAPI)

```
grep(pattern="collection\.find\s*\(\s*\{[^}]*request\.(args|form|json|GET|POST)|db\.\w+\.find_one\s*\(\s*\{[^}]*request\.", max_matches=20)
```

```
grep(pattern="\.find\s*\(\s*\{[^}]*\$where[^}]*request\.|aggregate\s*\(\s*\[\s*\{[^}]*\$where[^}]*request\.", max_matches=15)
```

**Verify**: does any MongoDB operator key (starting with `$`) in the query filter come from user input? If the request body is parsed as JSON and merged directly into the query, operator injection is possible.

→ Submit: violated_invariant="pymongo query filter receives user JSON without type checking; {\"$where\":\"sleep(3000)\"} causes DoS, {\"$gt\":\"\"} bypasses auth", severity=9, confidence=8, exposure="internet"

---

## Step 3 — MongoDB operator injection: Go (gin / net/http / gorilla)

The first grep already requires user input in the bson.M literal — use only that:
```
grep(pattern="bson\.M\{[^}]*r\.(URL\.Query\(\)\.Get|FormValue|PostForm)\s*\(|bson\.D\{[^}]*r\.(URL\.Query\(\)\.Get|FormValue)", max_matches=20)
```

For each match: `get_code_snippet("containing_handler_function")` to read the full query construction.

**Verify**:
1. The `bson.M{}` value is assigned directly from `r.URL.Query().Get(...)` / `r.FormValue(...)` / decoded JSON body — not sanitized into a typed primitive first.
2. No operator-key filter: `strings.HasPrefix(value, "$")` → **SKIP**; `reflect.TypeOf(value) == reflect.String` typed assertion → **SKIP**.
3. If the filter is built via `bson.M{"username": username}` where `username` is a `string` from a typed struct → **SKIP** (Go's type system prevents operator injection). Only flag if the value can be `interface{}` or `map[string]interface{}`.

→ Submit: violated_invariant="Go MongoDB filter uses untyped user value (interface{}) in bson.M without operator key check; {\"$gt\":\"\"} bypasses authentication", severity=9, confidence=7, exposure="internet"

---

## Step 4 — MongoDB operator injection: Rust (actix / hyper / rocket)

The dangerous case is untyped JSON deserialized to `serde_json::Value` used in a filter — grep for that specifically:
```
grep(pattern="serde_json::Value|Value::Object\s*\(|from_value\s*\(.*body|from_value\s*\(.*payload", max_matches=20)
```

```
grep(pattern="collection\.find\s*\(\s*doc!\s*\{|collection\.find_one\s*\(\s*doc!\s*\{|collection\.find_one\s*\(\s*\w+\s*,", max_matches=15)
```

For each MongoDB call: `get_code_snippet("containing_function")` and check the filter argument type:
- `doc!{"username": username}` where `username: String` (typed) → **SKIP** (Rust type system prevents injection)
- `bson::to_bson(&user_input)?` where `user_input: serde_json::Value` (untyped, from JSON body) → **CONTINUE**
- `bson::Document` built from user-supplied `HashMap<String, Value>` → **CONTINUE**

Does the `serde_json::Value` come from `web::Json::<serde_json::Value>` or `body.get("filter")` without a typed struct? → **SUBMIT**.

→ Submit: violated_invariant="Rust MongoDB filter uses serde_json::Value from request body without typed deserialization; attacker injects {\"$gt\":\"\"} operator to bypass authentication", severity=9, confidence=7, exposure="internet"

---

## Step 5 — NoSQL injection: AWS DynamoDB filter expressions

```
grep(pattern="FilterExpression\s*=\s*['\"].*\+|FilterExpression\s*=\s*f['\"].*\{|KeyConditionExpression\s*=\s*['\"].*\+", max_matches=15)
```

For each match: `get_code_snippet("containing_function")` to identify what's being concatenated into the expression string.

**Verify**:
- Is the concatenated variable from `event["queryStringParameters"]`, `request.args`, `body.get(...)`, or another HTTP input source? → **CONTINUE**
- Is it an application-internal constant (e.g. a fixed attribute name like `"#status = :s"` with only the value parameterized via `ExpressionAttributeValues`)? → **SKIP**
- DynamoDB parameterization pattern (safe): `FilterExpression="#attr = :val"` with `ExpressionAttributeValues={":val": user_input}` — attribute names and operators are hardcoded, only values are user-controlled → **SKIP**
- Dangerous: `FilterExpression="attribute_name = " + user_input` where `user_input` is the entire expression tail → **SUBMIT**

→ Submit: violated_invariant="DynamoDB FilterExpression assembled with user-supplied string; attacker injects OR/AND conditions to bypass filters and return unauthorized records", severity=8, confidence=7, exposure="internet"

---

# Part B — Spring Expression Language (SpEL) Injection

## Step 6 — SpEL injection: Java Spring

```
grep(pattern="parser\.parseExpression\s*\(\s*\w+\s*\)|expressionParser\.parseExpression\s*\(\s*\w+\s*\)|new SpelExpressionParser\s*\(\s*\)\.parseExpression\s*\(\s*\w+\s*\)", max_matches=20)
```

For each match: `get_code_snippet("containing_method")` to read the full method. Identify the variable `\w+` passed to `parseExpression()`.

**Verify** — trace the variable's origin:
- Declared as a compile-time constant: `private static final String EXPR = "user.age > 18"` → **SKIP**
- Loaded from a properties file / application config at startup (not per-request) → **SKIP**
- Assigned from HTTP request: `@RequestParam String expr`, `request.getParameter("filter")`, `@PathVariable` → **SUBMIT immediately** (SpEL = RCE, no further verification needed once user input confirmed)
- Unclear: `trace_path("method_name", mode="data_flow")` to follow the variable's assignment chain upstream

→ Submit: violated_invariant="Spring SpEL parseExpression() receives user-controlled string; attacker evaluates T(java.lang.Runtime).exec() for immediate RCE on the server", severity=10, confidence=9, exposure="internet"

---

## Step 7 — SpEL injection: Kotlin Spring

```
grep(pattern="SpelExpressionParser\s*\(\s*\)\.parseExpression\s*\(\s*\w+\s*\)|ExpressionParser\s*\(\s*\)\.parseExpression\s*\(\s*\w+\s*\)", max_matches=20)
```

For each match: `get_code_snippet("containing_fun")` — read the full Kotlin function. Identify the variable passed to `parseExpression()`.

**Verify**: same origin-tracing as Step 6 — is the variable a constant/config, or does it come from a request parameter (`@RequestParam`, `@PathVariable`, request body)? If unclear, `trace_path("fun_name", mode="data_flow")` upstream. User-controlled SpEL = RCE with no further verification needed.

→ Submit: violated_invariant="Kotlin Spring SpEL parseExpression receives user-controlled string; RCE via T(java.lang.Runtime).exec()", severity=10, confidence=9, exposure="internet"

---

## Step 8 — EL injection: Java (JSP EL / JEXL / MVEL / OGNL)

**JEXL:**
```
grep(pattern="JexlEngine\s*\(\s*\)\.createExpression\s*\(\s*\w+\s*\)|new JexlBuilder\s*\(\s*\).*create\s*\(\s*\).*createExpression\s*\(\s*\w+\s*\)", max_matches=15)
```

**MVEL:**
```
grep(pattern="MVEL\.eval\s*\(\s*\w+\s*[,)]|MVEL\.compileExpression\s*\(\s*\w+\s*\)|MVEL\.executeExpression\s*\(", max_matches=15)
```

**OGNL (Struts / MyBatis):**
```
grep(pattern="Ognl\.getValue\s*\(\s*\w+\s*[,)]|Ognl\.parseExpression\s*\(\s*\w+\s*\)", max_matches=15)
```

**Script engine (javax.script):**
```
grep(pattern="ScriptEngine.*eval\s*\(\s*\w+\s*\)|engine\.eval\s*\(\s*\w+\s*\)", max_matches=15)
```

For each match: `get_code_snippet("containing_method")` — read the full method. Identify the variable/argument passed to `eval()` / `createExpression()` / `getValue()`.

**Verify**: trace the argument's origin:
- Fixed string literal or class-level constant → **SKIP**
- Template loaded from a classpath resource at startup → **SKIP**
- Assigned from HTTP input (`request.getParameter(...)`, `@RequestParam`, `@RequestBody` field) → **SUBMIT immediately**
- Unclear → `trace_path("method", mode="data_flow")` to follow the assignment chain

→ Submit: violated_invariant="Java expression engine (JEXL/MVEL/OGNL/ScriptEngine) evaluates user-supplied expression string; RCE via reflection gadgets available in the expression language runtime", severity=10, confidence=9, exposure="internet"

---

# Part C — CRLF Injection / HTTP Response Splitting

## Step 9 — CRLF injection: Java (Servlet / Spring)

```
grep(pattern="response\.setHeader\s*\(\s*['\"][^'\"]+['\"],\s*\w+\s*\)|response\.addHeader\s*\(\s*['\"][^'\"]+['\"],\s*\w+\s*\)", max_matches=20)
```

```
grep(pattern="response\.sendRedirect\s*\(\s*\w+\s*\)", max_matches=20)
```

For each match: `get_code_snippet("containing_method")` to identify the variable `\w+` being set as the header value or redirect URL.

**Verify** — trace the variable's origin:
- Hardcoded string, comes from a DB query result (not user-controlled), or comes from server-internal logic → **SKIP**
- Assigned from `request.getParameter(...)`, `request.getHeader(...)`, `@RequestParam`, path variable → **CONTINUE**
- Has `\r` / `\n` strip: `value.replaceAll("[\r\n]", "")` → **SKIP**
- No strip, user input flows directly → **SUBMIT**

If unclear, `trace_path("method", mode="data_flow")` to follow the variable upstream.

→ Submit: violated_invariant="HTTP response header value flows from request.getParameter() without CRLF stripping; HTTP response splitting injects arbitrary headers and body content", severity=7, confidence=8, exposure="internet"

---

## Step 10 — CRLF injection: log injection (Java / Kotlin / Scala)

```
grep(pattern="log\.(info|debug|warn|error)\s*\(\s*['\"].*\+\s*\w+|logger\.(info|debug|warn|error)\s*\(\s*['\"].*\+\s*\w+", max_matches=20)
```

For each match: `get_code_snippet("containing_method")` to identify the variable being concatenated into the log message.

**Verify** — the variable must trace to HTTP user input to be a finding:
- Internal server state, DB result, or fixed constant → **SKIP** (logging internal values is normal)
- `trace_path("method", mode="data_flow")` if origin is unclear — follow the assignment upstream
- Assigned from `request.getParameter(...)`, `@RequestParam`, request header, `@PathVariable`, request body → **CONTINUE**
- No `\r\n` sanitization before the log call → **SUBMIT**

→ Submit: violated_invariant="User input from [source] concatenated into log statement without CRLF sanitization; attacker injects newlines to forge audit log entries and break SIEM parsers", severity=5, confidence=7, exposure="internet"

---

## Step 11 — CRLF injection: Python / Go / Ruby

**Python:**
```
grep(pattern="response\.headers\s*\[.*\]\s*=\s*\w+.*request\.|flask\.Response\s*\(.*headers.*request\.", max_matches=15)
```

**Go:**
```
grep(pattern="w\.Header\(\)\.Set\s*\(\s*['\"][^'\"]+['\"],\s*\w+\s*\)|w\.Header\(\)\.Add\s*\(\s*['\"][^'\"]+['\"],\s*\w+\s*\)", max_matches=15)
```

**Ruby/Rails:**
```
grep(pattern="response\.headers\[['\"][^'\"]+['\"]\]\s*=\s*params\[|headers\[['\"][^'\"]+['\"]\]\s*=\s*params\[", max_matches=15)
```

**Verify**: Go's `net/http` package sanitizes headers in recent versions — check the Go version in go.mod. Python Flask also sanitizes in recent versions. Still flag because old versions or custom HTTP libs may not.

→ Submit: violated_invariant="HTTP response header value set from user input; CRLF injection possible in older framework versions or custom transport layers", severity=6, confidence=7, exposure="internet"

---

## Step 12 — Prototype pollution: JavaScript / TypeScript

**Unsafe object merge / extend / assign with user data:**
```
grep(pattern="Object\.assign\s*\(\s*\w+,\s*req\.(body|query|params)\b|merge\s*\(\s*\w+,\s*req\.(body|query|params)\b|extend\s*\(\s*\w+,\s*req\.(body|query|params)\b", max_matches=20)
```

**Direct property assignment without hasOwnProperty check:**
```
grep(pattern="for\s*\(\s*(const|let|var)\s+\w+\s+in\s+req\.(body|query)\s*\)\s*\{[^}]*\w+\s*\[\s*\w+\s*\]\s*=", max_matches=20)
```

**lodash merge / deepmerge with user input:**
```
grep(pattern="_\.merge\s*\(\s*\w+,\s*req\.(body|query)\b|deepmerge\s*\(\s*\w+,\s*req\.(body|query)\b|\\\$\.extend\s*\(\s*true,\s*\w+,\s*req\.(body|query)\b", max_matches=20)
```

**Verify**: does the merge/assign/extend target an object with `{}` or `new Object()` base? Does the user object contain `__proto__` or `constructor.prototype` keys? A PoC: `req.body = {"__proto__": {"isAdmin": true}}` pollutes `Object.prototype.isAdmin` globally.

→ Submit: violated_invariant="Object.assign / lodash.merge / deepmerge copies user-controlled keys including __proto__/constructor.prototype into target; prototype pollution sets global properties enabling auth bypass or RCE", severity=8, confidence=8, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
