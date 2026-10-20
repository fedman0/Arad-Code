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
- Unclear → `trace_path("function_name", mode="data_flow")` upstream; if still unclear, **submit with confidence=5** (uncertain is not safe)

**c.** Check for sanitization:
- MongoDB operator injection: value forced to a primitive (`typeof x === "string"` check, `String(x)`, explicit `$eq`), `sanitizeFilter: true` / `mongoose.set("sanitizeFilter", true)`, `express-mongo-sanitize` / `mongo-sanitize`, or a manual `$`-key strip → **SKIP**. Mongoose `strict` / `strictQuery` are NOT guards: they drop unknown paths, but a `{"$gt": ""}` object on a known field still reaches the query.
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
grep(pattern="\.(find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments|exists)\s*\(\s*\{[^}]*req\.(body|query)(\.|\[)", max_matches=20)
```

**Verify**: is the entire `req.body`/`req.query` object passed as the MongoDB query filter? If so, an attacker sends `{"password": {"$gt": ""}}` to bypass authentication. Look for:
- `User.findOne({ username: req.body.username, password: req.body.password })` — if `req.body.password` is `{"$gt":""}`, login bypassed
- Explicit type check (`typeof req.body.password !== "string"`) → **SKIP**
- Mongoose `strict` / `strictQuery` schema options → NOT a guard (see protocol step c); `sanitizeFilter` enabled or the value cast to a string → **SKIP**
- `req.params` values are always strings → not operator-injectable; `req.query` (parsed by `qs`, `?password[$ne]=x`) and JSON `req.body` are

→ Submit: violated_invariant="MongoDB query filter receives untyped user object; operator injection via {\"$gt\":\"\"} or {\"$regex\":\".*\"} bypasses authentication or returns all records", severity=9, confidence=9, exposure="internet", cwe="CWE-943"

---

## Step 2 — MongoDB operator injection: Python (pymongo — Django / Flask / FastAPI)

```
grep(pattern="\.(find|find_one|update_one|update_many|delete_one|delete_many|count_documents)\s*\(\s*\{[^}]*request\.(json|get_json|data|args|form|GET|POST)|\.(find|find_one|delete_many|count_documents)\s*\(\s*request\.(json|get_json\s*\(\s*\)|data)", max_matches=20)
```

```
grep(pattern="\.find\s*\(\s*\{[^}]*\$where[^}]*request\.|aggregate\s*\(\s*\[\s*\{[^}]*\$where[^}]*request\.", max_matches=15)
```

**Verify**: does any MongoDB operator key (starting with `$`) in the query filter come from user input? If the request body is parsed as JSON and merged directly into the query, operator injection is possible. Only JSON bodies (`request.json`, `request.get_json()`, DRF `request.data`) can carry operator objects; `request.args` / `request.form` / `request.GET` / `request.POST` values are strings — injectable only when concatenated into a `$where` / `$regex` string.

→ Submit: violated_invariant="pymongo query filter receives user JSON without type checking; {\"$where\":\"sleep(3000)\"} causes DoS, {\"$gt\":\"\"} bypasses auth", severity=9, confidence=8, exposure="internet", cwe="CWE-943"

---

## Step 3 — MongoDB operator injection: Go (gin / net/http / gorilla)

Typed values (`r.URL.Query().Get(...)`, `r.FormValue(...)`, `string` struct fields) cannot carry operators — Go's type system blocks the injection. The dangerous case is a request body decoded into an untyped map (`bson.M`, `map[string]interface{}`, `map[string]any`) or an `interface{}` field that then becomes (part of) a filter:
```
grep(pattern="var\s+\w+\s+(bson\.M|bson\.D|map\[string\]interface\{\}|map\[string\]any)\b|\w+\s*:=\s*(bson\.M|map\[string\]interface\{\}|map\[string\]any)\{\}|\b(interface\{\}|any|bson\.M|map\[string\]interface\{\})\s+.json:\"", max_matches=20)
```

```
grep(pattern="\.(Find|FindOne|FindOneAndUpdate|UpdateOne|UpdateMany|DeleteOne|DeleteMany|CountDocuments)\s*\(\s*\w+\s*,\s*[a-z]\w*\s*[,)]", max_matches=20)
```

For each match: `get_code_snippet("containing_handler_function")` to read the full query construction.

**Verify**:
1. The filter variable is decoded from the request (`json.NewDecoder(r.Body).Decode(&filter)`, `c.ShouldBindJSON(&filter)`, a bound struct with an `interface{}` / `bson.M` field) and reaches `Find` / `FindOne` / `UpdateOne` ... without being rebuilt from typed values.
2. No operator-key filter: rejecting keys with `strings.HasPrefix(key, "$")` → **SKIP**; value type-asserted to `string` → **SKIP**.
3. If the filter is built via `bson.M{"username": username}` where `username` is a `string` from a typed struct → **SKIP** (Go's type system prevents operator injection). Only flag if the value can be `interface{}` or `map[string]interface{}`.

→ Submit: violated_invariant="Go MongoDB filter uses untyped user value (interface{}) in bson.M without operator key check; {\"$gt\":\"\"} bypasses authentication", severity=9, confidence=7, exposure="internet", cwe="CWE-943"

---

## Step 4 — MongoDB operator injection: Rust (actix / hyper / rocket)

The dangerous case is untyped JSON deserialized to `serde_json::Value` used in a filter — grep for that specifically:
```
grep(pattern="serde_json::Value|Value::Object\s*\(|from_value\s*\(.*body|from_value\s*\(.*payload", max_matches=20)
```

```
grep(pattern="coll\w*\.find(_one)?\s*\(\s*(doc!\s*\{|[a-z_]\w*\s*[,)])", max_matches=15)
```

For each MongoDB call: `get_code_snippet("containing_function")` and check the filter argument type:
- `doc!{"username": username}` where `username: String` (typed) → **SKIP** (Rust type system prevents injection)
- `bson::to_bson(&user_input)?` where `user_input: serde_json::Value` (untyped, from JSON body) → **CONTINUE**
- `bson::Document` built from user-supplied `HashMap<String, Value>` → **CONTINUE**

Does the `serde_json::Value` come from `web::Json::<serde_json::Value>` or `body.get("filter")` without a typed struct? → **SUBMIT**.

→ Submit: violated_invariant="Rust MongoDB filter uses serde_json::Value from request body without typed deserialization; attacker injects {\"$gt\":\"\"} operator to bypass authentication", severity=9, confidence=7, exposure="internet", cwe="CWE-943"

---

## Step 5 — NoSQL injection: AWS DynamoDB filter expressions

```
grep(pattern="(Filter|KeyCondition|Condition|Projection)Expression\s*[=:]\s*(f['\"].*\{|['\"].*['\"]\s*\+|\x60[^\x60]*\$\{)", max_matches=15)
```

For each match: `get_code_snippet("containing_function")` to identify what's being concatenated into the expression string.

**Verify**:
- Is the concatenated variable from `event["queryStringParameters"]`, `request.args`, `body.get(...)`, or another HTTP input source? → **CONTINUE**
- Is it an application-internal constant (e.g. a fixed attribute name like `"#status = :s"` with only the value parameterized via `ExpressionAttributeValues`)? → **SKIP**
- DynamoDB parameterization pattern (safe): `FilterExpression="#attr = :val"` with `ExpressionAttributeValues={":val": user_input}` — attribute names and operators are hardcoded, only values are user-controlled → **SKIP**
- Dangerous: `FilterExpression="attribute_name = " + user_input` where `user_input` is the entire expression tail → **SUBMIT**

→ Submit: violated_invariant="DynamoDB FilterExpression assembled with user-supplied string; attacker injects OR/AND conditions to bypass filters and return unauthorized records", severity=8, confidence=7, exposure="internet", cwe="CWE-943"

---

# Part B — Spring Expression Language (SpEL) Injection

## Step 6 — SpEL injection: Java Spring

```
grep(pattern="\.parse(Expression|Raw)\s*\(\s*[^\"\s)]|\.parse(Expression|Raw)\s*\(\s*\"[^\"]*\"\s*\+", max_matches=20)
```

The grep returns calls whose argument is not a plain string literal (a variable, a method call, or a literal concatenated with something). For each match: `get_code_snippet("containing_method")` to read the full method. Identify the expression passed to `parseExpression()`.

**Verify** — trace the variable's origin:
- Declared as a compile-time constant: `private static final String EXPR = "user.age > 18"` → **SKIP**
- Loaded from a properties file / application config at startup (not per-request) → **SKIP**
- Assigned from HTTP request: `@RequestParam String expr`, `request.getParameter("filter")`, `@PathVariable` → **SUBMIT immediately** (SpEL = RCE, no further verification needed once user input confirmed)
- Unclear: `trace_path("method_name", mode="data_flow")` to follow the variable's assignment chain upstream
- Evaluated only with `SimpleEvaluationContext` (e.g. `SimpleEvaluationContext.forReadOnlyDataBinding()`) instead of `StandardEvaluationContext` → `T()` type references and constructors are blocked: report as data exposure at severity 5, not RCE

→ Submit: violated_invariant="Spring SpEL parseExpression() receives user-controlled string; attacker evaluates T(java.lang.Runtime).exec() for immediate RCE on the server", severity=10, confidence=9, exposure="internet", cwe="CWE-917"

---

## Step 7 — SpEL injection: Kotlin Spring

```
grep(pattern="\.parse(Expression|Raw)\s*\(\s*[^\"\s)]|\.parse(Expression|Raw)\s*\(\s*\"[^\"]*(\$\{?[A-Za-z_]|\"\s*\+)", file_glob="*.kt", max_matches=20)
```

This also catches Kotlin string templates (`parseExpression("#{$input}")`). For each match: `get_code_snippet("containing_fun")` — read the full Kotlin function. Identify the variable passed to `parseExpression()`.

**Verify**: same origin-tracing as Step 6 — is the variable a constant/config, or does it come from a request parameter (`@RequestParam`, `@PathVariable`, request body)? If unclear, `trace_path("fun_name", mode="data_flow")` upstream; if still unclear, **submit with confidence=5**. User-controlled SpEL = RCE with no further verification needed.

→ Submit: violated_invariant="Kotlin Spring SpEL parseExpression receives user-controlled string; RCE via T(java.lang.Runtime).exec()", severity=10, confidence=9, exposure="internet", cwe="CWE-917"

---

## Step 8 — EL injection: Java (JSP EL / JEXL / MVEL / OGNL)

**JEXL:**
```
grep(pattern="\.create(Expression|Script)\s*\(\s*[^\"\s)]|new\s+JexlBuilder\s*\(", max_matches=15)
```

**MVEL:**
```
grep(pattern="MVEL\.(eval\w*|compileExpression)\s*\(\s*[^\"\s)]|MVEL\.executeExpression\s*\(", max_matches=15)
```

**OGNL (Struts / MyBatis):**
```
grep(pattern="Ognl\.(getValue|setValue|parseExpression)\s*\(\s*[^\"\s)]", max_matches=15)
```

**Script engine (javax.script):**
```
grep(pattern="[Ee]ngine\w*\.eval\s*\(\s*[^\"\s)]", max_matches=15)
```

For each match: `get_code_snippet("containing_method")` — read the full method. Identify the variable/argument passed to `eval()` / `createExpression()` / `getValue()`.

**Verify**: trace the argument's origin:
- Fixed string literal or class-level constant → **SKIP**
- Template loaded from a classpath resource at startup → **SKIP**
- Assigned from HTTP input (`request.getParameter(...)`, `@RequestParam`, `@RequestBody` field) → **SUBMIT immediately**
- Unclear → `trace_path("method", mode="data_flow")` to follow the assignment chain; if still unclear, **submit with confidence=5**

→ Submit: violated_invariant="Java expression engine (JEXL/MVEL/OGNL/ScriptEngine) evaluates user-supplied expression string; RCE via reflection gadgets available in the expression language runtime", severity=10, confidence=9, exposure="internet", cwe="CWE-917" (use "CWE-94" for ScriptEngine)

---

# Part C — CRLF Injection / HTTP Response Splitting

## Step 9 — CRLF injection: Java (Servlet / Spring)

```
grep(pattern="(response|resp|res)\.(setHeader|addHeader)\s*\(\s*\"[^\"]+\"\s*,\s*[^\"\s)]|new\s+Cookie\s*\(\s*\"[^\"]+\"\s*,\s*[^\"\s)]", max_matches=20)
```

```
grep(pattern="\.sendRedirect\s*\(\s*[^\"\s)]", max_matches=20)
```

For each match: `get_code_snippet("containing_method")` to identify the expression being set as the header value or redirect URL.

**Verify** — trace the variable's origin:
- Hardcoded string, comes from a DB query result (not user-controlled), or comes from server-internal logic → **SKIP**
- Assigned from `request.getParameter(...)`, `request.getHeader(...)`, `@RequestParam`, path variable → **CONTINUE**
- Has `\r` / `\n` strip: `value.replaceAll("[\r\n]", "")` → **SKIP**
- No strip, user input flows directly → **SUBMIT**

If unclear, `trace_path("method", mode="data_flow")` to follow the variable upstream; if still unclear, **submit with confidence=5**.

Current servlet containers (Tomcat, Jetty, Undertow) reject or neutralise CR/LF in header values, so on a maintained container the impact is limited — check the container/version and use severity 4 unless it is old or a custom HTTP layer writes the headers.

→ Submit: violated_invariant="HTTP response header value flows from request.getParameter() without CRLF stripping; HTTP response splitting injects arbitrary headers and body content", severity=7, confidence=8, exposure="internet", cwe="CWE-113"

---

## Step 10 — CRLF injection: log injection (Java / Kotlin / Scala)

```
grep(pattern="(log|logger|LOG|LOGGER)\.(info|debug|warn|error|trace)\s*\(\s*\"[^\"]*\"\s*\+|(log|logger|LOG|LOGGER)\.(info|debug|warn|error|trace)\s*\(\s*\"[^\"]*(\{\}|\$\{?[A-Za-z_])[^\"]*\"", max_matches=20)
```

The grep covers concatenation, SLF4J `{}` placeholders and Kotlin `$var` templates — placeholders do not escape CR/LF either. For each match: `get_code_snippet("containing_method")` to identify the variable being concatenated into the log message.

**Verify** — the variable must trace to HTTP user input to be a finding:
- Internal server state, DB result, or fixed constant → **SKIP** (logging internal values is normal)
- `trace_path("method", mode="data_flow")` if origin is unclear — follow the assignment upstream; if still unclear, **submit with confidence=5**
- Assigned from `request.getParameter(...)`, `@RequestParam`, request header, `@PathVariable`, request body → **CONTINUE**
- No `\r\n` sanitization before the log call → **SUBMIT**

→ Submit: violated_invariant="User input from [source] concatenated into log statement without CRLF sanitization; attacker injects newlines to forge audit log entries and break SIEM parsers", severity=5, confidence=7, exposure="internet", cwe="CWE-117"

---

## Step 11 — CRLF injection: Python / Go / Ruby

**Python:**
```
grep(pattern="headers\s*\[[^\]]+\]\s*=.*request\.(args|form|headers|values|json|GET|POST|META|cookies|query_params)|response\s*\[\s*['\"][^'\"]+['\"]\s*\]\s*=.*request\.|Response\s*\(.*headers\s*=.*request\.", max_matches=15)
```

**Go:**
```
grep(pattern="w\.Header\(\)\.(Set|Add)\s*\(\s*\"[^\"]+\"\s*,\s*[^\"\s)]", max_matches=15)
```

**Ruby/Rails:**
```
grep(pattern="response\.headers\[['\"][^'\"]+['\"]\]\s*=\s*params\[|headers\[['\"][^'\"]+['\"]\]\s*=\s*params\[", max_matches=15)
```

**Verify**: Go's `net/http` package sanitizes headers in recent versions — check the Go version in go.mod. Python Flask also sanitizes in recent versions. Still flag because old versions or custom HTTP libs may not.

→ Submit: violated_invariant="HTTP response header value set from user input; CRLF injection possible in older framework versions or custom transport layers", severity=6, confidence=7, exposure="internet", cwe="CWE-113"

---

## Step 12 — Prototype pollution: JavaScript / TypeScript

**Unsafe object merge / extend / assign with user data:**
```
grep(pattern="Object\.assign\s*\(\s*(\w+|\{\s*\})\s*,\s*req\.(body|query|params)\b|\bmerge\s*\(\s*(\w+|\{\s*\})\s*,\s*req\.(body|query|params)\b|\bextend\s*\(\s*(true\s*,\s*)?(\w+|\{\s*\})\s*,\s*req\.(body|query|params)\b", max_matches=20)
```

**Direct property assignment without hasOwnProperty check:**
```
grep(pattern="for\s*\(\s*(const|let|var)\s+\w+\s+in\s+(req\.(body|query)|\w*(body|input|payload|source|src)\w*)\s*\)", max_matches=20)
```

**lodash merge / deepmerge with user input:**
```
grep(pattern="_\.(merge|mergeWith|defaultsDeep)\s*\(\s*(\w+|\{\s*\})\s*,\s*req\.(body|query)\b|_\.(set|setWith)\s*\(\s*\w+\s*,\s*req\.|deepmerge\s*\(\s*\w+\s*,\s*req\.(body|query)\b|(\$|jQuery)\.extend\s*\(\s*true\s*,\s*(\w+|\{\s*\})\s*,\s*req\.(body|query)\b", max_matches=20)
```

**Verify**: what kind of merge receives the user object?
- **Recursive** merge / set-by-path without a `__proto__` / `constructor` / `prototype` key guard — lodash `merge` / `defaultsDeep` before 4.17.12, jQuery `$.extend(true, …)` before 3.4.0, hand-written deep-merge or for-in copy loops that recurse into nested objects — walks into `__proto__` and writes to `Object.prototype`: `{"__proto__": {"isAdmin": true}}` makes `isAdmin` true on every object → **SUBMIT** (severity 8). Check the library version in the lockfile.
- `Object.assign(target, req.body)`, object spread, or a shallow `extend` copies only top-level own keys: a JSON `"__proto__"` key replaces the prototype of `target` alone — no global pollution. That is still mass assignment on `target`; **SUBMIT** at severity 5 only if `target` is later trusted (e.g. `if (target.isAdmin)`).
- `req.query` parsed by `qs` drops `__proto__` keys by default, so JSON bodies are the main vector.

→ Submit: violated_invariant="Recursive merge (lodash.merge / deepmerge / $.extend(true) / custom deep-merge) copies user-controlled __proto__/constructor.prototype keys; Object.prototype polluted globally enabling auth bypass or RCE gadgets", severity=8 (5 for a shallow Object.assign that only replaces the target's own prototype), confidence=8, exposure="internet", cwe="CWE-1321"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
