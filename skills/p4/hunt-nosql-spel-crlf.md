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

```
grep(pattern="bson\.M\{[^}]*r\.(URL\.Query\(\)\.Get|FormValue|PostForm)\s*\(|bson\.D\{[^}]*r\.(URL\.Query\(\)\.Get|FormValue)", max_matches=20)
```

```
grep(pattern="collection\.FindOne\s*\(\s*ctx,\s*bson\.M\{|collection\.Find\s*\(\s*ctx,\s*bson\.M\{", max_matches=20)
```

**Verify**: are any values in the `bson.M{}` filter derived from `r.URL.Query()`, `r.FormValue()`, or parsed JSON body? Specifically, can a user inject a BSON operator key?

→ Submit: violated_invariant="Go MongoDB filter uses user-supplied values in bson.M without operator key validation; operator injection possible", severity=9, confidence=7, exposure="internet"

---

## Step 4 — MongoDB operator injection: Rust (actix / hyper / rocket)

```
grep(pattern="collection\.find\s*\(\s*doc!\s*\{[^}]*\w+\s*=>\s*\w+\)|collection\.find_one\s*\(\s*doc!\s*\{", max_matches=15)
```

**Verify**: do any `doc!{}` values come from `web::Query`, `web::Json`, or path parameters? The `doc!{}` macro is type-checked at compile time, but if JSON is deserialized to `serde_json::Value` (untyped), operators can be injected.

→ Submit: violated_invariant="Rust MongoDB query uses serde_json::Value from user input in filter; operator injection bypasses strict type checking", severity=9, confidence=7, exposure="internet"

---

## Step 5 — NoSQL injection: AWS DynamoDB filter expressions

```
grep(pattern="FilterExpression\s*=\s*['\"].*\+|FilterExpression\s*=\s*f['\"].*\{|KeyConditionExpression\s*=\s*['\"].*\+", max_matches=15)
```

**Verify**: is the FilterExpression string assembled with user input concatenation? DynamoDB uses ExpressionAttributeValues for parameterization — raw string concat in FilterExpression is injectable.

→ Submit: violated_invariant="DynamoDB FilterExpression built with string concatenation; injection alters filter logic to return unauthorized records", severity=8, confidence=7, exposure="internet"

---

# Part B — Spring Expression Language (SpEL) Injection

## Step 6 — SpEL injection: Java Spring

```
grep(pattern="ExpressionParser\s*\(\s*\)|SpelExpressionParser\s*\(\s*\)|new SpelExpressionParser\s*\(\s*\)", max_matches=20)
```

```
grep(pattern="parser\.parseExpression\s*\(\s*\w+\s*\)|expressionParser\.parseExpression\s*\(\s*\w+\s*\)", max_matches=20)
```

**Verify**: is the string passed to `parseExpression()` user-supplied? Even a single character of user input in a SpEL expression allows RCE:
```java
String expr = userInput;  // "T(java.lang.Runtime).exec('id')"
parser.parseExpression(expr).getValue(context)  // RCE
```

→ Submit: violated_invariant="Spring SpEL parseExpression() receives user-controlled string; attacker evaluates T(java.lang.Runtime).exec() for immediate RCE", severity=10, confidence=9, exposure="internet"

---

## Step 7 — SpEL injection: Kotlin Spring

```
grep(pattern="SpelExpressionParser\s*\(\s*\)\.parseExpression\s*\(\s*\w+\s*\)|ExpressionParser\s*\(\s*\)\.parseExpression\s*\(\s*\w+\s*\)", max_matches=20)
```

**Verify**: same as Java — Kotlin Spring apps share the SpEL engine. User-controlled expression string = RCE.

→ Submit: violated_invariant="Kotlin Spring SpEL parseExpression with user input; RCE via T(Runtime).exec()", severity=10, confidence=9, exposure="internet"

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

**Verify**: does the expression string originate from HTTP request? JEXL, MVEL, OGNL, and javax.script all enable RCE when user input reaches the engine.

→ Submit: violated_invariant="Java expression engine (JEXL/MVEL/OGNL/ScriptEngine) evaluates user-supplied expression; RCE via reflection gadgets built into the expression language", severity=10, confidence=9, exposure="internet"

---

# Part C — CRLF Injection / HTTP Response Splitting

## Step 9 — CRLF injection: Java (Servlet / Spring)

```
grep(pattern="response\.setHeader\s*\(\s*['\"][^'\"]+['\"],\s*\w+\s*\)|response\.addHeader\s*\(\s*['\"][^'\"]+['\"],\s*\w+\s*\)", max_matches=20)
```

```
grep(pattern="response\.sendRedirect\s*\(\s*\w+\s*\)|response\.setStatus\s*\(", max_matches=20)
```

**Verify**: does the header value (`\w+` above) originate from `request.getParameter()`? If so, an attacker injects `\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>` into the header, inserting a fake HTTP response body.

→ Submit: violated_invariant="HTTP response header set from user parameter without CRLF stripping; HTTP response splitting injects arbitrary headers and XSS into browsers that cache the split response", severity=7, confidence=8, exposure="internet"

---

## Step 10 — CRLF injection: log injection (Java / Kotlin / Scala)

```
grep(pattern="log\.(info|debug|warn|error)\s*\(\s*['\"].*\+\s*\w+|logger\.(info|debug|warn|error)\s*\(\s*['\"].*\+\s*\w+", max_matches=20)
```

**Verify**: does the string concatenated into the log message come from user input (HTTP parameter, API request body)? An attacker can inject fake log lines: `username=admin\n2024-01-01 WARN [auth] Login succeeded for admin` — forges the audit trail.

→ Submit: violated_invariant="User input concatenated into log statement without sanitization; CRLF injection in log forges audit trail entries, breaks log parsers, may cause log injection attacks in aggregation tools", severity=5, confidence=7, exposure="internet"

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
