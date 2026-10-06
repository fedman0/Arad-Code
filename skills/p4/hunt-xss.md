# SKILL: hunt-xss

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

**grep = CANDIDATES only.** Never submit from a grep match alone.

---

## FLOW VERIFICATION PROTOCOL — run for every candidate before submitting

For each grep match:

**a.** `get_code_snippet("containing_function_or_class")` — read the full enclosing function.

**b.** Identify variable `V` assigned to the DOM sink / reflected in HTML response.

**c.** Trace V's origin:
- Hardcoded constant / static template string → **SKIP**
- User-supplied: HTTP param, query string, form field, URL fragment, WebSocket message, API response that includes user-contributed content → **CONTINUE**
- Unclear → `trace_path("function_name", mode="data_flow")` upstream; if still unclear, **submit with confidence=5** (uncertain is not safe)

**d.** Check for output encoding between source and sink:
- `htmlspecialchars($v, ENT_QUOTES)` / `HtmlEncode` / `html.EscapeString` → **SKIP**
- DOMPurify.sanitize applied immediately before → **SKIP**
- `mark_safe` / `html_safe` / `dangerouslySetInnerHTML` / `v-html` / `bypassSecurityTrust*` without sanitization → **SUBMIT**
- Raw template interpolation without escaping → **SUBMIT**

**Submit only when confirmed**: name function, variable, source (user input), and missing encoder (e.g. `req.query.name interpolated into res.send("<p>" + name + "</p>") in search() without htmlEncode`).

---

---

## Step 1 — XSS: Python (Django / Jinja2 / Flask)

**Django mark_safe / format_html misuse:**
```
grep(pattern="mark_safe\s*\(.*request\.|mark_safe\s*\(.*\+|mark_safe\s*\(f['\"]|mark_safe\s*\(.*format\s*\(", max_matches=20)
```

**Jinja2 / Flask render_template_string (direct template injection → XSS/SSTI):**
```
grep(pattern="render_template_string\s*\(.*request\.|render_template_string\s*\(.*\+|Markup\s*\(.*request\.|Markup\s*\(.*\+", max_matches=20)
```

For each match: is the variable derived from `request.args`, `request.form`, `request.json()`, `request.GET`, or `request.POST`? `mark_safe()` disables Django's autoescaping — any user value passed to it is reflected as-is.

→ Submit: violated_invariant="User input passed to mark_safe/Markup/render_template_string without escaping; reflected as raw HTML", severity=8, confidence=8, exposure="internet"

---

## Step 2 — XSS: JavaScript / TypeScript (DOM sinks)

**innerHTML / outerHTML / document.write:**
```
grep(pattern="\.innerHTML\s*=\s*\w|\.outerHTML\s*=\s*\w|document\.write\s*\(.*\+|document\.writeln\s*\(.*\+|insertAdjacentHTML\s*\(", max_matches=20)
```

**jQuery html / append / prepend with user data:**
```
grep(pattern="\$\s*\([^)]*\)\.html\s*\(.*req\.|\.html\s*\(.*params\[|\.append\s*\(.*req\.|\.prepend\s*\(.*req\.", max_matches=20)
```

For each match: does the right-hand side of `innerHTML =` or argument to `html()` contain a variable from `req.query`, `req.body`, `req.params`, or any request parameter? Template literals with user data are equally dangerous.

→ Submit: violated_invariant="User-controlled string assigned to DOM sink without sanitization; stored/reflected XSS", severity=8, confidence=8, exposure="internet"

---

## Step 3 — XSS: React (dangerouslySetInnerHTML)

```
grep(pattern="dangerouslySetInnerHTML\s*=\s*\{\{|dangerouslySetInnerHTML=\{\{|__html\s*:\s*\w+", max_matches=20)
```

For each match: what value populates `__html`? If it comes from props, state, or any API response that includes user-contributed content, it is an XSS vector. DOMPurify sanitization immediately before the assignment is the only safe mitigation.

→ Submit: violated_invariant="React dangerouslySetInnerHTML set from [source]; HTML injection executes attacker JS in viewer's browser", severity=8, confidence=7, exposure="internet"

---

## Step 4 — XSS: Vue / Angular template bypass

**Vue v-html directive:**
```
grep(pattern="v-html\s*=\s*['\"][^'\"]*['\"]|v-html=\"\w+", max_matches=20)
```

**Angular bypassSecurityTrust:**
```
grep(pattern="bypassSecurityTrustHtml\s*\(|bypassSecurityTrustScript\s*\(|bypassSecurityTrustResourceUrl\s*\(|bypassSecurityTrustStyle\s*\(", max_matches=20)
```

For each `v-html`: is the bound variable derived from user input or an API response? For `bypassSecurityTrust*`: is the argument user-controlled?

→ Submit: violated_invariant="Angular/Vue security bypass applied to user data; DOM XSS via framework trust override", severity=8, confidence=8, exposure="internet"

---

## Step 5 — XSS: Java / Kotlin (JSP / Servlet / Thymeleaf)

**Servlet response.getWriter without encoding:**
```
grep(pattern="response\.getWriter\s*\(\s*\)\.print\s*\(.*request\.getParameter|PrintWriter.*print\s*\(.*getParameter\s*\(|getWriter\s*\(\s*\)\.write\s*\(.*getParameter", max_matches=20)
```

**Thymeleaf th:utext (unescaped):**
```
grep(pattern="th:utext\s*=\s*['\"][^'\"]*['\"]|th:utext=\"\$\{|\.setText\s*\(.*request\.getParameter", max_matches=15)
```

**Velocity $!{var} (not escaped):**
```
grep(pattern="\$!\{[a-zA-Z_][a-zA-Z0-9_.]*\}|\$![a-zA-Z_][a-zA-Z0-9_.]*", max_matches=20)
```

→ Submit: violated_invariant="User parameter written to HTTP response or unescaped template without HtmlUtils.htmlEscape/ESAPI.encoder; reflected XSS", severity=8, confidence=8, exposure="internet"

---

## Step 6 — XSS: PHP

**echo / print with raw $_GET/$_POST:**
```
grep(pattern="echo\s+\\\$_(GET|POST|REQUEST|COOKIE)\s*\[|print\s+\\\$_(GET|POST|REQUEST|COOKIE)\s*\[|echo\s+\\\$\w+.*\\\$_(GET|POST)", max_matches=20)
```

**printf / sprintf without htmlspecialchars:**
```
grep(pattern="printf\s*\(.*\\\$_(GET|POST|REQUEST)|echo\s+htmlspecialchars_decode\s*\(|echo\s+html_entity_decode\s*\(", max_matches=15)
```

For each: is the output within HTML context (inside `<body>`, attribute, or script)? `htmlspecialchars($var, ENT_QUOTES, 'UTF-8')` is the safe pattern.

→ Submit: violated_invariant="PHP echoes user input directly into HTML response; reflected XSS via unescaped request variable", severity=8, confidence=9, exposure="internet"

---

## Step 7 — XSS: Ruby (Rails)

**html_safe / raw on user data:**
```
grep(pattern="params\[.*\]\.html_safe|raw\s*\(\s*params\[|html_safe\s*$|\.html_safe\s*%", max_matches=20)
```

**render inline with interpolation:**
```
grep(pattern="render\s+inline\s*:\s*['\"].*#\{.*params|render\s+inline\s*:.*\+.*params", max_matches=15)
```

→ Submit: violated_invariant="Rails html_safe/raw applied to params; escaping bypassed, XSS in rendered HTML", severity=8, confidence=8, exposure="internet"

---

## Step 8 — XSS: Go (html/template vs text/template)

**text/template used for HTML output (no autoescaping):**
```
grep(pattern="\"text/template\"\s*$|text/template.*Execute\s*\(|template\.Must\s*\(template\.New.*Parse\s*\(", max_matches=20)
```

**fmt.Fprintf writing HTML with user data:**
```
grep(pattern="fmt\.Fprintf\s*\(w,\s*['\"]<|fmt\.Fprintf\s*\(w,\s*.*\+\s*\w+\s*\+|io\.WriteString\s*\(w,\s*.*\+\s*\w+\s*\+", max_matches=20)
```

For each `text/template`: is the template executing with user-controlled data without `html.EscapeString`? `html/template` auto-escapes; `text/template` does not.

→ Submit: violated_invariant="Go text/template or fmt.Fprintf writes user data into HTML without html.EscapeString; reflected XSS", severity=8, confidence=7, exposure="internet"

---

## Step 9 — XSS: C# (ASP.NET / Razor)

**Response.Write without HtmlEncode:**
```
grep(pattern="Response\.Write\s*\(.*Request\.\w+\[|Response\.Write\s*\(.*Request\.QueryString|Response\.Write\s*\(.*Request\.Form", max_matches=20)
```

**HtmlHelper.Raw / MvcHtmlString.Create with user data:**
```
grep(pattern="Html\.Raw\s*\(.*[Rr]equest\.|MvcHtmlString\.Create\s*\(.*\+|@Html\.Raw\s*\(", max_matches=20)
```

→ Submit: violated_invariant="ASP.NET Response.Write or Html.Raw outputs user request data without HtmlEncode; reflected XSS", severity=8, confidence=8, exposure="internet"

---

## Step 10 — XSS: Swift (WKWebView)

```
grep(pattern="loadHTMLString\s*\(.*\+|loadHTMLString\s*\(.*\\\\(|evaluateJavaScript\s*\(.*\+|evaluateJavaScript\s*\(.*\\\\(", max_matches=20)
```

For each `loadHTMLString` or `evaluateJavaScript`: does the string contain a variable derived from network response, user input field, or URL parameters? Swift WKWebView runs full JS — attacker HTML executes with app permissions.

→ Submit: violated_invariant="WKWebView loads/executes HTML/JS containing user-controlled data; XSS with access to WebKit bridge methods", severity=8, confidence=7, exposure="local"

---

## Step 11 — XSS: Rust (Actix-web / Rocket)

**HttpResponse body with user data formatted as HTML:**
```
grep(pattern="HttpResponse::Ok\s*\(\s*\)\.body\s*\(format!\s*\(['\"]<|HttpResponse::Ok\s*\(\s*\)\.body\s*\(\w+\s*\+", max_matches=20)
```

```
grep(pattern="format!\s*\(['\"]<[^\"']*\{\}|format!\s*\(['\"]<[^\"']*\{[a-z]", max_matches=20)
```

For each: does the `{}` format argument originate from `req.match_info()`, `web::Query`, `web::Path`, or `web::Json`? Rust has no automatic HTML escaping — use the `html-escape` crate.

→ Submit: violated_invariant="Rust web handler formats user data directly into HTML body; reflected XSS without html-escape crate", severity=8, confidence=7, exposure="internet"

---

## Step 12 — XSS: Scala (Play Framework / Twirl)

**Play Twirl @Html() with user data:**
```
grep(pattern="Html\s*\(\s*\w+\s*\)|play\.twirl\.api\.Html\s*\(|Ok\s*\(\s*Html\s*\(", max_matches=20)
```

**Scala string formatting into HTML:**
```
grep(pattern="Ok\s*\(\s*s\"<|Ok\s*\(\s*\"<.*\+\s*\w+|Content\s*\(\s*s\"<", max_matches=20)
```

For each `Html(userVar)`: Twirl auto-escapes only `@variable` interpolation — `Html(raw)` bypasses all escaping.

→ Submit: violated_invariant="Play Framework Html() wraps user-controlled string; XSS via escaping bypass in Twirl template", severity=8, confidence=7, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
