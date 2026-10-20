# SKILL: hunt-xss

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

**grep = CANDIDATES only.** Never submit from a grep match alone. Issue all greps of a step together in one turn.

---

## FLOW VERIFICATION PROTOCOL — run for every candidate before submitting

For each grep match:

**a.** `get_code_snippet("containing_function_or_class")` — read the full enclosing function.

**b.** Identify variable `V` assigned to the DOM sink / reflected in HTML response.

**c.** Trace V's origin:
- Hardcoded constant / static template string → **SKIP**
- User-supplied: HTTP param, query string, form field, URL fragment, WebSocket message, API response that includes user-contributed content → **CONTINUE**
- Unclear → `trace_path("function_name", mode="data_flow", direction="inbound")` upstream; if still unclear, **submit with confidence=5** (uncertain is not safe)

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
grep(pattern="mark_safe\s*\(\s*([^'\")\s]|['\"].*['\"]\s*(\+|%\s*[\w(]|\.format\s*\())|SafeString\s*\(\s*[^'\")\s]", max_matches=20)
```

**Jinja2 / Flask render_template_string (direct template injection → XSS/SSTI):**
```
grep(pattern="(render_template_string|Markup)\s*\(\s*(f['\"]|['\"].*['\"]\s*(\+|%\s*[\w(]|\.format\s*\()|.*request\.)", max_matches=20)
```

**Templates with escaping turned off:**
```
grep(pattern="\|\s*safe\b|\{%-?\s*autoescape\s+(off|false)", max_matches=20)
```

For each match: is the variable derived from `request.args`, `request.form`, `request.json()`, `request.GET`, or `request.POST` (or stored user content)? `mark_safe()` and the `|safe` filter disable Django/Jinja2 autoescaping — any user value passed through them is reflected as-is. `format_html("<b>{}</b>", v)` escapes `v` → **SKIP**.

→ Submit: violated_invariant="User input passed to mark_safe/Markup/render_template_string without escaping; reflected as raw HTML", severity=8, confidence=8, exposure="internet", cwe="CWE-79"

---

## Step 2 — XSS: JavaScript / TypeScript (DOM sinks)

**innerHTML / outerHTML / document.write:**
```
grep(pattern="\.(innerHTML|outerHTML)\s*\+?=\s*([^'\"`\s;]|['\"].*['\"]\s*\+|`[^`]*\$\{)|document\.write(ln)?\s*\(\s*([^'\"`)\s]|.*\+|`[^`]*\$\{)|insertAdjacentHTML\s*\(", max_matches=20)
```

**jQuery html / append / prepend with dynamic data:**
```
grep(pattern="\$(\([^)]*\)|\w+)\.(html|append|prepend|after|before|replaceWith|wrap)\s*\(\s*([^'\"`)\s]|['\"].*['\"]\s*\+|`[^`]*\$\{)|\$\(\s*(location|window\.location|document\.(URL|referrer)|decodeURIComponent)", max_matches=20)
```

**DOM sources (correlate with the sinks above):**
```
grep(pattern="location\.(hash|search|href)|document\.(URL|documentURI|referrer|baseURI)|window\.name|new URLSearchParams\(|searchParams\.get\(|addEventListener\s*\(\s*['\"]message['\"]", max_matches=20)
```

**Server-side JS templates with unescaped output (EJS / Handlebars / Pug):**
```
grep(pattern="<%-\s*[^%\s]|\{\{\{\s*[^}\s]|!\{[^}]+\}", max_matches=20)
```

For each sink match: does the value come from a DOM source (`location.hash` / `location.search` / `location.href`, `document.URL`, `document.referrer`, `window.name`, `URLSearchParams`, a `message` event's `event.data` without an `event.origin` check), from server data that contains user content, or (server-side) from `req.query` / `req.body` / `req.params`? Template literals with user data are equally dangerous.

→ Submit: violated_invariant="User-controlled string assigned to DOM sink without sanitization; stored/reflected XSS", severity=8, confidence=8, exposure="internet", cwe="CWE-79"

---

## Step 3 — XSS: React (dangerouslySetInnerHTML)

```
grep(pattern="dangerouslySetInnerHTML\s*=\s*\{|__html\s*:\s*([^'\"\s}]|['\"].*['\"]\s*\+|`[^`]*\$\{)", max_matches=20)
```

For each match: what value populates `__html`? If it comes from props, state, or any API response that includes user-contributed content, it is an XSS vector. DOMPurify sanitization immediately before the assignment is the only safe mitigation.

→ Submit: violated_invariant="React dangerouslySetInnerHTML set from [source]; HTML injection executes attacker JS in viewer's browser", severity=8, confidence=7, exposure="internet", cwe="CWE-79"

---

## Step 4 — XSS: Vue / Angular / Svelte template bypass

**Vue v-html / Svelte {@html}:**
```
grep(pattern="v-html\s*=\s*['\"][^'\"]*['\"]|\{@html\s", max_matches=20)
```

**Angular bypassSecurityTrust:**
```
grep(pattern="bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)\s*\(", max_matches=20)
```

For each `v-html` / `{@html}`: is the bound variable derived from user input or an API response? For `bypassSecurityTrust*`: is the argument user-controlled?

→ Submit: violated_invariant="Angular/Vue security bypass applied to user data; DOM XSS via framework trust override", severity=8, confidence=8, exposure="internet", cwe="CWE-79"

---

## Step 5 — XSS: Java / Kotlin (JSP / Servlet / Thymeleaf)

**Servlet writer / JSP output without encoding:**
```
grep(pattern="\.(print|println|write|append|printf|format)\s*\(.*getParameter\s*\(|<%=\s*request\.get(Parameter|Header|QueryString)|>\s*\$\{\s*param(Values)?\.\w+", max_matches=20)
```

**Thymeleaf th:utext / [(...)] (unescaped):**
```
grep(pattern="th:utext\s*=\s*['\"][^'\"]*['\"]|\[\(\$\{|\.setText\s*\(.*request\.getParameter", max_matches=15)
```

**Velocity templates (`$var` and `$!var` are not HTML-escaped by default):**
```
grep(pattern="EscapeHtmlReference|eventhandler\.referenceinsertion\.class", max_matches=10)
```
```
grep(pattern="\$!?\{?[a-zA-Z_]\w*(\.\w+)*\}?", file_glob="*.vm", max_matches=20)
```
If an `EscapeHtmlReference` reference-insertion handler is configured, references are escaped → **SKIP**; otherwise check which `.vm` references carry user data and are not wrapped in `$esc.html(...)`.

→ Submit: violated_invariant="User parameter written to HTTP response or unescaped template without HtmlUtils.htmlEscape/ESAPI.encoder; reflected XSS", severity=8, confidence=8, exposure="internet", cwe="CWE-79"

---

## Step 6 — XSS: PHP

**echo / print / short echo with raw request data:**
```
grep(pattern="(echo|print)\s*\(?\s*(['\"][^'\"]*['\"]\s*\.\s*)*\$_(GET|POST|REQUEST|COOKIE)\s*\[|(echo|print)\s+\"[^\"]*\$_(GET|POST|REQUEST|COOKIE)|<\?=\s*\$_(GET|POST|REQUEST|COOKIE)|(echo|<\?=)\s*\$_SERVER\[\s*['\"](PHP_SELF|REQUEST_URI|QUERY_STRING|HTTP_REFERER|HTTP_USER_AGENT)", max_matches=20)
```

**printf / decode helpers / unescaped Blade & Twig output:**
```
grep(pattern="printf\s*\(.*\$_(GET|POST|REQUEST)|(echo|print)\s+(htmlspecialchars_decode|html_entity_decode)\s*\(|\{!!.*!!\}|\|\s*raw\s*\}\}", max_matches=15)
```

For each: is the output within HTML context (inside `<body>`, attribute, or script)? `htmlspecialchars($var, ENT_QUOTES, 'UTF-8')` is the safe pattern; Blade `{{ }}` and Twig `{{ }}` escape by default, `{!! !!}` and `|raw` do not.

→ Submit: violated_invariant="PHP echoes user input directly into HTML response; reflected XSS via unescaped request variable", severity=8, confidence=9, exposure="internet", cwe="CWE-79"

---

## Step 7 — XSS: Ruby (Rails)

**html_safe / raw on user data:**
```
grep(pattern="params\[.*\]\.html_safe|[^'\"\s]\.html_safe\b|#\{.*['\"]\.html_safe|\braw\s*\(\s*[^'\")\s]|\braw\s+(params|@\w)|<%==", max_matches=20)
```

**render inline with interpolation:**
```
grep(pattern="render\s*\(?\s*inline\s*:\s*(['\"].*#\{|.*\+|\s*params)", max_matches=15)
```

→ Submit: violated_invariant="Rails html_safe/raw applied to params; escaping bypassed, XSS in rendered HTML", severity=8, confidence=8, exposure="internet", cwe="CWE-79"

---

## Step 8 — XSS: Go (html/template vs text/template)

**text/template used for HTML output / html/template escaping bypassed:**
```
grep(pattern="\"text/template\"|template\.(HTML|HTMLAttr|JS|JSStr|URL|CSS|Srcset)\s*\(\s*[^\"`)\s]", file_glob="*.go", max_matches=20)
```

**fmt.Fprintf / Write writing HTML with user data:**
```
grep(pattern="fmt\.Fprint(f|ln)?\s*\(\s*w\s*,.*(%[sv]|\+\s*\w)|io\.WriteString\s*\(\s*w\s*,.*\+\s*\w|w\.Write\s*\(\s*\[\]byte\s*\(.*(\+\s*\w|Sprintf)", file_glob="*.go", max_matches=20)
```

For each `text/template`: is the template executing with user-controlled data without `html.EscapeString`? `html/template` auto-escapes; `text/template` does not, and `template.HTML(userValue)` disables `html/template` escaping for that value.

→ Submit: violated_invariant="Go text/template or fmt.Fprintf writes user data into HTML without html.EscapeString; reflected XSS", severity=8, confidence=7, exposure="internet", cwe="CWE-79"

---

## Step 9 — XSS: C# (ASP.NET / Razor)

**Response.Write without HtmlEncode:**
```
grep(pattern="Response\.Write\s*\(.*Request(\.\w+)?\s*\[|Response\.Write\s*\(.*Request\.(QueryString|Form|Params|Cookies|Headers)|<%=\s*Request", max_matches=20)
```

**HtmlHelper.Raw / MvcHtmlString.Create / HtmlString with user data:**
```
grep(pattern="Html\.Raw\s*\(\s*([^\")\s]|\"[^\"]*\"\s*\+|(\$@?|@\$)\")|MvcHtmlString\.Create\s*\(\s*[^\")\s]|MvcHtmlString\.Create\s*\(.*\+|new HtmlString\s*\(\s*[^\")\s]", max_matches=20)
```

→ Submit: violated_invariant="ASP.NET Response.Write or Html.Raw outputs user request data without HtmlEncode; reflected XSS", severity=8, confidence=8, exposure="internet", cwe="CWE-79"

---

## Step 10 — XSS: Swift (WKWebView)

```
grep(pattern="(loadHTMLString|evaluateJavaScript|callAsyncJavaScript)\s*\(\s*([^\")\s]|\"[^\"]*(\x5C\(|\"\s*\+))", max_matches=20)
```

For each `loadHTMLString` or `evaluateJavaScript`: does the string contain a variable derived from network response, user input field, or URL parameters? Swift WKWebView runs full JS — attacker HTML executes with app permissions.

→ Submit: violated_invariant="WKWebView loads/executes HTML/JS containing user-controlled data; XSS with access to WebKit bridge methods", severity=8, confidence=7, exposure="internet", cwe="CWE-79"

---

## Step 11 — XSS: Rust (Actix-web / Rocket / Axum)

**HttpResponse body with user data formatted as HTML:**
```
grep(pattern="HttpResponse::Ok\s*\(\s*\)\.body\s*\(format!\s*\(['\"]<|HttpResponse::Ok\s*\(\s*\)\.body\s*\(\w+\s*\+|(Html|RawHtml)\s*\(\s*format!\s*\(", max_matches=20)
```

```
grep(pattern="format!\s*\(\s*\"[^\"]*<[a-zA-Z/][^\"]*\{", max_matches=20)
```

For each: does the `{}` format argument originate from `req.match_info()`, `web::Query`, `web::Path`, or `web::Json`? Rust has no automatic HTML escaping — use the `html-escape` crate.

→ Submit: violated_invariant="Rust web handler formats user data directly into HTML body; reflected XSS without html-escape crate", severity=8, confidence=7, exposure="internet", cwe="CWE-79"

---

## Step 12 — XSS: Scala (Play Framework / Twirl)

**Play Twirl @Html() with user data:**
```
grep(pattern="\bHtml\s*\(\s*([^\")\s]|s\"|\"[^\"]*\"\s*\+)|play\.twirl\.api\.Html\s*\(", max_matches=20)
```

**Scala string formatting into HTML:**
```
grep(pattern="Ok\s*\(\s*s\"<|Ok\s*\(\s*\"<.*\+\s*\w+|Content\s*\(\s*s\"<", max_matches=20)
```

For each `Html(userVar)`: Twirl auto-escapes only `@variable` interpolation — `Html(raw)` bypasses all escaping. `Ok(s"<…>")` without `.as(HTML)` is served as text/plain → **SKIP**.

→ Submit: violated_invariant="Play Framework Html() wraps user-controlled string; XSS via escaping bypass in Twirl template", severity=8, confidence=7, exposure="internet", cwe="CWE-79"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
