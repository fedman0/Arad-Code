# SKILL: hunt-ldap-ssti

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

**grep = CANDIDATES only.** Never submit from a grep match alone. Issue all greps of a step together in one turn.

---

## FLOW VERIFICATION PROTOCOL — run for every candidate before submitting

For each grep match:

**a.** `get_code_snippet("containing_function_or_class")` — read the full enclosing function.

**b.** Identify variable `I` used as LDAP filter string / template string.

**c.** Trace I's origin:
- Hardcoded literal / config constant → **SKIP**
- User-supplied: HTTP param, request body, path variable, session value set by user → **CONTINUE**
- Unclear → `trace_path("function_name", mode="data_flow", direction="inbound")` upstream; if still unclear, **submit with confidence=5** (uncertain is not safe)

**d. For LDAP injection:**
- `ldap3.utils.conv.escape_filter_chars(I)` applied → **SKIP**
- `LdapQueryBuilder` with type-safe parameters → **SKIP**
- Raw string concat or %-format → **SUBMIT**

**d. For SSTI:**
- Template string from hardcoded file / resource (not user data) → **SKIP**
- Template string from user input with no sandbox → **SUBMIT immediately** (SSTI = RCE with Jinja2/ERB/Velocity/FreeMarker)
- Template string with sandbox but data leakage possible → **SUBMIT** at lower severity

**Submit only when confirmed**: name function, variable, and source (e.g. `request.form["template"] passed to Jinja2 Environment().from_string() in render_email() — RCE via {{''.__class__.__mro__}}`).

---

---

# Part A — LDAP Injection

## Step 1 — LDAP injection: Python (python-ldap / ldap3)

**python-ldap raw search filter:**
```
grep(pattern="\.search(_s|_st|_ext|_ext_s)?\s*\(.*SCOPE_\w+\s*,\s*(f['\"]|['\"].*(\+|['\"]\s*%\s*[\w(]|\.format\s*\())", max_matches=20)
```

**ldap3 Connection.search / filter built by concatenation:**
```
grep(pattern="\.search\s*\(.*(f['\"]\(|['\"]\(.*(\+|['\"]\s*%\s*[\w(]|\.format\s*\())|\w*[Ff]ilter\w*\s*=\s*(f['\"]\(|['\"]\(.*(\+|['\"]\s*%\s*[\w(]|\.format\s*\())", max_matches=20)
```

For each: is the filter string assembled with `+` or `%` from `request.args`, `request.form`, or `request.json()`? Injection into `(uid=INJECT)` can become `(uid=*)(|(password=*))` to bypass authentication or dump all users. Safe: `ldap3.utils.conv.escape_filter_chars(user_input)`.

→ Submit: violated_invariant="LDAP filter string concatenated with user input without escape_filter_chars; attacker bypasses authentication or extracts directory entries", severity=9, confidence=8, exposure="internet", cwe="CWE-90"

---

## Step 2 — LDAP injection: Java / Kotlin (JNDI / Spring LDAP)

**JNDI DirContext.search with user filter:**
```
grep(pattern="\.search\s*\(.*(\"\(.*\"\s*\+|String\.format\s*\(\s*\"\()|\w*[Ff]ilter\w*\s*=\s*(\"\(.*\"\s*\+|String\.format\s*\(\s*\"\()|new Initial(Dir|Ldap)Context\s*\(", max_matches=20)
```

**Spring LdapTemplate with concatenation:**
```
grep(pattern="ldapTemplate\.(search|authenticate|searchForObject|find|findOne)\s*\(.*\"\(.*\"\s*\+|\.filter\s*\(\s*\"[^\"]*\"\s*\+", max_matches=20)
```

Also flag `InitialDirContext` and `InitialLdapContext` instantiation — they are used as JNDI LDAP clients. Trace if the environment hashtable or subsequent search filter contains user data. `LdapQueryBuilder.query().filter("(uid={0})", uid)` and `.where("uid").is(uid)` encode the value → **SKIP**.

→ Submit: violated_invariant="Spring LdapTemplate/JNDI search filter built from user input; LDAP auth bypass or blind LDAP injection", severity=9, confidence=8, exposure="internet", cwe="CWE-90"

---

## Step 3 — LDAP injection: PHP

```
grep(pattern="ldap_(search|list|read)\s*\(.*,\s*(['\"]\(.*['\"]\s*\.\s*\$|\"\([^\"]*\$\w)|\$\w*[Ff]ilter\w*\s*=\s*(['\"]\(.*['\"]\s*\.\s*\$|\"\([^\"]*\$\w)", max_matches=20)
```

Safe signal: `ldap_escape($value, '', LDAP_ESCAPE_FILTER)` wrapping the user value.

→ Submit: violated_invariant="PHP ldap_search filter built with string concat from $_GET/$_POST; LDAP injection bypasses AD/OpenLDAP authentication", severity=9, confidence=9, exposure="internet", cwe="CWE-90"

---

## Step 4 — LDAP injection: C# (DirectorySearcher / DirectoryEntry)

```
grep(pattern="new DirectorySearcher\s*\(.*(\"\(.*\"\s*\+|(\$@?|@\$)\"\()|DirectoryEntry\s*\(\s*((\$@?|@\$)\"|\")LDAP://.*(\+|\{)", max_matches=20)
```

```
grep(pattern="\.Filter\s*=\s*\".*\"\s*\+\s*\w|\.Filter\s*=\s*(\$@?|@\$)\"[^\"]*\{|\.Filter\s*=\s*[Ss]tring\.Format\s*\(", max_matches=20)
```

→ Submit: violated_invariant="C# DirectorySearcher.Filter assembled from user input; LDAP injection in Active Directory authentication", severity=9, confidence=8, exposure="internet", cwe="CWE-90"

---

## Step 5 — LDAP injection: Ruby

```
grep(pattern="Net::LDAP::Filter\.(construct|from_rfc2254|from_rfc4515)\s*\(\s*(\"[^\"]*#\{|.*\+)|\.(search|bind_as)\s*\(.*filter\s*:\s*(\"[^\"]*#\{|.*\+)|\.(search|bind_as)\s*\(.*:filter\s*=>\s*(\"[^\"]*#\{|.*\+)", max_matches=20)
```

`Net::LDAP::Filter.eq` / `.contains` / `.begins` escape the value → **SKIP**; `Filter.construct` and raw filter strings do not.

→ Submit: violated_invariant="Ruby Net::LDAP filter string includes params without Net::LDAP::Filter encoding; LDAP auth bypass", severity=9, confidence=7, exposure="internet", cwe="CWE-90"

---

# Part B — Server-Side Template Injection (SSTI)

## Step 6 — SSTI: Python (Jinja2 / Mako / Tornado / Genshi)

**Jinja2 from_string / render_template_string / Template() with a non-literal template:**
```
grep(pattern="\b(from_string|render_template_string|Template)\s*\(\s*([^'\")\s]|['\"].*['\"]\s*(\+|%\s*[\w(]|\.format\s*\())", max_matches=20)
```

**Genshi / Chameleon / other template classes:**
```
grep(pattern="\b(MarkupTemplate|NewTextTemplate|OldTextTemplate|TextTemplate|PageTemplate)\s*\(\s*([^'\")\s]|['\"].*['\"]\s*(\+|%\s*[\w(]|\.format\s*\())", max_matches=20)
```

If the template source (first argument — a variable, f-string, `.format()` result, or concatenation such as `render_template_string("Hello " + name)`) originates from user input: Jinja2 SSTI enables `{{7*7}}` → RCE via `{{''.__class__.__mro__[1].__subclasses__()}}` gadget chains. This is full server-side code execution. `string.Template(...)` substitution is not SSTI → **SKIP**.

→ Submit: violated_invariant="Jinja2/Mako/Tornado Template() or render_template_string() called with user-controlled template string; RCE via template expression evaluation", severity=10, confidence=9, exposure="internet", cwe="CWE-1336"

---

## Step 7 — SSTI: JavaScript (Handlebars / Pug / EJS / Mustache / Nunjucks)

**Handlebars.compile / precompile with user input:**
```
grep(pattern="Handlebars\.(compile|precompile)\s*\(\s*([^'\"`)\s]|['\"].*['\"]\s*\+|`[^`]*\$\{)", max_matches=20)
```

**Pug / EJS / Nunjucks / lodash compile with user data:**
```
grep(pattern="(pug\.(compile|render)|ejs\.(compile|render)|nunjucks\.(renderString|compile)|\w*[Ee]nv\w*\.renderString|_\.template|doT\.template)\s*\(\s*([^'\"`)\s]|['\"].*['\"]\s*\+|`[^`]*\$\{)", max_matches=20)
```

**Mustache.render with user template string (not data):**
```
grep(pattern="Mustache\.render\s*\(\s*([^'\"`)\s]|['\"].*['\"]\s*\+|`[^`]*\$\{)", max_matches=20)
```

→ Submit: violated_invariant="JS template engine compile/render called with user-supplied template string; RCE via template prototype escape or code injection", severity=10, confidence=8, exposure="internet", cwe="CWE-1336"

---

## Step 8 — SSTI: Java (Velocity / FreeMarker / Thymeleaf)

**Velocity evaluate with user template:**
```
grep(pattern="Velocity\.evaluate\s*\(|[Vv]elocity\w*\.evaluate\s*\(|\.evaluate\s*\(\s*\w*([Cc]ontext|ctx)\w*\s*,\s*\w+\s*,", max_matches=20)
```

**FreeMarker Template from string:**
```
grep(pattern="new Template\s*\(.*new StringReader\s*\(|new Template\s*\(\s*[^,]+,\s*[^,'\"]+,\s*\w*([Cc]fg|[Cc]onf)\w*\s*\)|StringTemplateLoader\s*\(|\.putTemplate\s*\(", max_matches=20)
```

**Thymeleaf template / view name from user input:**
```
grep(pattern="templateEngine\.process\s*\(\s*[^'\")\s]|StringTemplateResolver|return\s+\"[\w-]+/[\w/-]*\"\s*\+\s*\w", max_matches=20)
```
A Spring controller returning a view name built from user input (`return "user/" + lang + "/welcome";`) is Thymeleaf expression injection via `__${...}__` preprocessing.

→ Submit: violated_invariant="Java Velocity/FreeMarker/Thymeleaf engine evaluates user-controlled template string; SSTI RCE via expression language evaluation", severity=10, confidence=8, exposure="internet", cwe="CWE-1336"

---

## Step 9 — SSTI: PHP (Twig / Smarty / Blade)

**Twig createTemplate with user string:**
```
grep(pattern="->createTemplate\s*\(\s*(\$|\"[^\"]*\$\w|['\"].*['\"]\s*\.\s*\$)", max_matches=20)
```

**Smarty string: / eval: resources with user string:**
```
grep(pattern="->(display|fetch|createTemplate)\s*\(\s*['\"](string|eval):.*\$", max_matches=20)
```

**Blade inline compilation:**
```
grep(pattern="Blade::render\s*\(\s*(\$|\"[^\"]*\$\w|['\"].*['\"]\s*\.\s*\$)|(Blade::|->)compileString\s*\(\s*\$", max_matches=15)
```

→ Submit: violated_invariant="PHP Twig createTemplate/Smarty string template with user input; SSTI via {system('id')} or {{dump(app.request.server.all)}}", severity=10, confidence=8, exposure="internet", cwe="CWE-1336"

---

## Step 10 — SSTI: Ruby (ERB / Liquid / Slim)

**ERB / Rails inline render with user template string:**
```
grep(pattern="ERB\.new\s*\(\s*([^'\")\s]|\"[^\"]*#\{|['\"].*['\"]\s*\+)|render\s*\(?\s*inline:\s*([^'\"\s]|\"[^\"]*#\{)", max_matches=20)
```

**Liquid / Haml / Tilt with user-controlled template:**
```
grep(pattern="Liquid::Template\.parse\s*\(\s*([^'\")\s]|\"[^\"]*#\{)|(Haml::Engine|Haml::Template|Slim::Template|Tilt::\w+Template)\.new\s*\(\s*[^'\")\s]", max_matches=20)
```

ERB SSTI is directly RCE: `<%= \`id\` %>`. Liquid is sandboxed but allows data leakage via `{{ site }}`. `ERB.new(File.read(...))` of an application template is not user-controlled → **SKIP**.

→ Submit: violated_invariant="Ruby ERB.new(user_template).result; SSTI with direct RCE via ERB expression evaluation", severity=10, confidence=9, exposure="internet", cwe="CWE-1336"

---

## Step 11 — SSTI: Go (text/template vs html/template)

**template Parse with a non-literal template string:**
```
grep(pattern="template\.New\s*\([^)]*\)\.Parse\s*\(\s*([^\"`)\s]|\"[^\"]*\"\s*\+)|\b(tmpl|tpl|t)\.Parse\s*\(\s*([^\"`)\s]|\"[^\"]*\"\s*\+)", file_glob="*.go", max_matches=20)
```

**Files that import text/template:**
```
grep(pattern="\"text/template\"", file_glob="*.go", max_matches=20)
```

Go's `text/template` has `{{.}}` which cannot escape the data model — unlike Jinja2 it cannot achieve RCE. But `html/template` must be used for HTML; `text/template` in an HTTP handler is XSS. SSTI in Go engines with `.Call` or `call` template functions can call arbitrary Go functions.

→ Submit: violated_invariant="Go text/template Parse with user template string; XSS via {{ or code execution via {{ call .Function }}", severity=8, confidence=7, exposure="internet", cwe="CWE-1336"

---

## Step 12 — SSTI: C# (Razor runtime compilation / Scriban)

```
grep(pattern="Engine\.Razor\.(RunCompile|Compile|AddTemplate)\s*\(\s*[^\")\s]|Razor\.Parse\s*\(\s*[^\")\s]|CompileRenderStringAsync\s*\(\s*[^,]+,\s*[^\",)\s]|RazorEngine\.(Compile|Run)\s*\(\s*[^\")\s]", max_matches=20)
```

```
grep(pattern="\bTemplate\.Parse(Liquid)?\s*\(\s*[^\")\s]|FluidTemplate\.(Try)?Parse\s*\(\s*[^\")\s]|\.TryParse\s*\(\s*[^\",)\s][^,]*,\s*out\s+(var\s+)?\w*[Tt]emplate", max_matches=20)
```

RazorEngine compiles C# code from templates — user-controlled templates are direct RCE. Scriban/Fluid are sandboxed but still allow model data leakage.

→ Submit: violated_invariant="RazorEngine compiles user-supplied template string as C#; direct arbitrary code execution on the server", severity=10, confidence=8, exposure="internet", cwe="CWE-1336"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
