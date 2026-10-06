# SKILL: hunt-ldap-ssti

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

**grep = CANDIDATES only.** Never submit from a grep match alone.

---

## FLOW VERIFICATION PROTOCOL — run for every candidate before submitting

For each grep match:

**a.** `get_code_snippet("containing_function_or_class")` — read the full enclosing function.

**b.** Identify variable `I` used as LDAP filter string / template string.

**c.** Trace I's origin:
- Hardcoded literal / config constant → **SKIP**
- User-supplied: HTTP param, request body, path variable, session value set by user → **CONTINUE**
- Unclear → `trace_path("function_name", mode="data_flow")` upstream; if still unclear, **submit with confidence=5** (uncertain is not safe)

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
grep(pattern="ldap\.search_s\s*\(\s*\w+,\s*ldap\.SCOPE_\w+,\s*['\"].*\+|ldap\.search\s*\(\s*\w+,\s*ldap\.SCOPE_\w+,\s*['\"].*\+", max_matches=20)
```

**ldap3 Connection.search with concatenation:**
```
grep(pattern="conn\.search\s*\(\s*\w+,\s*['\"].*\+|Connection\s*\(.*\)\.search\s*\(\s*.*search_filter\s*=.*\+", max_matches=20)
```

For each: is the filter string assembled with `+` or `%` from `request.args`, `request.form`, or `request.json()`? Injection into `(uid=INJECT)` can become `(uid=*)(|(password=*))` to bypass authentication or dump all users. Safe: `ldap3.utils.conv.escape_filter_chars(user_input)`.

→ Submit: violated_invariant="LDAP filter string concatenated with user input without escape_filter_chars; attacker bypasses authentication or extracts directory entries", severity=9, confidence=8, exposure="internet"

---

## Step 2 — LDAP injection: Java / Kotlin (JNDI / Spring LDAP)

**JNDI DirContext.search with user filter:**
```
grep(pattern="ctx\.search\s*\(\s*\w+,\s*['\"].*\+|dirContext\.search\s*\(\s*\w+,\s*['\"].*\+|new InitialDirContext\s*\(", max_matches=20)
```

**Spring LdapTemplate with concatenation:**
```
grep(pattern="ldapTemplate\.search\s*\(\s*\w+,\s*['\"].*\+|ldapTemplate\.authenticate\s*\(\s*\w+,\s*['\"].*\+|LdapQueryBuilder\.query\s*\(\s*\).*filter\s*\(\s*['\"].*\+", max_matches=20)
```

Also flag `InitialDirContext` and `InitialLdapContext` instantiation — they are used as JNDI LDAP clients. Trace if the environment hashtable or subsequent search filter contains user data.

→ Submit: violated_invariant="Spring LdapTemplate/JNDI search filter built from user input; LDAP auth bypass or blind LDAP injection", severity=9, confidence=8, exposure="internet"

---

## Step 3 — LDAP injection: PHP

```
grep(pattern="ldap_search\s*\(\s*\\\$\w+,\s*\\\$\w+,\s*['\"].*\.\s*\\\$|ldap_list\s*\(\s*\\\$\w+,\s*\\\$\w+,\s*['\"].*\.\s*\\\$|ldap_read\s*\(\s*\\\$\w+,\s*\\\$\w+,\s*['\"].*\.\s*\\\$", max_matches=20)
```

Safe signal: `ldap_escape($value, '', LDAP_ESCAPE_FILTER)` wrapping the user value.

→ Submit: violated_invariant="PHP ldap_search filter built with string concat from $_GET/$_POST; LDAP injection bypasses AD/OpenLDAP authentication", severity=9, confidence=9, exposure="internet"

---

## Step 4 — LDAP injection: C# (DirectorySearcher / DirectoryEntry)

```
grep(pattern="new DirectorySearcher\s*\(\s*\w+,\s*['\"].*\+|DirectorySearcher\s*\(\s*\).*Filter\s*=.*\+|DirectoryEntry\s*\(\s*['\"]LDAP://.*\+", max_matches=20)
```

```
grep(pattern="\.Filter\s*=\s*['\"].*\+\s*\w+|\.Filter\s*=\s*\\\$['\"][^'\"]*\{", max_matches=20)
```

→ Submit: violated_invariant="C# DirectorySearcher.Filter assembled from user input; LDAP injection in Active Directory authentication", severity=9, confidence=8, exposure="internet"

---

## Step 5 — LDAP injection: Ruby

```
grep(pattern="Net::LDAP\.new\s*\(.*\)\.search\s*\(\s*filter\s*:|ldap\.search\s*\(\s*filter\s*:.*\+.*params\[|Net::LDAP::Filter\.\w+\s*\(.*params\[", max_matches=20)
```

→ Submit: violated_invariant="Ruby Net::LDAP filter string includes params without Net::LDAP::Filter encoding; LDAP auth bypass", severity=9, confidence=7, exposure="internet"

---

# Part B — Server-Side Template Injection (SSTI)

## Step 6 — SSTI: Python (Jinja2 / Mako / Tornado / Genshi)

**Jinja2 from_string / render_template_string with user input:**
```
grep(pattern="Environment\s*\(\s*\)\.from_string\s*\(\s*\w*[Tt]emplate\w*\s*\)|render_template_string\s*\(\s*\w*[Tt]emplate\w*\s*[,)]|Template\s*\(\s*\w*[Tt]emplate\w*\s*\)\.render", max_matches=20)
```

**Mako / Tornado / Genshi with user template:**
```
grep(pattern="mako\.template\.Template\s*\(\s*\w*[Tt]emplate\w*\s*\)|tornado\.template\.Template\s*\(\s*\w*[Tt]emplate\w*\s*\)|genshi\.template\.\w+Template\s*\(\s*\w*[Tt]emplate\w*\s*\)", max_matches=20)
```

If `template` variable originates from user input: Jinja2 SSTI enables `{{7*7}}` → RCE via `{{''.__class__.__mro__[1].__subclasses__()}}` gadget chains. This is full server-side code execution.

→ Submit: violated_invariant="Jinja2/Mako/Tornado Template() or render_template_string() called with user-controlled template string; RCE via template expression evaluation", severity=10, confidence=9, exposure="internet"

---

## Step 7 — SSTI: JavaScript (Handlebars / Pug / EJS / Mustache / Nunjucks)

**Handlebars.compile / precompile with user input:**
```
grep(pattern="Handlebars\.compile\s*\(\s*\w*[Tt]emplate\w*\s*\)|Handlebars\.precompile\s*\(\s*\w*[Tt]emplate\w*\s*\)", max_matches=20)
```

**Pug / EJS / Mustache compile with user data:**
```
grep(pattern="pug\.compile\s*\(\s*\w*[Tt]emplate\w*\s*\)|pug\.render\s*\(\s*\w*[Tt]emplate\w*\s*\)|ejs\.render\s*\(\s*\w*[Tt]emplate\w*\s*\)|nunjucks\.renderString\s*\(\s*\w*[Tt]emplate\w*\s*,", max_matches=20)
```

**Mustache.render with user template string (not data):**
```
grep(pattern="Mustache\.render\s*\(\s*req\.(query|body|params)\.|Mustache\.render\s*\(\s*\w*[Tt]emplate\w*\s*,\s*", max_matches=20)
```

→ Submit: violated_invariant="JS template engine compile/render called with user-supplied template string; RCE via template prototype escape or code injection", severity=10, confidence=8, exposure="internet"

---

## Step 8 — SSTI: Java (Velocity / FreeMarker / Thymeleaf)

**Velocity StringWriter with user template:**
```
grep(pattern="Velocity\.evaluate\s*\(.*\w*[Tt]emplate\w*\s*\)|VelocityEngine\s*\(\s*\)\.evaluate\s*\(.*\w*[Tt]emplate\w*\s*\)|new VelocityContext\s*\(\s*\)", max_matches=20)
```

**FreeMarker Template from string:**
```
grep(pattern="new Template\s*\(\s*['\"][^'\"]*['\"],\s*\w*[Tt]emplate\w*\s*,|freemarker\.template\.Template\s*\(\s*[^,]+,\s*new StringReader\s*\(\s*\w*[Tt]emplate\w*\s*\)", max_matches=20)
```

**Thymeleaf SpringTemplateEngine with user template:**
```
grep(pattern="templateEngine\.process\s*\(\s*\w*[Tt]emplate\w*\s*,|SpringTemplateEngine\s*\(\s*\)\.process\s*\(\s*\w*[Tt]emplate\w*\s*,", max_matches=20)
```

→ Submit: violated_invariant="Java Velocity/FreeMarker/Thymeleaf engine evaluates user-controlled template string; SSTI RCE via expression language evaluation", severity=10, confidence=8, exposure="internet"

---

## Step 9 — SSTI: PHP (Twig / Smarty / Blade)

**Twig createTemplate with user string:**
```
grep(pattern="\\\$twig->createTemplate\s*\(\s*\\\$_(GET|POST|REQUEST|COOKIE)\[|\\\$twig->createTemplate\s*\(\s*\\\$\w+\s*\)|Environment.*createTemplate\s*\(\s*\\\$\w+\s*\)", max_matches=20)
```

**Smarty display / fetch with user string:**
```
grep(pattern="\\\$smarty->display\s*\(\s*['\"]string:.*\\\$|smarty->fetch\s*\(\s*['\"]string:.*\\\$|\\\$smarty->assign\s*\(.*\\\$_(GET|POST)", max_matches=20)
```

**Blade @eval / inline Blade compilation:**
```
grep(pattern="Blade::render\s*\(\s*\\\$\w*[Tt]emplate\w*|view()->make.*with.*\\\$_(GET|POST)", max_matches=15)
```

→ Submit: violated_invariant="PHP Twig createTemplate/Smarty string template with user input; SSTI via {system('id')} or {{dump(app.request.server.all)}}", severity=10, confidence=8, exposure="internet"

---

## Step 10 — SSTI: Ruby (ERB / Liquid / Slim)

**ERB with user template string:**
```
grep(pattern="ERB\.new\s*\(\s*params\[|ERB\.new\s*\(\s*\w*[Tt]emplate\w*\s*\)\.result\s*\(|ERB\.new\s*\(\s*request\.", max_matches=20)
```

**Liquid with user-controlled template:**
```
grep(pattern="Liquid::Template\.parse\s*\(\s*params\[|Liquid::Template\.parse\s*\(\s*\w*[Tt]emplate\w*\s*\)", max_matches=20)
```

ERB SSTI is directly RCE: `<%= \`id\` %>`. Liquid is sandboxed but allows data leakage via `{{ site }}`.

→ Submit: violated_invariant="Ruby ERB.new(user_template).result; SSTI with direct RCE via ERB expression evaluation", severity=10, confidence=9, exposure="internet"

---

## Step 11 — SSTI: Go (text/template vs html/template)

**text/template Execute with user template string:**
```
grep(pattern="template\.Must\s*\(\s*template\.New\s*\(\s*['\"][^'\"]*['\"\s*\)\s*\)\.Parse\s*\(\s*\w*[Tt]emplate\w*\s*\)|template\.New\s*\(\s*['\"][^'\"]*['\"\s*\)\s*\.Parse\s*\(\s*\w*[Tt]emplate\w*\s*\)", max_matches=20)
```

```
grep(pattern="text/template.*\.Parse\s*\(\s*\w*[Tt]emplate\w*\s*\)|textTemplate\.Execute\s*\(\s*\w+,\s*\w+\s*\)", max_matches=20)
```

Go's `text/template` has `{{.}}` which cannot escape the data model — unlike Jinja2 it cannot achieve RCE. But `html/template` must be used for HTML; `text/template` in an HTTP handler is XSS. SSTI in Go engines with `.Call` or `call` template functions can call arbitrary Go functions.

→ Submit: violated_invariant="Go text/template Parse with user template string; XSS via {{ or code execution via {{ call .Function }}", severity=8, confidence=7, exposure="internet"

---

## Step 12 — SSTI: C# (Razor runtime compilation / Scriban)

```
grep(pattern="RazorEngine\.Compile\s*\(\s*\w*[Tt]emplate\w*\s*\)|RazorEngine\.Run\s*\(\s*\w*[Tt]emplate\w*\s*[,)]|Engine\.Razor\.RunCompile\s*\(\s*\w*[Tt]emplate\w*\s*,", max_matches=20)
```

```
grep(pattern="Scriban\.Template\.Parse\s*\(\s*\w*[Tt]emplate\w*\s*\)|Fluid\.FluidParser\s*\(\s*\).*TryParse\s*\(\s*\w*[Tt]emplate\w*\s*,", max_matches=20)
```

RazorEngine compiles C# code from templates — user-controlled templates are direct RCE. Scriban/Fluid are sandboxed but still allow model data leakage.

→ Submit: violated_invariant="RazorEngine compiles user-supplied template string as C#; direct arbitrary code execution on the server", severity=10, confidence=8, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
