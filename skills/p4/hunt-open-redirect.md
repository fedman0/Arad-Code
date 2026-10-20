---
parallel: true
requires: [web]
---

# SKILL: hunt-open-redirect

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

**grep = CANDIDATES only.** Never submit from a grep match alone. Issue all greps of a step together in one turn.

---

## FLOW VERIFICATION PROTOCOL — run for every candidate before submitting

For each grep match:

**a.** `get_code_snippet("containing_function_or_class")` — read the full enclosing function.

**b.** Identify variable `R` used as the redirect target / Location header value.

**c.** Trace R's origin:
- Hardcoded path / constant → **SKIP**
- User-supplied: HTTP query param (`?next=`, `?returnUrl=`, `?redirect_uri=`), form field, referer header → **CONTINUE**
- Unclear → `trace_path("function_name", mode="data_flow", direction="inbound")` upstream; if still unclear, **submit with confidence=5** (uncertain is not safe)

**d.** Check for redirect validation between source and redirect call:
- `url_has_allowed_host_and_scheme(url, allowed_hosts)` (Django) → **SKIP**
- `Url.IsLocalUrl(returnUrl)` (ASP.NET) → **SKIP**
- `allow_other_host: false` (Rails 7+) → **SKIP** (but confirm Rails version)
- `urlparse(url).netloc == ""` or `url.startswith("/")` — weak check, bypassable with `//evil.com` → **SUBMIT**
- No validation → **SUBMIT**

**Submit only when confirmed**: name function, parameter, and bypass proof (e.g. `GET ?next= flows into redirect() in login_view with no host check — //evil.com bypass works`).

---

---

## Step 1 — Open redirect: Python (Django / Flask / FastAPI)

**redirect / HttpResponseRedirect / RedirectResponse with a request parameter:**
```
grep(pattern="(redirect|HttpResponseRedirect|HttpResponsePermanentRedirect|RedirectResponse)\s*\(\s*(url\s*=\s*)?request\.(GET|POST|args|form|values|data|query_params)(\[|\.get\s*\()", max_matches=20)
```

**redirect with a variable target (next / return / url …):**
```
grep(pattern="(redirect|HttpResponseRedirect|HttpResponsePermanentRedirect|RedirectResponse)\s*\(\s*(url\s*=\s*)?\w*(?i:url|uri|next|return|redirect|goto|dest|continue|target|callback)\w*\s*[,)]", max_matches=20)
```

For each: does the redirect target pass through `url_has_allowed_host_and_scheme(url, allowed_hosts={request.get_host()})` (Django) or equivalent host validation? A bare `redirect(request.GET['next'])` redirects to any host.

→ Submit: violated_invariant="redirect() target taken directly from request parameter; open redirect to phishing site stealing session cookies or OAuth tokens", severity=6, confidence=8, exposure="internet", cwe="CWE-601"

---

## Step 2 — Open redirect: JavaScript / TypeScript (Express / Next.js)

**Express res.redirect with query/body:**
```
grep(pattern="res\.redirect\s*\(\s*(\d{3}\s*,\s*)?(req\.(query|body|params|headers|cookies)|[\w.]*(?i:url|uri|next|return|redirect|goto|dest|continue|target|callback)\w*\s*[,)]|`[^`]*\$\{|['\"].*['\"]\s*\+)", max_matches=20)
```

**Location header / client-side navigation with user data:**
```
grep(pattern="res\.(setHeader|header|set|writeHead)\s*\(.*['\"]?Location['\"]?\s*[:,].*req\.(query|body|params)|(router\.(push|replace)|location\.(assign|replace))\s*\(.*(router\.query|searchParams\.get|URLSearchParams|location\.(search|hash)|params\[|query\.)|location(\.href)?\s*=\s*.*(router\.query|searchParams\.get|URLSearchParams|location\.(search|hash)|params\[)|NextResponse\.redirect\s*\(.*(searchParams|query)|\bredirect\s*\(\s*(searchParams|params)\.(get\(|\w)", max_matches=20)
```

A fixed path prefix (`res.redirect('/login?next=' + encodeURIComponent(x))`) is safe; `'/' + userValue` is not (`//evil.com`).

→ Submit: violated_invariant="Express res.redirect / Location header set from req.query without host validation; open redirect enables OAuth redirect_uri hijack or phishing", severity=6, confidence=8, exposure="internet", cwe="CWE-601"

---

## Step 3 — Open redirect: Java / Kotlin (Spring MVC / Jakarta Servlet)

**response.sendRedirect with user input:**
```
grep(pattern="sendRedirect\s*\(\s*([\w.]*getParameter\s*\(|[\w.]*getHeader\s*\(|\w*(?i:url|uri|redirect|next|return|goto|target|dest|continue|callback)\w*\s*\)|\"[^\"]*\"\s*\+\s*[\w.]*getParameter)", max_matches=20)
```

**Spring return "redirect:" with concatenation:**
```
grep(pattern="return\s+\"redirect:\s*\"\s*\+\s*\w|\"redirect:\$\{?\w|new ModelAndView\s*\(\s*\"redirect:\s*\"\s*\+|new RedirectView\s*\(\s*([^\")\s]|\"\s*\+)", max_matches=20)
```

→ Submit: violated_invariant="Spring/Servlet redirect target from request parameter; redirect to attacker domain bypasses authentication flow", severity=6, confidence=8, exposure="internet", cwe="CWE-601"

---

## Step 4 — Open redirect: Go

```
grep(pattern="http\.Redirect\s*\(\s*\w+\s*,\s*\w+\s*,\s*(r\.(URL\.Query\(\)\.Get|FormValue|PostFormValue|Referer|Header\.Get)\s*\(|\w*(?i:url|uri|next|return|redirect|goto|target|dest|continue|callback)\w*\s*,)|c\.Redirect\s*\(\s*[\w.]+\s*,\s*(c\.(Query|QueryParam|DefaultQuery|PostForm|FormValue|Param|GetHeader)\s*\(|\w*(?i:url|uri|next|return|redirect|goto|target|dest|continue|callback)\w*\s*\))", max_matches=20)
```

```
grep(pattern="w\.Header\(\)\.Set\s*\(\s*['\"]Location['\"]\s*,.*r\.(URL\.Query\(\)\.Get|FormValue)\s*\(|w\.Header\(\)\.Set\s*\(\s*['\"]Location['\"]\s*,.*\+\s*\w+", max_matches=20)
```

→ Submit: violated_invariant="Go http.Redirect / Location header set from query parameter without host allowlist; open redirect bypasses CORS and same-origin protections", severity=6, confidence=7, exposure="internet", cwe="CWE-601"

---

## Step 5 — Open redirect: PHP

```
grep(pattern="header\s*\(\s*['\"](?i:location)\s*:\s*(['\"]\s*\.\s*\$|\$\w|\{\$)", max_matches=20)
```

```
grep(pattern="wp_redirect\s*\(\s*(\$_(GET|POST|REQUEST)|\$\w*(?i:url|redirect|next|return|goto|to)\w*\b)|redirect\s*\(\s*\)\s*->\s*(to|away)\s*\(\s*(\$request|request\s*\(|\$_(GET|POST)|\$\w*(?i:url|redirect|next|return)\w*\b)|\bredirect\s*\(\s*(\$request->|request\s*\(\s*\)\s*->|request\s*\(\s*['\"]|\$_(GET|POST))|Redirect::(to|away)\s*\(\s*(\$request|Input::get|request\s*\(|\$_(GET|POST))", max_matches=20)
```

`wp_safe_redirect()` validates the host against an allowlist → **SKIP**; `wp_redirect()` and Laravel `redirect()->to()` / `->away()` do not.

→ Submit: violated_invariant="PHP header(Location:) set from $_GET/$_POST; open redirect to external attacker domain", severity=6, confidence=9, exposure="internet", cwe="CWE-601"

---

## Step 6 — Open redirect: Ruby (Rails)

```
grep(pattern="redirect_to\s*\(?\s*(params\[|params\.(fetch|require|permit|dig)|request\.(referer|referrer|params)|session\[:?\w*return|cookies\[)|redirect_to\s*\(?\s*@?(return_to|return_url|returnTo|redirect_url|redirect_uri|redirect_path|next_url|next|target_url|url|continue_url|destination|back_to)\s*(,|\)|$)", max_matches=20)
```

```
grep(pattern="allow_other_host:\s*true|raise_on_open_redirects\s*=\s*false|redirect_to\s*\(?\s*\"[^\"]*#\{\s*params", max_matches=20)
```

Rails 7.0+ raises `UnsafeRedirectError` for an external host only when `config.action_controller.raise_on_open_redirects` is true (set by `load_defaults 7.0`; apps upgraded from older versions often still have it false) and the call does not pass `allow_other_host: true`. Rails < 7 does not validate the host at all.

→ Submit: violated_invariant="Rails redirect_to with params[:return_to] / params[:next] without allow_other_host: false; open redirect to external host", severity=6, confidence=8, exposure="internet", cwe="CWE-601"

---

## Step 7 — Open redirect: C# (ASP.NET / .NET Core)

```
grep(pattern="Response\.Redirect\s*\(\s*(Request(\.\w+)?\s*\[|\w*(?i:url|return|redirect|next|target)\w*\s*[,)])|\bRedirect(Permanent)?\s*\(\s*Request\.", max_matches=20)
```

```
grep(pattern="new RedirectResult\s*\(\s*\w*(?i:url|return|redirect|next|target)\w*\s*[,)]|return\s+Redirect(Permanent)?\s*\(\s*\w*(?i:url|return|redirect|next|target)\w*\s*\)", max_matches=20)
```

`Url.IsLocalUrl(returnUrl)` is the ASP.NET safe check. `LocalRedirect()` automatically throws if the URL is non-local. Bare `Redirect(returnUrl)` does not validate.

→ Submit: violated_invariant="ASP.NET Redirect(returnUrl) without Url.IsLocalUrl check; open redirect enables CSRF token theft via referrer", severity=6, confidence=8, exposure="internet", cwe="CWE-601"

---

## Step 8 — Open redirect: Scala (Play Framework)

```
grep(pattern="Redirect\s*\(\s*(request\.(getQueryString|queryString|body\.asFormUrlEncoded|headers\.get)|\w*(?i:url|return|redirect|next|target)\w*\s*[,)])|\b(MovedPermanently|SeeOther|Found|TemporaryRedirect|PermanentRedirect)\s*\(\s*(request\.|\w*(?i:url|return|redirect|next|target)\w*\s*\))", max_matches=20)
```

```
grep(pattern="getQueryString\s*\(\s*\"(?i:\w*(url|return|redirect|next|goto|target|continue|callback)\w*)\"", max_matches=20)
```

→ Submit: violated_invariant="Play Framework Redirect() with user query string; open redirect to external site", severity=6, confidence=7, exposure="internet", cwe="CWE-601"

---

## Step 9 — Open redirect: Swift (Vapor server-side)

```
grep(pattern="\.redirect\s*\(\s*to\s*:\s*(req\.(query|content|parameters)|try\s+req\.|\w*(?i:url|return|redirect|next|target)\w*\s*[,)])", max_matches=20)
```

→ Submit: violated_invariant="Vapor redirect target from req.query without host validation; open redirect in server-side Swift", severity=6, confidence=6, exposure="internet", cwe="CWE-601"

---

## Step 10 — OAuth redirect_uri takeover pattern (all languages)

This is the high-impact variant: redirect_uri accepted from request parameter during OAuth flows.

```
grep(pattern="(redirect_uri|redirectUri|redirect_url|redirectUrl)\w*['\"]?\s*[:=]\s*.*(request\.(args|GET|POST|query_params|form|values|data|json)|req\.(query|body|params)|getParameter\s*\(|params\[|\$_(GET|POST|REQUEST)|Request\.(Query|Form))|\{[^}]*\bredirect_uri\b[^}]*\}\s*=\s*req\.(query|body)", max_matches=20)
```

```
grep(pattern="(?i:callback_?ur[li]|return_?ur[li]|return_?to|next_?ur[li]|continue_?ur[li]|redirect_?to)\w*\s*[:=]\s*.*([Rr]equest\.|req\.(query|body|params)|params\[|\$_(GET|POST|REQUEST))|\bnext\s*=\s*request\.(args|GET|POST|form)", max_matches=20)
```

For each: is the `redirect_uri` validated against a registered allowlist? If not, OAuth account takeover is possible — attacker steals authorization code by hosting their own redirect target.

→ Submit: violated_invariant="OAuth redirect_uri accepted from request without registered allowlist validation; authorization code interception leads to account takeover", severity=9, confidence=8, exposure="internet", cwe="CWE-601"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
