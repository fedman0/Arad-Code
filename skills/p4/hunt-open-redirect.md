# SKILL: hunt-open-redirect

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

**grep = CANDIDATES only.** Never submit from a grep match alone.

---

## FLOW VERIFICATION PROTOCOL — run for every candidate before submitting

For each grep match:

**a.** `get_code_snippet("containing_function_or_class")` — read the full enclosing function.

**b.** Identify variable `R` used as the redirect target / Location header value.

**c.** Trace R's origin:
- Hardcoded path / constant → **SKIP**
- User-supplied: HTTP query param (`?next=`, `?returnUrl=`, `?redirect_uri=`), form field, referer header → **CONTINUE**
- Unclear → `trace_path("function_name", mode="data_flow")` upstream; if still unclear, **submit with confidence=5** (uncertain is not safe)

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

**Django redirect / HttpResponseRedirect with user param:**
```
grep(pattern="redirect\s*\(\s*request\.(GET|POST|args|form)\[|HttpResponseRedirect\s*\(\s*request\.(GET|POST)\[|redirect\s*\(\s*request\.data\[", max_matches=20)
```

**Flask redirect with args:**
```
grep(pattern="redirect\s*\(\s*request\.args\.get\s*\(|redirect\s*\(\s*request\.form\.get\s*\(|redirect\s*\(\s*request\.args\[", max_matches=20)
```

For each: does the redirect target pass through `url_has_allowed_host_and_scheme(url, allowed_hosts={request.get_host()})` (Django) or equivalent host validation? A bare `redirect(request.GET['next'])` redirects to any host.

→ Submit: violated_invariant="redirect() target taken directly from request parameter; open redirect to phishing site stealing session cookies or OAuth tokens", severity=6, confidence=8, exposure="internet"

---

## Step 2 — Open redirect: JavaScript / TypeScript (Express / Next.js)

**Express res.redirect with query/body:**
```
grep(pattern="res\.redirect\s*\(\s*req\.(query|body|params)\[|res\.redirect\s*\(\s*req\.(query|body|params)\.|res\.redirect\s*\(\s*\w*[Uu]rl\w*\s*[,)]", max_matches=20)
```

**Next.js router.push / window.location with user data:**
```
grep(pattern="router\.push\s*\(\s*req\.(query|body)|res\.setHeader\s*\(['\"]Location['\"],.*req\.(query|body)|window\.location\s*=\s*.*params\[", max_matches=20)
```

→ Submit: violated_invariant="Express res.redirect / Location header set from req.query without host validation; open redirect enables OAuth redirect_uri hijack or phishing", severity=6, confidence=8, exposure="internet"

---

## Step 3 — Open redirect: Java / Kotlin (Spring MVC / Jakarta Servlet)

**response.sendRedirect with user input:**
```
grep(pattern="response\.sendRedirect\s*\(\s*request\.getParameter\s*\(|sendRedirect\s*\(\s*\w*[Uu]rl\w*\s*\)|sendRedirect\s*\(\s*\w*[Rr]edirect\w*\s*\)", max_matches=20)
```

**Spring return "redirect:" with concatenation:**
```
grep(pattern="return\s+['\"]redirect:\s*['\"].*\+\s*\w+|return\s+['\"]redirect:\s*['\"].*request\.getParameter|ModelAndView\s*\(['\"]redirect:", max_matches=20)
```

→ Submit: violated_invariant="Spring/Servlet redirect target from request parameter; redirect to attacker domain bypasses authentication flow", severity=6, confidence=8, exposure="internet"

---

## Step 4 — Open redirect: Go

```
grep(pattern="http\.Redirect\s*\(\s*w,\s*r,\s*r\.(URL\.Query\(\)\.Get|FormValue)\s*\(|http\.Redirect\s*\(\s*w,\s*r,\s*\w*[Uu]rl\w*\s*,", max_matches=20)
```

```
grep(pattern="w\.Header\(\)\.Set\s*\(['\"]Location['\"],.*r\.(URL\.Query\(\)\.Get|FormValue)\s*\(|w\.Header\(\)\.Set\s*\(['\"]Location['\"],.*\+\s*\w+", max_matches=20)
```

→ Submit: violated_invariant="Go http.Redirect / Location header set from query parameter without host allowlist; open redirect bypasses CORS and same-origin protections", severity=6, confidence=7, exposure="internet"

---

## Step 5 — Open redirect: PHP

```
grep(pattern="header\s*\(\s*['\"]Location:\s*['\"].*\.\s*\\\$_(GET|POST|REQUEST|COOKIE)|header\s*\(\s*['\"]Location:\s*['\"].*\\\$\w+[Uu]rl|header\s*\(\s*['\"]Location:\s*['\"].*\\\$redirect", max_matches=20)
```

```
grep(pattern="header\s*\(\s*'Location:\s*'\s*\.\s*\\\$_(GET|POST)|wp_safe_redirect\s*\(\s*\\\$_(GET|POST)|wp_redirect\s*\(\s*\\\$_(GET|POST)", max_matches=20)
```

→ Submit: violated_invariant="PHP header(Location:) set from $_GET/$_POST; open redirect to external attacker domain", severity=6, confidence=9, exposure="internet"

---

## Step 6 — Open redirect: Ruby (Rails)

```
grep(pattern="redirect_to\s+params\[|redirect_to\s+\w*[Uu]rl\w*\s*$|redirect_to\s+\w*[Rr]eturn\w*\s*$", max_matches=20)
```

```
grep(pattern="redirect_to\s+params\[:return_to\]|redirect_to\s+params\[:redirect_url\]|redirect_to\s+params\[:next\]", max_matches=20)
```

`redirect_to` in Rails performs host validation only if `allow_other_host: false` is passed (default in Rails 7+). Older Rails or explicit `allow_other_host: true` is vulnerable.

→ Submit: violated_invariant="Rails redirect_to with params[:return_to] / params[:next] without allow_other_host: false; open redirect to external host", severity=6, confidence=8, exposure="internet"

---

## Step 7 — Open redirect: C# (ASP.NET / .NET Core)

```
grep(pattern="Response\.Redirect\s*\(\s*Request\.(QueryString|Form|Params)\[|Response\.Redirect\s*\(\s*Request\.Query\[|Redirect\s*\(\s*returnUrl\s*\)", max_matches=20)
```

```
grep(pattern="LocalRedirect\s*\(\s*\w*[Rr]eturn\w*\s*\)|RedirectResult\s*\(\s*\w*[Uu]rl\w*\s*\)|return\s+Redirect\s*\(\s*\w*[Uu]rl\w*\s*\)", max_matches=20)
```

`Url.IsLocalUrl(returnUrl)` is the ASP.NET safe check. `LocalRedirect()` automatically throws if the URL is non-local. Bare `Redirect(returnUrl)` does not validate.

→ Submit: violated_invariant="ASP.NET Redirect(returnUrl) without Url.IsLocalUrl check; open redirect enables CSRF token theft via referrer", severity=6, confidence=8, exposure="internet"

---

## Step 8 — Open redirect: Scala (Play Framework)

```
grep(pattern="Redirect\s*\(\s*request\.getQueryString\s*\(|Redirect\s*\(\s*request\.body\.asFormUrlEncoded\s*\(|MovedPermanently\s*\(\s*\w*[Uu]rl\w*\s*\)", max_matches=20)
```

```
grep(pattern="Results\.Redirect\s*\(\s*\w*[Uu]rl\w*\s*\)|SeeOther\s*\(\s*\w*[Uu]rl\w*\s*\)|Found\s*\(\s*\w*[Uu]rl\w*\s*\)", max_matches=20)
```

→ Submit: violated_invariant="Play Framework Redirect() with user query string; open redirect to external site", severity=6, confidence=7, exposure="internet"

---

## Step 9 — Open redirect: Swift (Vapor server-side)

```
grep(pattern="req\.redirect\s*\(\s*to\s*:\s*req\.query\[|Response\.redirect\s*\(\s*to\s*:\s*req\.content\[|\.redirect\s*\(\s*to\s*:\s*\w*[Uu]rl\w*\s*\)", max_matches=20)
```

→ Submit: violated_invariant="Vapor redirect target from req.query without host validation; open redirect in server-side Swift", severity=6, confidence=6, exposure="internet"

---

## Step 10 — OAuth redirect_uri takeover pattern (all languages)

This is the high-impact variant: redirect_uri accepted from request parameter during OAuth flows.

```
grep(pattern="redirect_uri.*=.*request\.(args|GET|POST|query|body|form|params)\[|redirect_uri.*=.*req\.(query|body|params)\[|redirect_uri.*getParameter\s*\(", max_matches=20)
```

```
grep(pattern="callback_url.*=.*request\.|return_url.*=.*request\.|returnUrl.*=.*Request\.(Query|Form)\[|next.*=.*request\.args", max_matches=20)
```

For each: is the `redirect_uri` validated against a registered allowlist? If not, OAuth account takeover is possible — attacker steals authorization code by hosting their own redirect target.

→ Submit: violated_invariant="OAuth redirect_uri accepted from request without registered allowlist validation; authorization code interception leads to account takeover", severity=9, confidence=8, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
