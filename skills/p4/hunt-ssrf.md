# SKILL: hunt-ssrf

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

**grep = CANDIDATES only.** Never submit from a grep match alone.

---

## FLOW VERIFICATION PROTOCOL — run for every candidate before submitting

For each grep match:

**a.** `get_code_snippet("containing_function_or_class")` — read the full enclosing function.

**b.** Identify variable `URL` passed to the HTTP client call.

**c.** Trace URL's origin:
- Hardcoded string literal / config constant / env var → **SKIP**
- User-supplied: `request.args/body/form/GET/POST/json/params`, path param, or header value → **CONTINUE**
- Unclear → `trace_path("function_name", mode="data_flow")` upstream until you find the source; if still unclear, **submit with confidence=5** (uncertain is not safe)

**d.** Check for URL validation between source and HTTP call:
- Allowlist host check (`url.host in ALLOWED_HOSTS`, `startswith("https://api.example.com/")`) → **SKIP**
- `urlparse(url).netloc == expected` comparison → **SKIP**
- No host validation, or blocklist-only (bypassable via DNS rebinding / IPv6 / redirects) → **SUBMIT**

**Submit only when confirmed**: name the function, the user-input variable, and the missing guard (e.g. `params["webhook_url"] flows into requests.get in process_webhook() with no host allowlist`).

---

---

## Step 1 — SSRF: Python (requests / httpx / urllib)

**requests / httpx with user-controlled URL:**
```
grep(pattern="requests\.(get|post|put|delete|head|patch|request)\s*\(.*request\.(args|form|json|GET|POST)|requests\.\w+\s*\(\s*\w*url\w*\s*[,)]", max_matches=20)
```

```
grep(pattern="httpx\.(get|post|put|delete|AsyncClient)\s*\(.*request\.(args|form|json|GET|POST)|urllib\.request\.urlopen\s*\(.*request\.", max_matches=20)
```

For each: is the URL argument derived from `request.args`, `request.form`, `request.json()`, `request.GET`, or `request.POST`? Allowlist-based validation (`url.startswith("https://api.example.com/")`) is the safe pattern — blocklist approaches are bypassable via redirects or IPv6.

→ Submit: violated_invariant="requests/httpx fetches attacker-supplied URL; internal network reachable from server (metadata, Redis, Kubernetes API)", severity=9, confidence=8, exposure="internet"

---

## Step 2 — SSRF: JavaScript / TypeScript (fetch / axios / node http)

**fetch / axios with request parameter:**
```
grep(pattern="fetch\s*\(\s*req\.(query|body|params)|axios\.(get|post|put)\s*\(\s*req\.(query|body|params)|axios\.\w+\s*\(\s*\w*[Uu]rl\w*\s*[,)]", max_matches=20)
```

**Node http.request / https.request with user host:**
```
grep(pattern="http\.request\s*\(\s*\{.*host\s*:\s*req\.|https\.request\s*\(\s*\{.*host\s*:\s*req\.|http\.get\s*\(\s*req\.(query|body|params)", max_matches=20)
```

**got / node-fetch / superagent:**
```
grep(pattern="got\s*\(\s*req\.(query|body|params)|node-fetch.*fetch\s*\(\s*req\.|superagent\.get\s*\(\s*req\.", max_matches=15)
```

→ Submit: violated_invariant="Server-side fetch to user-controlled URL; attacker pivots to internal services via cloud metadata or private network", severity=9, confidence=8, exposure="internet"

---

## Step 3 — SSRF: Java (URL.openConnection / RestTemplate / WebClient)

**java.net.URL with user input:**
```
grep(pattern="new URL\s*\(\s*\w*[Uu]rl\w*\s*\)\.openConnection\s*\(\s*\)|new URL\s*\(\s*request\.getParameter|URLConnection.*openConnection\s*\(\s*\)", max_matches=20)
```

**Spring RestTemplate / WebClient:**
```
grep(pattern="restTemplate\.(getForObject|getForEntity|exchange|postForObject)\s*\(\s*\w*[Uu]rl|webClient\.get\s*\(\s*\)\.uri\s*\(\s*\w*[Uu]rl|WebClient\.create\s*\(\s*\w*[Uu]rl", max_matches=20)
```

**Apache HttpClient:**
```
grep(pattern="HttpGet\s*\(\s*\w*[Uu]rl\s*\)|HttpPost\s*\(\s*\w*[Uu]rl\s*\)|HttpRequest\.newBuilder\s*\(\s*\)\.uri\s*\(\s*URI\.create\s*\(\s*\w*[Uu]rl", max_matches=20)
```

→ Submit: violated_invariant="Java HTTP client requests user-supplied URL; SSRF to internal K8s API / cloud metadata (169.254.169.254)", severity=9, confidence=8, exposure="internet"

---

## Step 4 — SSRF: Go (http.Get / http.NewRequest)

```
grep(pattern="http\.Get\s*\(\s*\w*[Uu]rl\w*\s*\)|http\.NewRequest\s*\(.*\w*[Uu]rl\w*\s*[,)]|http\.Post\s*\(\s*\w*[Uu]rl", max_matches=20)
```

```
grep(pattern="r\.URL\.Query\(\)\.Get.*[Uu]rl|r\.FormValue\s*\(.*[Uu]rl|r\.PostFormValue\s*\(.*[Uu]rl", max_matches=20)
```

Correlate: find where the URL variable is assigned (grep result 1) and where its value originates (grep result 2). If the same variable appears in both, it is SSRF.

→ Submit: violated_invariant="Go http.Get/NewRequest with URL from query/form parameter; internal network reachable", severity=9, confidence=7, exposure="internet"

---

## Step 5 — SSRF: PHP (curl / file_get_contents / fopen)

**curl with user URL:**
```
grep(pattern="curl_setopt\s*\(.*CURLOPT_URL.*\\\$_(GET|POST|REQUEST|COOKIE)|curl_setopt\s*\(\s*\\\$\w+,\s*CURLOPT_URL,\s*\\\$\w+\s*\)", max_matches=20)
```

**file_get_contents / fopen with URL:**
```
grep(pattern="file_get_contents\s*\(\s*\\\$_(GET|POST|REQUEST|COOKIE)\[|file_get_contents\s*\(\s*\\\$\w+[Uu]rl|fopen\s*\(\s*\\\$_(GET|POST|REQUEST)", max_matches=20)
```

For each `curl_setopt(..., CURLOPT_URL, ...)`: does the URL argument come from `$_GET`, `$_POST`, or a database field that stores user input?

→ Submit: violated_invariant="PHP curl/file_get_contents fetches user-controlled URL; SSRF to internal admin panels, Redis, memcached", severity=9, confidence=9, exposure="internet"

---

## Step 6 — SSRF: Ruby (Net::HTTP / open-uri / Faraday)

**Net::HTTP / open-uri with params:**
```
grep(pattern="Net::HTTP\.get\s*\(\s*URI\s*\(\s*params\[|Net::HTTP\.get_response\s*\(\s*URI\s*\(\s*params\[|open\s*\(\s*params\[", max_matches=20)
```

**Faraday / HTTParty / RestClient:**
```
grep(pattern="Faraday\.get\s*\(\s*params\[|HTTParty\.get\s*\(\s*params\[|RestClient\.get\s*\(\s*params\[|URI\.open\s*\(\s*params\[", max_matches=20)
```

`Kernel#open` / `URI.open` with a user-supplied URL is especially dangerous — it also supports `|command` execution (RCE).

→ Submit: violated_invariant="Ruby HTTP client / open() fetches user-supplied URL; SSRF or RCE via pipe prefix in open()", severity=9, confidence=8, exposure="internet"

---

## Step 7 — SSRF: C# (HttpClient / WebRequest)

```
grep(pattern="new HttpClient\s*\(\s*\).*GetAsync\s*\(\s*\w*[Uu]rl|new HttpClient\s*\(\s*\).*PostAsync\s*\(\s*\w*[Uu]rl|HttpClient\(\)\.GetStringAsync\s*\(\s*\w*[Uu]rl", max_matches=20)
```

```
grep(pattern="WebRequest\.Create\s*\(\s*\w*[Uu]rl\s*\)|WebClient\s*\(\s*\)\.DownloadString\s*\(\s*\w*[Uu]rl", max_matches=20)
```

→ Submit: violated_invariant="C# HttpClient/WebRequest fetches URL derived from request parameter; SSRF to internal .NET services or Azure metadata", severity=9, confidence=8, exposure="internet"

---

## Step 8 — SSRF: Kotlin (OkHttp / Ktor / Retrofit)

```
grep(pattern="OkHttpClient\s*\(\s*\).*Request\.Builder\s*\(\s*\).*url\s*\(\s*\w*[Uu]rl|OkHttp.*\.newCall\s*\(.*Request\.Builder|Ktor.*HttpClient.*get\s*\(\s*\w*[Uu]rl", max_matches=20)
```

```
grep(pattern="URL\s*\(\s*\w*[Uu]rl\s*\)\.openConnection\s*\(\s*\)|okhttp3\.Request\.Builder\s*\(\s*\)\.url\s*\(\s*\w*[Uu]rl", max_matches=20)
```

→ Submit: violated_invariant="Kotlin OkHttp/Ktor fetches attacker-controlled URL; SSRF targeting internal Kubernetes services", severity=9, confidence=7, exposure="internet"

---

## Step 9 — SSRF: Rust (reqwest / hyper)

```
grep(pattern="reqwest::get\s*\(\s*\w*[Uu]rl\s*\)|reqwest::Client::new\s*\(\s*\)\.get\s*\(\s*\w*[Uu]rl|reqwest::blocking::get\s*\(\s*\w*[Uu]rl", max_matches=20)
```

```
grep(pattern="hyper::Client::new\s*\(\s*\).*request\s*\(\s*Request::builder\s*\(\s*\)\.uri\s*\(\s*\w*[Uu]rl", max_matches=15)
```

→ Submit: violated_invariant="Rust reqwest/hyper sends request to URL from user input; SSRF to internal services accessible from the server", severity=9, confidence=7, exposure="internet"

---

## Step 10 — SSRF: Swift (URLSession)

```
grep(pattern="URLSession\.shared\.dataTask\s*\(\s*with\s*:\s*URL\s*\(\s*string\s*:\s*\w*[Uu]rl\s*\)\s*!\s*\)|URLSession\.shared\.dataTask\s*\(with:\s*URL\s*\(string:\s*\w+\s*\)", max_matches=20)
```

```
grep(pattern="URLRequest\s*\(\s*url\s*:\s*URL\s*\(\s*string\s*:\s*\w*[Uu]rl|URLSession.*dataTask.*URLRequest\s*\(\s*url\s*:", max_matches=20)
```

For each: is the `url` string derived from user input (query params, JSON body, user settings)? iOS/macOS apps calling SSRF targets from the app server are lower severity than server-side; server-side Swift (Vapor/Hummingbird) is full SSRF.

→ Submit: violated_invariant="Swift URLSession fetches user-controlled URL; SSRF if running server-side, or data exfiltration if client-side", severity=8, confidence=6, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
