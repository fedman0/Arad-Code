---
parallel: true
---

# SKILL: hunt-ssrf

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

**grep = CANDIDATES only.** Never submit from a grep match alone. Issue all greps of a step together in one turn.

---

## FLOW VERIFICATION PROTOCOL — run for every candidate before submitting

For each grep match:

**a.** `get_code_snippet("containing_function_or_class")` — read the full enclosing function.

**b.** Identify variable `URL` passed to the HTTP client call.

**c.** Trace URL's origin:
- Hardcoded string literal / config constant / env var → **SKIP**
- User-supplied: `request.args/body/form/GET/POST/json/params`, path param, or header value → **CONTINUE**
- Unclear → `trace_path("function_name", mode="data_flow", direction="inbound")` upstream until you find the source; if still unclear, **submit with confidence=5** (uncertain is not safe)

**d.** Check for URL validation between source and HTTP call:
- Allowlist host check (`url.host in ALLOWED_HOSTS`, `startswith("https://api.example.com/")`) → **SKIP**
- `urlparse(url).netloc == expected` comparison → **SKIP**
- No host validation, or blocklist-only (bypassable via DNS rebinding / IPv6 / redirects) → **SUBMIT**

**Submit only when confirmed**: name the function, the user-input variable, and the missing guard (e.g. `params["webhook_url"] flows into requests.get in process_webhook() with no host allowlist`).

---

---

## Step 1 — SSRF: Python (requests / httpx / urllib)

**requests with user-controlled URL:**
```
grep(pattern="(requests|session)\.\w+\s*\(.*request\.(args|form|json|values|data|GET|POST|query_params)|(requests|session)\.\w+\s*\(\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)+]|f['\"](https?://)?\{|['\"]https?://['\"]\s*\+)", max_matches=20)
```

**httpx / aiohttp / urllib:**
```
grep(pattern="(httpx|client|aiohttp|http)\.(get|post|put|patch|delete|head|request|stream)\s*\(\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)+]|f['\"](https?://)?\{|['\"]https?://['\"]\s*\+)|\burlopen\s*\(\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)+]|f['\"](https?://)?\{|Request\s*\(|.*request\.)|httpx\.\w+\s*\(.*request\.(args|form|json|GET|POST)", max_matches=20)
```

For each: is the URL argument derived from `request.args`, `request.form`, `request.json()`, `request.GET`, or `request.POST`? Allowlist-based validation (`url.startswith("https://api.example.com/")`) is the safe pattern — blocklist approaches are bypassable via redirects or IPv6. An f-string with a fixed scheme and host (`f"https://api.example.com/{id}"`) only controls the path → not SSRF.

→ Submit: violated_invariant="requests/httpx fetches attacker-supplied URL; internal network reachable from server (metadata, Redis, Kubernetes API)", severity=9, confidence=8, exposure="internet", cwe="CWE-918"

---

## Step 2 — SSRF: JavaScript / TypeScript (fetch / axios / node http)

**fetch / axios / got / superagent with request parameter:**
```
grep(pattern="\b(fetch|axios(\.\w+)?|got(\.\w+)?|needle(\.\w+)?|superagent\.\w+|ky(\.\w+)?|request(\.(get|post))?|undici\.request)\s*\(\s*(req\.(query|body|params|headers)|[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)+]|`(https?://)?\$\{|['\"]https?://['\"]\s*\+)|axios\s*\(\s*\{.*\burl\s*:\s*[^'\"\s]", max_matches=20)
```

**Node http.request / https.request with user host:**
```
grep(pattern="https?\.(request|get)\s*\(\s*(\{.*\b(host|hostname)\s*:\s*[^'\"\s,}]|req\.(query|body|params)|[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)+]|`(https?://)?\$\{|new URL\s*\()", max_matches=20)
```

**URL-like request parameters (sources to correlate with the calls above):**
```
grep(pattern="new URL\s*\(\s*req\.|req\.(query|body|params)\.(?i:\w*(url|uri|link|target|webhook|callback|endpoint|src|image|feed|proxy|host)\w*)\b", max_matches=15)
```

Only server-side code (Node / Deno / edge handlers / SSR loaders) is SSRF — a `fetch` that runs in the browser is not.

→ Submit: violated_invariant="Server-side fetch to user-controlled URL; attacker pivots to internal services via cloud metadata or private network", severity=9, confidence=8, exposure="internet", cwe="CWE-918"

---

## Step 3 — SSRF: Java (URL.openConnection / RestTemplate / WebClient)

**java.net.URL with user input:**
```
grep(pattern="new URL\s*\(\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*\)|[\w.]*getParameter\s*\(|\"https?://\"\s*\+)|\w*([Uu]rl|URL)\w*\.open(Connection|Stream)\s*\(|URI\.create\s*\(\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*\)|[\w.]*getParameter\s*\(|\"https?://\"\s*\+)", max_matches=20)
```

**Spring RestTemplate / WebClient:**
```
grep(pattern="\w*[Rr]est\w*\.(getForObject|getForEntity|exchange|postForObject|postForEntity|put|delete|execute|headForHeaders)\s*\(\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)+]|\"https?://\"\s*\+|[\w.]*getParameter)|\.uri\s*\(\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)+]|\"https?://\"\s*\+|URI\.create\s*\(\s*[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*)|WebClient\.(create|builder\s*\(\s*\)\.baseUrl)\s*\(\s*[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*", max_matches=20)
```

**Apache HttpClient / java.net.http:**
```
grep(pattern="new Http(Get|Post|Put|Delete|Head|Patch|Options)\s*\(\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*\)|\"https?://\"\s*\+|.*getParameter)|newBuilder\s*\(\s*URI\.create\s*\(\s*[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*", max_matches=20)
```

→ Submit: violated_invariant="Java HTTP client requests user-supplied URL; SSRF to internal K8s API / cloud metadata (169.254.169.254)", severity=9, confidence=8, exposure="internet", cwe="CWE-918"

---

## Step 4 — SSRF: Go (http.Get / http.NewRequest)

```
grep(pattern="http\.(Get|Head|Post|PostForm)\s*\(\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)]|\"https?://\"\s*\+|fmt\.Sprintf\s*\(\s*\"https?://%|r\.(URL|Form))|http\.NewRequest(WithContext)?\s*\(.*,\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)]|\"https?://\"\s*\+|fmt\.Sprintf\s*\(\s*\"https?://%)|\w*[Cc]lient\.(Get|Head|Post)\s*\(\s*[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)]", file_glob="*.go", max_matches=20)
```

```
grep(pattern="(r\.URL\.Query\(\)\.Get|r\.FormValue|r\.PostFormValue|c\.Query|c\.DefaultQuery|c\.PostForm|c\.Param|c\.QueryParam|c\.FormValue)\s*\(\s*\"(?i:\w*(url|uri|link|target|host|endpoint|webhook|callback|dest|src|feed|proxy|image)\w*)\"", file_glob="*.go", max_matches=20)
```

Correlate: find where the URL variable is assigned (grep result 1) and where its value originates (grep result 2). If the same variable appears in both, it is SSRF.

→ Submit: violated_invariant="Go http.Get/NewRequest with URL from query/form parameter; internal network reachable", severity=9, confidence=7, exposure="internet", cwe="CWE-918"

---

## Step 5 — SSRF: PHP (curl / file_get_contents / fopen)

**curl with user URL:**
```
grep(pattern="curl_setopt\s*\(.*CURLOPT_URL.*\$_(GET|POST|REQUEST|COOKIE)|curl_setopt\s*\(\s*\$\w+\s*,\s*CURLOPT_URL\s*,\s*(\$|\"[^\"]*\$\w|['\"].*['\"]\s*\.\s*\$)|curl_init\s*\(\s*(\$|\"[^\"]*\$\w|['\"].*['\"]\s*\.\s*\$)", max_matches=20)
```

**file_get_contents / fopen / Guzzle with URL:**
```
grep(pattern="\b(file_get_contents|fopen|readfile|file|get_headers|getimagesize|simplexml_load_file|copy)\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE)|\$\w*(?i:url|uri|link|src|target|host|endpoint|feed|image|webhook|callback)\w*\b|['\"]https?://['\"]\s*\.\s*\$)|->request\s*\(\s*['\"]\w+['\"]\s*,\s*\$|->(get|post)\s*\(\s*\$\w*(?i:url|uri|endpoint|link)\w*", max_matches=20)
```

For each `curl_setopt(..., CURLOPT_URL, ...)`: does the URL argument come from `$_GET`, `$_POST`, or a database field that stores user input?

→ Submit: violated_invariant="PHP curl/file_get_contents fetches user-controlled URL; SSRF to internal admin panels, Redis, memcached", severity=9, confidence=9, exposure="internet", cwe="CWE-918"

---

## Step 6 — SSRF: Ruby (Net::HTTP / open-uri / Faraday)

**Net::HTTP / open-uri with params:**
```
grep(pattern="Net::HTTP\.(get|get_response|post_form|start)\s*\(\s*(URI(\.parse)?\s*\(\s*)?(params\[|[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)]|\"[^\"]*#\{)|URI(\.parse)?\s*\(\s*params\[|(^|[^.\w]|Kernel\.)open\s*\(\s*(params\[|[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)])", max_matches=20)
```

**Faraday / HTTParty / RestClient:**
```
grep(pattern="(Faraday|HTTParty|RestClient|HTTP|Excon|Typhoeus)\.(get|post|put|delete|head|request)(\s*\(\s*|\s+)(params\[|[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*(,|\)|$)|\"[^\"]*#\{)|URI\.open\s*\(\s*(params\[|[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*)", max_matches=20)
```

`Kernel#open` / `URI.open` with a user-supplied URL is especially dangerous — it also supports `|command` execution (RCE).

→ Submit: violated_invariant="Ruby HTTP client / open() fetches user-supplied URL; SSRF or RCE via pipe prefix in open()", severity=9, confidence=8, exposure="internet", cwe="CWE-918"

---

## Step 7 — SSRF: C# (HttpClient / WebRequest)

```
grep(pattern="new HttpClient\s*\(\s*\).*(Get|Post|Put|Delete|Send)\w*Async\s*\(\s*[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*|\w*[Cc]lient\w*\.(GetAsync|PostAsync|PutAsync|DeleteAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync|SendAsync)\s*\(\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)]|\$@?\"https?://\{|\"https?://\"\s*\+|new Uri\s*\(\s*[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*)|new HttpRequestMessage\s*\(.*,\s*[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*", max_matches=20)
```

```
grep(pattern="WebRequest\.Create(Http)?\s*\(\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*\)|\"https?://\"\s*\+|\$@?\"https?://\{)|\.Download(String|Data|File)\w*\s*\(\s*[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*", max_matches=20)
```

→ Submit: violated_invariant="C# HttpClient/WebRequest fetches URL derived from request parameter; SSRF to internal .NET services or Azure metadata", severity=9, confidence=8, exposure="internet", cwe="CWE-918"

---

## Step 8 — SSRF: Kotlin (OkHttp / Ktor / Retrofit)

```
grep(pattern="Request\.Builder\s*\(\s*\)\s*\.url\s*\(\s*[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*|\.url\s*\(\s*[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*\)|client\.(get|post|request)\s*(<[^>]*>)?\s*\(\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*|\"https?://\$)", max_matches=20)
```

```
grep(pattern="\bURL\s*\(\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*|\"https?://\$[^\"]*\")\s*\)\.(openConnection|openStream|readText|readBytes)\s*\(", max_matches=20)
```

→ Submit: violated_invariant="Kotlin OkHttp/Ktor fetches attacker-controlled URL; SSRF targeting internal Kubernetes services", severity=9, confidence=7, exposure="internet", cwe="CWE-918"

---

## Step 9 — SSRF: Rust (reqwest / hyper)

```
grep(pattern="reqwest::(blocking::)?get\s*\(\s*(&?[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*|&?format!\s*\(\s*\"https?://\{)|(\w*[Cc]lient\w*|Client::new\s*\(\s*\))\.(get|post|put|delete|head|request)\s*\(\s*(&?[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*|&?format!\s*\(\s*\"https?://\{)", max_matches=20)
```

```
grep(pattern="\.uri\s*\(\s*(&?[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*\)|format!\s*\(\s*\"https?://\{)", file_glob="*.rs", max_matches=15)
```

→ Submit: violated_invariant="Rust reqwest/hyper sends request to URL from user input; SSRF to internal services accessible from the server", severity=9, confidence=7, exposure="internet", cwe="CWE-918"

---

## Step 10 — SSRF: Swift (URLSession / Vapor client)

```
grep(pattern="URL\s*\(\s*string\s*:\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*|\"https?://\x5C\()|\.(dataTask|data|download|downloadTask|bytes)\s*\(\s*(with|from|for)\s*:\s*[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)]", max_matches=20)
```

```
grep(pattern="URLRequest\s*\(\s*url\s*:\s*([\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)]|URL\s*\(\s*string\s*:\s*[^\")\s])|\.client\.(get|post|send)\s*\(\s*(URI\s*\(\s*string\s*:\s*)?[\w.]*([Uu]rl|URL|[Uu]ri|URI|[Ee]ndpoint|[Hh]ost|[Ww]ebhook|[Cc]allback|[Tt]arget|[Ll]ink)\w*\s*[,)]", max_matches=20)
```

For each: is the `url` string derived from user input (query params, JSON body, user settings)? iOS/macOS apps calling SSRF targets from the app server are lower severity than server-side; server-side Swift (Vapor/Hummingbird) is full SSRF.

→ Submit: violated_invariant="Swift URLSession fetches user-controlled URL; SSRF if running server-side, or data exfiltration if client-side", severity=8, confidence=6, exposure="internet", cwe="CWE-918"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
