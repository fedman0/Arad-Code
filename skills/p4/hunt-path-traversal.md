# SKILL: hunt-path-traversal

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

**grep = CANDIDATES only.** Never submit from a grep match alone.

---

## FLOW VERIFICATION PROTOCOL — run for every candidate before submitting

For each grep match:

**a.** `get_code_snippet("containing_function_or_class")` — read the full enclosing function.

**b.** Identify variable `F` used as a path component (filename, directory, etc.).

**c.** Trace F's origin:
- Hardcoded literal / internal constant / config → **SKIP**
- User-supplied: request param, query string, path variable, URL segment, form field → **CONTINUE**
- Unclear → `trace_path("function_name", mode="data_flow")` upstream

**d.** Check for path sanitization after source:
- `os.path.realpath(joined)` followed by `startswith(base_dir)` check → **SKIP**
- `filepath.EvalSymlinks` + prefix check (Go) → **SKIP**
- `Path.GetFullPath` + `StartsWith` (C#) → **SKIP**
- `basename` only (strips directory but not dangerous enough) → **SUBMIT** (bypassable with null bytes in some languages)
- No sanitization, `os.path.join` with absolute-path injection, `include`/`require` → **SUBMIT**

**Critical**: `os.path.join("/base", "/etc/passwd")` returns `/etc/passwd` in Python — absolute path in second arg silently overrides base. Always flag this.

**Submit only when confirmed**: name the function, the path variable, and proof it is user-controlled (e.g. `request.args["file"] reaches os.open via os.path.join in download_handler without realpath check`).

---

---

## Step 1 — Path traversal: Python (Flask / Django / FastAPI)

**Flask send_file / open with user path:**
```
grep(pattern="send_file\s*\(\s*\w*[Ff]ile\w*\s*[,)]|send_from_directory\s*\(.*request\.(args|form)|open\s*\(\s*\w*[Ff]ile\w*\s*,\s*['\"]r", max_matches=20)
```

**os.path.join with user-controlled component:**
```
grep(pattern="os\.path\.join\s*\(.*request\.(args|form|GET|POST|json)\b|os\.path\.join\s*\(.*params\[|pathlib\.Path\s*\(.*\)\s*/\s*\w*[Ff]ile", max_matches=20)
```

Critical: `os.path.join("/safe/base", "/etc/passwd")` returns `/etc/passwd` — absolute-path injection bypasses the base directory entirely. Use `os path.realpath()` and verify the result starts with the base dir.

→ Submit: violated_invariant="os.path.join/open/send_file with user-supplied component; path traversal reads arbitrary files including /etc/passwd, private keys", severity=9, confidence=8, exposure="internet"

---

## Step 2 — Path traversal: JavaScript / TypeScript (Node.js)

**fs.readFile / readFileSync with user param:**
```
grep(pattern="fs\.readFile\s*\(\s*path\.join\s*\(.*req\.(query|body|params)|fs\.readFileSync\s*\(\s*path\.join\s*\(.*req\.(query|body|params)|fs\.\w+\s*\(\s*req\.(query|body|params)", max_matches=20)
```

**Express res.sendFile / download:**
```
grep(pattern="res\.sendFile\s*\(\s*req\.(query|body|params)|res\.download\s*\(\s*req\.(query|body|params)|res\.sendFile\s*\(\s*path\.join\s*\(.*req\.", max_matches=20)
```

**Deno file read:**
```
grep(pattern="Deno\.readTextFile\s*\(\s*\w*[Ff]ile\w*\s*\)|Deno\.open\s*\(\s*req\.", max_matches=15)
```

→ Submit: violated_invariant="Node fs.readFile/sendFile uses req.query/body without realpath validation; ../../../etc/passwd traversal to read server files", severity=9, confidence=8, exposure="internet"

---

## Step 3 — Path traversal: Java / Kotlin (Spring / Jakarta EE)

**File / Paths.get with user input:**
```
grep(pattern="new File\s*\(\s*\w*[Bb]ase\w*,\s*\w*[Ff]ile\w*\s*\)|Paths\.get\s*\(\s*\w*[Bb]ase\w*,\s*\w*[Ff]ile\w*\s*\)|Files\.readAllBytes\s*\(\s*Paths\.get\s*\(", max_matches=20)
```

**Spring ResourceLoader / ClassPathResource:**
```
grep(pattern="ResourceLoader.*getResource\s*\(.*getParameter|ClassPathResource\s*\(\s*\w*[Ff]ile\w*\s*\)|FileSystemResource\s*\(\s*\w*[Ff]ile\w*\s*\)", max_matches=20)
```

For each `new File(baseDir, userInput)`: verify `file.getCanonicalPath().startsWith(baseDir.getCanonicalPath())` is called and throws/returns error if false.

→ Submit: violated_invariant="Java File/Paths.get with user-supplied filename without canonical path check; path traversal to read app config, keys, source", severity=9, confidence=8, exposure="internet"

---

## Step 4 — Path traversal: Go

**os.Open / os.ReadFile with user filename:**
```
grep(pattern="os\.Open\s*\(\s*filepath\.Join\s*\(.*r\.(URL|Form|PostForm)|os\.ReadFile\s*\(\s*filepath\.Join\s*\(.*r\.|ioutil\.ReadFile\s*\(\s*filepath\.Join\s*\(.*r\.", max_matches=20)
```

**http.FileServer without StripPrefix / validation:**
```
grep(pattern="http\.ServeFile\s*\(\s*w,\s*r,\s*filepath\.Join\s*\(.*r\.(URL\.Query|FormValue)|http\.ServeFile\s*\(\s*w,\s*r,\s*\w+\s*\+", max_matches=20)
```

After `filepath.Join`, always call `filepath.EvalSymlinks` then verify the result has the expected prefix with `strings.HasPrefix(resolved, allowedBase)`.

→ Submit: violated_invariant="Go filepath.Join with user query param without realpath check; ../../../etc/passwd bypasses expected base directory", severity=9, confidence=7, exposure="internet"

---

## Step 5 — Path traversal: PHP

**Direct path construction with $_GET/$_POST:**
```
grep(pattern="file_get_contents\s*\(\s*['\"][^'\"]*['\"].*\.\s*\\\$_(GET|POST|REQUEST|COOKIE)|include\s+\\\$_(GET|POST|REQUEST)|require\s+\\\$_(GET|POST|REQUEST)", max_matches=20)
```

**readfile / fopen with user input:**
```
grep(pattern="readfile\s*\(\s*\\\$_(GET|POST|REQUEST)|fopen\s*\(\s*\\\$_(GET|POST|REQUEST)|file\s*\(\s*\\\$_(GET|POST|REQUEST)", max_matches=20)
```

PHP `include`/`require` with user input is doubly dangerous: traversal + LFI → potential RCE via log poisoning or PHP session file.

→ Submit: violated_invariant="PHP include/file_get_contents with user path; LFI via ../../../../etc/passwd, or RCE via log/session file inclusion", severity=10, confidence=9, exposure="internet"

---

## Step 6 — Path traversal: Ruby (Rails / Sinatra)

**send_file / File.read with params:**
```
grep(pattern="send_file\s*\(\s*params\[|send_file\s*\(\s*File\.join\s*\(.*params\[|File\.read\s*\(\s*params\[|IO\.read\s*\(\s*params\[", max_matches=20)
```

**Rails render file:**
```
grep(pattern="render\s+file\s*:\s*params\[|render\s+:file\s*=>\s*params\[|Pathname\.new\s*\(\s*\w*\s*\)\s*\+\s*params\[", max_matches=20)
```

→ Submit: violated_invariant="Rails send_file/File.read with params; path traversal to read Gemfile, database.yml, credentials", severity=9, confidence=8, exposure="internet"

---

## Step 7 — Path traversal: C# (ASP.NET / .NET Core)

**Path.Combine with user input:**
```
grep(pattern="Path\.Combine\s*\(.*Request\.(Query|Form|QueryString|Params)|Path\.Combine\s*\(\s*\w*[Bb]ase\w*,\s*\w*[Ff]ile\w*\s*\)|File\.ReadAllText\s*\(\s*Path\.Combine", max_matches=20)
```

**File.ReadAllBytes / File.Open:**
```
grep(pattern="File\.ReadAllBytes\s*\(\s*\w*[Ff]ile\w*\s*\)|File\.Open\s*\(\s*\w*[Ff]ile\w*\s*,|PhysicalFile\s*\(\s*\w*[Ff]ile\w*", max_matches=20)
```

`Path.Combine(root, "../secret")` returns the traversed path in .NET. Use `Path.GetFullPath(combined).StartsWith(Path.GetFullPath(root))`.

→ Submit: violated_invariant="C# Path.Combine/File.ReadAllBytes with user input; traversal bypasses root restriction to read web.config, appsettings.json", severity=9, confidence=8, exposure="internet"

---

## Step 8 — Path traversal: Rust (Actix / Rocket)

```
grep(pattern="std::fs::read_to_string\s*\(\s*Path::new\s*\(.*\)\.join\s*\(|std::fs::File::open\s*\(\s*\w*[Pp]ath\w*\s*\)|tokio::fs::read_to_string\s*\(\s*\w*[Pp]ath\w*\s*\)", max_matches=20)
```

```
grep(pattern="PathBuf::from\s*\(\s*\w*[Bb]ase\w*\s*\)\.join\s*\(\s*\w*[Ff]ile\w*\s*\)|std::path::Path::new\s*\(.*\)\.join\s*\(\s*\w*[Ff]ile", max_matches=20)
```

For each `.join(userInput)`: is `canonicalize()` called and does the result start with the expected base? Rust's type system does not prevent traversal — only logic checks do.

→ Submit: violated_invariant="Rust PathBuf::join with user-supplied component; ../../../etc/passwd traversal bypasses PathBuf base without canonicalize check", severity=9, confidence=7, exposure="internet"

---

## Step 9 — Path traversal: Swift (Vapor / Hummingbird server-side)

```
grep(pattern="URL\s*\(\s*fileURLWithPath\s*:\s*\w*[Bb]ase\w*\s*\)\.appendingPathComponent\s*\(\s*\w*[Ff]ile\w*\s*\)|FileManager\.default\.contents\s*\(\s*atPath\s*:\s*\w*[Ff]ile", max_matches=20)
```

```
grep(pattern="String\s*\(\s*contentsOfFile\s*:\s*\w*[Ff]ile|Data\s*\(\s*contentsOf\s*:\s*URL\s*\(\s*fileURLWithPath\s*:\s*\w*[Ff]ile", max_matches=20)
```

→ Submit: violated_invariant="Swift appendingPathComponent/contentsOfFile with user param; path traversal in server-side Swift reads arbitrary server files", severity=9, confidence=6, exposure="internet"

---

## Step 10 — Zip Slip (archive traversal): all languages

**Python zipfile:**
```
grep(pattern="zipfile\.ZipFile\s*\(|\.extract\s*\(\s*\w+,\s*\w*[Pp]ath\w*\s*\)|\.extractall\s*\(\s*\w*[Pp]ath\w*\s*\)", max_matches=20)
```

**Java ZipEntry:**
```
grep(pattern="new ZipInputStream\s*\(|zipEntry\.getName\s*\(\s*\)|new File\s*\(\s*\w*[Dd]est\w*,\s*zipEntry\.getName", max_matches=20)
```

**Go archive/zip:**
```
grep(pattern="zip\.OpenReader\s*\(|zipFile\.Open\s*\(\s*\)|zip\.NewReader\s*\(", max_matches=20)
```

**Node (adm-zip / extract-zip):**
```
grep(pattern="AdmZip\s*\(|\.extractAllTo\s*\(|extract\s*\(\s*\w*[Zz]ip\w*,\s*\w*[Dd]est", max_matches=20)
```

For each archive extraction: is the extracted entry name checked for `..` components before being joined with the destination path? The canonical check: `resolved = path.realpath(os.path.join(dest, entry)); assert resolved.startswith(os.path.realpath(dest))`.

→ Submit: violated_invariant="Archive extraction joins entry name with dest path without traversal check; Zip Slip overwrites arbitrary files including authorized_keys, cron jobs, app binaries", severity=9, confidence=8, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
