---
parallel: true
---

# SKILL: hunt-path-traversal

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

**grep = CANDIDATES only.** Never submit from a grep match alone. Issue all greps of a step together in one turn.

---

## FLOW VERIFICATION PROTOCOL — run for every candidate before submitting

For each grep match:

**a.** `get_code_snippet("containing_function_or_class")` — read the full enclosing function.

**b.** Identify variable `F` used as a path component (filename, directory, etc.).

**c.** Trace F's origin:
- Hardcoded literal / internal constant / config → **SKIP**
- User-supplied: request param, query string, path variable, URL segment, form field, uploaded file name → **CONTINUE**
- Unclear → `trace_path("function_name", mode="data_flow", direction="inbound")` upstream; if still unclear, **submit with confidence=5** (uncertain is not safe)

**d.** Check for path sanitization after source:
- `os.path.realpath(joined)` followed by `startswith(base_dir)` check → **SKIP**
- `filepath.EvalSymlinks` + prefix check, `filepath.IsLocal` (Go 1.20+) or `os.Root` / `os.OpenInRoot` (Go 1.24+) → **SKIP**
- `Path.GetFullPath` + `StartsWith` (C#) → **SKIP**
- `basename` only (`os.path.basename`, `path.basename`, `filepath.Base`, `Path.GetFileName`, `File#getName`) applied to the user value before joining → **SKIP** (it strips every directory component; null-byte truncation does not work on modern runtimes)
- No sanitization, `os.path.join` with absolute-path injection, `include`/`require` → **SUBMIT**

**Critical**: `os.path.join("/base", "/etc/passwd")` returns `/etc/passwd` in Python — absolute path in second arg silently overrides base. Always flag this.

**Submit only when confirmed**: name the function, the path variable, and proof it is user-controlled (e.g. `request.args["file"] reaches os.open via os.path.join in download_handler without realpath check`).

---

---

## Step 1 — Path traversal: Python (Flask / Django / FastAPI)

**Flask send_file / open with user path:**
```
grep(pattern="send_file\s*\(\s*([^'\")\s]|['\"].*['\"]\s*\+)|FileResponse\s*\(\s*[^'\")\s]|\bopen\s*\(\s*([\w.]*(?i:file|name|path)\w*\s*[,)]|os\.path\.join\s*\(|f['\"]|['\"][^'\"]*['\"]\s*\+)", max_matches=20)
```

**os.path.join / pathlib with user-controlled component:**
```
grep(pattern="os\.path\.join\s*\(.*(request\.(args|form|GET|POST|json|values|files|query_params)|params\[|,\s*[\w.]*(?i:file|name|path)\w*\s*\))|(Path\s*\([^)]*\)|\w*(?i:dir|root|base|folder))\s*/\s*[\w.]*(?i:file|name|path)\w*", max_matches=20)
```

Critical: `os.path.join("/safe/base", "/etc/passwd")` returns `/etc/passwd` — absolute-path injection bypasses the base directory entirely. Use `os.path.realpath()` and verify the result starts with the base dir. Flask `send_from_directory()` / `werkzeug.utils.safe_join()` reject traversal → **SKIP**.

→ Submit: violated_invariant="os.path.join/open/send_file with user-supplied component; path traversal reads arbitrary files including /etc/passwd, private keys", severity=9, confidence=8, exposure="internet", cwe="CWE-22"

---

## Step 2 — Path traversal: JavaScript / TypeScript (Node.js)

**fs.readFile / readFileSync with user param:**
```
grep(pattern="\b(fs|fsp|fse|fsPromises)(\.promises)?\.\w+\s*\(\s*(req\.(query|body|params)|path\.(join|resolve)\s*\(.*(req\.(query|body|params)|,\s*[\w.]*(?i:file|name|path)\w*\s*\))|`[^`]*\$\{\s*(req\.|[\w.]*(?i:file|name|path))|['\"][^'\"]*['\"]\s*\+\s*(req\.|[\w.]*(?i:file|name|path)))", max_matches=20)
```

**Express res.sendFile / download:**
```
grep(pattern="res\.(sendFile|download|attachment)\s*\(\s*(req\.|path\.(join|resolve)\s*\(.*(req\.|,\s*[\w.]*(?i:file|name|path)\w*\s*\))|`[^`]*\$\{|[\w.]*(?i:file|name|path)\w*\s*[,)])", max_matches=20)
```
`res.sendFile(name, { root: dir })` — `send` rejects `..` that escapes `root` → **SKIP**.

**Deno file read:**
```
grep(pattern="Deno\.(readTextFile|readFile|open|readTextFileSync|readFileSync|remove|writeTextFile|writeFile)\s*\(\s*([^'\"`)\s]|`[^`]*\$\{)", max_matches=15)
```

→ Submit: violated_invariant="Node fs.readFile/sendFile uses req.query/body without realpath validation; ../../../etc/passwd traversal to read server files", severity=9, confidence=8, exposure="internet", cwe="CWE-22"

---

## Step 3 — Path traversal: Java / Kotlin (Spring / Jakarta EE)

**File / Paths.get with user input:**
```
grep(pattern="new File\s*\(\s*[^,()]+,\s*[\w.]*(?i:file|name|path)\w*(\(\))?\s*\)|new File\s*\(.*\+\s*[\w.]*(?i:file|name|path)|(Paths\.get|Path\.of)\s*\(\s*[^,()]+,\s*[\w.]*(?i:file|name|path)\w*(\(\))?\s*\)|\.resolve\s*\(\s*[\w.]*(?i:file|name|path)\w*(\(\))?\s*\)|(new File(InputStream|OutputStream|Reader|Writer)?|Paths\.get|Path\.of)\s*\(.*getParameter\s*\(", max_matches=20)
```

**Spring ResourceLoader / ClassPathResource:**
```
grep(pattern="[Rr]esource[Ll]oader\.getResource\s*\(\s*([^\")\s]|\"[^\"]*\"\s*\+)|new (ClassPathResource|FileSystemResource|UrlResource|PathResource|FileUrlResource)\s*\(\s*([^\")\s]|\"[^\"]*\"\s*\+)", max_matches=20)
```

For each `new File(baseDir, userInput)`: verify `file.getCanonicalPath().startsWith(baseDir.getCanonicalPath())` is called and throws/returns error if false. `MultipartFile.getOriginalFilename()` is attacker-controlled.

→ Submit: violated_invariant="Java File/Paths.get with user-supplied filename without canonical path check; path traversal to read app config, keys, source", severity=9, confidence=8, exposure="internet", cwe="CWE-22"

---

## Step 4 — Path traversal: Go

**os.Open / os.ReadFile with user filename:**
```
grep(pattern="(os\.(Open|OpenFile|ReadFile|Create|Remove|RemoveAll|WriteFile)|ioutil\.(ReadFile|WriteFile))\s*\(\s*((file)?path\.Join\s*\(.*(r\.(URL|Form|PostForm|FormValue)|c\.(Param|Query|PostForm)|,\s*[\w.]*(?i:file|name|path)\w*\s*\))|\w+\s*\+|\"[^\"]*\"\s*\+)", file_glob="*.go", max_matches=20)
```

**http.ServeFile / gin c.File with user path:**
```
grep(pattern="http\.ServeFile\s*\(\s*\w+\s*,\s*\w+\s*,\s*((file)?path\.Join\s*\(.*(r\.(URL\.Query|FormValue|PostFormValue)|,\s*[\w.]*(?i:file|name|path)\w*\s*\))|\w+\s*\+|\"[^\"]*\"\s*\+|r\.(URL\.Query|FormValue))|c\.File\s*\(\s*(filepath\.Join\s*\(.*)?c\.(Param|Query)", file_glob="*.go", max_matches=20)
```

After `filepath.Join`, always call `filepath.EvalSymlinks` then verify the result has the expected prefix with `strings.HasPrefix(resolved, allowedBase)`. `filepath.Join("/base", "../../etc/passwd")` cleans to `/etc/passwd`.

→ Submit: violated_invariant="Go filepath.Join with user query param without realpath check; ../../../etc/passwd bypasses expected base directory", severity=9, confidence=7, exposure="internet", cwe="CWE-22"

---

## Step 5 — Path traversal: PHP

**include / require / file_get_contents with user input:**
```
grep(pattern="(include|require)(_once)?\s*\(?\s*(\$_(GET|POST|REQUEST|COOKIE)|['\"][^'\"]*['\"]\s*\.\s*\$|\"[^\"]*\$\w|\$\w+\s*[;).])|file_get_contents\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE)|['\"][^'\"]*['\"]\s*\.\s*\$|\"[^\"]*\$\w|\$\w*(?i:file|name|path|page|doc|template)\w*\s*\))", file_glob="*.{php,phtml,inc}", max_matches=20)
```

**readfile / fopen / unlink with user input:**
```
grep(pattern="\b(readfile|fopen|file|unlink|file_put_contents|copy|rename|fpassthru|show_source|highlight_file|parse_ini_file)\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE)|['\"][^'\"]*['\"]\s*\.\s*\$|\"[^\"]*\$\w|\$\w*(?i:file|name|path)\w*\s*[,)])|new SplFileObject\s*\(\s*\$", file_glob="*.{php,phtml,inc}", max_matches=20)
```

PHP `include`/`require` with user input is doubly dangerous: traversal + LFI → potential RCE via log poisoning or PHP session file.

→ Submit: violated_invariant="PHP include/file_get_contents with user path; LFI via ../../../../etc/passwd, or RCE via log/session file inclusion", severity=10, confidence=9, exposure="internet", cwe="CWE-22" (CWE-98 for include/require)

---

## Step 6 — Path traversal: Ruby (Rails / Sinatra)

**send_file / File.read with params:**
```
grep(pattern="(send_file|send_data|File\.(read|open|new|readlines|binread|delete|write)|IO\.(read|readlines|binread)|FileUtils\.\w+)\s*\(?\s*(params\[|\"[^\"]*#\{\s*params|(File|Rails\.root|Pathname\.new\s*\([^)]*\))\.join\s*\(.*params\[)", max_matches=20)
```

**Rails render file / dynamic render path:**
```
grep(pattern="render\s*\(?\s*(file\s*:|:file\s*=>|template\s*:|partial\s*:)?\s*params\[|Pathname\.new\s*\([^)]*\)\s*\+\s*params\[", max_matches=20)
```

→ Submit: violated_invariant="Rails send_file/File.read with params; path traversal to read Gemfile, database.yml, credentials", severity=9, confidence=8, exposure="internet", cwe="CWE-22"

---

## Step 7 — Path traversal: C# (ASP.NET / .NET Core)

**Path.Combine with user input:**
```
grep(pattern="Path\.Combine\s*\(.*(Request\.(Query|Form|QueryString|Params|RouteValues)|,\s*[\w.]*(?i:file|name|path)\w*\s*\))|Path\.Join\s*\(.*,\s*[\w.]*(?i:file|name|path)\w*\s*\)", max_matches=20)
```

**File.ReadAllBytes / File.Open / PhysicalFile:**
```
grep(pattern="File\.(ReadAllBytes|ReadAllText|ReadAllLines|Open|OpenRead|OpenWrite|Create|Delete|WriteAllBytes|WriteAllText|Copy|Move)\s*\(\s*([\w.]*(?i:file|name|path)\w*\s*[,)]|(\$@?|@\$)\"|\"[^\"]*\"\s*\+)|PhysicalFile\s*\(\s*([\w.]*(?i:file|name|path)\w*\s*[,)]|Path\.Combine)|new FileStream\s*\(\s*[\w.]*(?i:file|name|path)", max_matches=20)
```

`Path.Combine(root, "../secret")` returns the traversed path in .NET, and an absolute second argument (`C:\…`, `/etc/…`) discards `root` entirely. `IFormFile.FileName` is attacker-controlled. Use `Path.GetFullPath(combined).StartsWith(Path.GetFullPath(root))`.

→ Submit: violated_invariant="C# Path.Combine/File.ReadAllBytes with user input; traversal bypasses root restriction to read web.config, appsettings.json", severity=9, confidence=8, exposure="internet", cwe="CWE-22"

---

## Step 8 — Path traversal: Rust (Actix / Rocket)

```
grep(pattern="(fs::(read|read_to_string|write|remove_file|remove_dir_all|copy|rename)|File::(open|create))\s*\(\s*(&?[\w.]*(?i:file|name|path)\w*\s*\)|format!\s*\(|&?\w+\.join\s*\(|Path::new\s*\(.*\)\.join)|NamedFile::open\s*\(", max_matches=20)
```

```
grep(pattern="(PathBuf::from|Path::new)\s*\([^)]*\)\.join\s*\(\s*&?[^\")\s]|\w*(?i:dir|root|base|folder)\w*\.join\s*\(\s*&?[\w.]*(?i:file|name|path)", file_glob="*.rs", max_matches=20)
```

For each `.join(userInput)`: is `canonicalize()` called and does the result start with the expected base? Rust's type system does not prevent traversal — only logic checks do; `Path::join` with an absolute argument replaces the base entirely. A Rocket `PathBuf` route segment (`FromSegments`) already rejects `..` → **SKIP**.

→ Submit: violated_invariant="Rust PathBuf::join with user-supplied component; ../../../etc/passwd traversal bypasses PathBuf base without canonicalize check", severity=9, confidence=7, exposure="internet", cwe="CWE-22"

---

## Step 9 — Path traversal: Swift (Vapor / Hummingbird server-side)

```
grep(pattern="\.appendingPathComponent\s*\(\s*([^\")\s]|\"[^\"]*\x5C\()|\.appending\s*\(\s*(path|component)\s*:\s*[^\")\s]|FileManager\.default\.(contents|removeItem|createFile|copyItem|moveItem)\s*\(\s*atPath\s*:\s*[^\")\s]|streamFile\s*\(\s*at\s*:\s*[^\")\s]", max_matches=20)
```

```
grep(pattern="String\s*\(\s*contentsOfFile\s*:\s*[^\")\s]|Data\s*\(\s*contentsOf\s*:\s*(URL\s*\(\s*fileURLWithPath\s*:\s*[^\")\s]|[a-z_]\w*\s*[,)])|FileHandle\s*\(\s*forReadingAtPath\s*:\s*[^\")\s]", max_matches=20)
```

→ Submit: violated_invariant="Swift appendingPathComponent/contentsOfFile with user param; path traversal in server-side Swift reads arbitrary server files", severity=9, confidence=6, exposure="internet", cwe="CWE-22"

---

## Step 10 — Zip Slip (archive traversal): all languages

**Python tarfile / manual extraction:**
```
grep(pattern="tarfile\.open\s*\(|tarfile\.TarFile\s*\(|\.extractall\s*\(|shutil\.unpack_archive\s*\(|os\.path\.join\s*\([^)]*(\.filename|\.name|member|entry)\b", max_matches=20)
```
Python `zipfile.ZipFile.extract()` / `extractall()` strip `..` and absolute names → **SKIP**. `tarfile` `extract()` / `extractall()` (and `shutil.unpack_archive` of a tar) without `filter="data"` (or `"tar"`) follow `../` names, absolute paths and links on Python < 3.14 (3.12/3.13 only emit a DeprecationWarning) → **SUBMIT** for untrusted archives. Also flag code that writes `ZipInfo.filename` / `TarInfo.name` itself via `open(os.path.join(dest, name), "wb")`.

**Java ZipEntry:**
```
grep(pattern="new ZipInputStream\s*\(|new ZipFile\s*\(|new (TarArchiveInputStream|ZipArchiveInputStream|JarInputStream)\s*\(|\w*[Ee]ntry\w*\.getName\s*\(\s*\)", max_matches=20)
```

**Go archive/zip / archive/tar:**
```
grep(pattern="zip\.(OpenReader|NewReader)\s*\(|tar\.NewReader\s*\(|filepath\.Join\s*\([^)]*\.Name\s*\)", max_matches=20)
```

**Node (adm-zip / extract-zip / unzipper / tar):**
```
grep(pattern="new AdmZip\s*\(|\.extractAllTo\s*\(|\.extractEntryTo\s*\(|unzipper\.(Extract|Parse)\s*\(|\bdecompress\s*\(|tar\.(x|extract)\s*\(|extract\s*\(\s*\w*[Zz]ip\w*\s*,|path\.join\s*\([^)]*\.(entryName|path|fileName)\s*\)", max_matches=20)
```
Current adm-zip (≥ 0.4.11), extract-zip/yauzl and node-tar reject `..` entries — check the installed version in package-lock.json; hand-written loops that join `entry.entryName` / `entry.path` with the destination are the usual finding.

For each archive extraction: is the extracted entry name checked for `..` components before being joined with the destination path? The canonical check: `resolved = path.realpath(os.path.join(dest, entry)); assert resolved.startswith(os.path.realpath(dest))`.

→ Submit: violated_invariant="Archive extraction joins entry name with dest path without traversal check; Zip Slip overwrites arbitrary files including authorized_keys, cron jobs, app binaries", severity=9, confidence=8, exposure="internet", cwe="CWE-22"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
