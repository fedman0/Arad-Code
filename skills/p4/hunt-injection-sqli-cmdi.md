# SKILL: hunt-injection-sqli-cmdi

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

**grep = CANDIDATES only.** Never submit from a grep match alone. Issue all greps of a step together in one turn.

---

## FLOW VERIFICATION PROTOCOL — run for every candidate before submitting

For each grep match:

**a.** `get_code_snippet("containing_function_or_class")` — read the full enclosing function.

**b.** Identify variable `X` passed to the dangerous call (query string, command string, etc.).

**c.** Trace X's origin:
- String literal / constant / config file / env var → **SKIP** (not user-controlled)
- HTTP source: `request.GET/POST/args/body/form/json/params`, URL path param, header, cookie → **CONTINUE**
- Unclear → `trace_path("function_name", mode="data_flow", direction="inbound")` to follow upstream until source is known; if still unclear, **submit with confidence=5** (uncertain is not safe)

**d.** Check for sanitization between source and sink:
- Parameterized query (`cursor.execute("SELECT … WHERE id=%s", (user_id,))`) → **SKIP**
- ORM query builder with bound parameters → **SKIP**
- `shlex.quote()` / array args with no shell → **SKIP**
- Raw string passed directly / `shell=True` → **SUBMIT**

**Submit only when confirmed**: `violated_invariant` must name the specific function, variable, and source (e.g. `req.query.name flows through fmt.Sprintf into db.Query without parameterization in SearchHandler`).

---

---

## Step 1 — SQL injection: Python (Django / SQLAlchemy / raw)

**Django raw / extra:**
```
grep(pattern="\.raw\s*\(\s*f['\"]|\.raw\s*\(.*(\+|['\"]\s*%\s*[\w(]|\.format\s*\()|\.extra\s*\(.*(\+|['\"]\s*%\s*[\w(]|\.format\s*\(|f['\"])|RawSQL\s*\(\s*f['\"]|RawSQL\s*\(.*(\+|['\"]\s*%\s*[\w(]|\.format\s*\()", max_matches=20)
```

**Django cursor execute with string concat / format:**
```
grep(pattern="\.execute(many)?\s*\(\s*f['\"]|\.execute(many)?\s*\(.*(\+|['\"]\s*%\s*[\w(]|\.format\s*\()", max_matches=20)
```

**SQLAlchemy text() with format:**
```
grep(pattern="\btext\s*\(\s*f['\"]|\btext\s*\(.*(\+|['\"]\s*%\s*[\w(]|\.format\s*\()", max_matches=20)
```

For each match: is the variable that enters the query derived from `request.GET`, `request.POST`, `request.json()`, `request.args`, or any other user-supplied source? Parameterized queries (`cursor.execute("...", (var,))`) are safe — flag only string interpolation.

→ Submit: violated_invariant="SQL query built with string concatenation/format from user input; attacker injects arbitrary SQL", severity=10, confidence=8, exposure="internet", cwe="CWE-89"

---

## Step 2 — SQL injection: JavaScript / TypeScript

**Raw db.query with concatenation / template literal:**
```
grep(pattern="\b\w*(db|pool|conn|connection|client|manager|dataSource|queryRunner|repository|Repository)\.(query|execute)\s*\(\s*(['\"`].*['\"`]\s*\+|\w+\s*\+)|\.(query|execute)\s*\(\s*`[^`]*\$\{", max_matches=20)
```

**Knex raw:**
```
grep(pattern="\.(raw|whereRaw|orWhereRaw|havingRaw|orderByRaw|groupByRaw|joinRaw|selectRaw)\s*\(\s*(['\"`].*['\"`]\s*\+|\w+\s*\+|`[^`]*\$\{)", max_matches=20)
```

**Sequelize / Prisma raw query:**
```
grep(pattern="sequelize\.query\s*\(\s*(['\"`].*['\"`]\s*\+|\w+\s*\+|`[^`]*\$\{)|[Ss]equelize\.literal\s*\(\s*(['\"`].*['\"`]\s*\+|\w+\s*\+|`[^`]*\$\{)|\$(queryRawUnsafe|executeRawUnsafe)\s*\(", max_matches=20)
```
Tagged templates (`` prisma.$queryRaw`…${id}` ``, `` sql`…${id}` ``) bind parameters → **SKIP**.

**MongoDB $where with string (NoSQLi):**
```
grep(pattern="['\"]?\$where['\"]?\s*:\s*(\w|['\"`].*(\+|\$\{))", max_matches=20)
```

→ Submit: violated_invariant="SQL/NoSQL query string built from user input via concatenation; attacker controls query structure", severity=10, confidence=8, exposure="internet", cwe="CWE-89" (CWE-943 for $where)

---

## Step 3 — SQL injection: Java (Spring JDBC / Hibernate)

**JdbcTemplate with concatenation:**
```
grep(pattern="\w*[Jj]dbc\w*\.\w+\s*\(\s*(\w+\s*\+|\"[^\"]*\"\s*\+|String\.format\s*\()", max_matches=20)
```

**Plain JDBC Statement / query string building:**
```
grep(pattern="\.(executeQuery|executeUpdate|executeLargeUpdate|prepareStatement|prepareCall|addBatch|execute)\s*\(\s*(\w+\s*\+|\"[^\"]*\"\s*\+|String\.format\s*\()|String\s+\w*([Ss]ql|[Qq]uery|SQL)\w*\s*=\s*\"(?i:select|insert|update|delete|with)\b[^\"]*\"\s*\+", max_matches=20)
```

**Hibernate createQuery / createNativeQuery with concat:**
```
grep(pattern="create(Native|SQL)?Query\s*\(\s*(\w+\s*\+|\"[^\"]*\"\s*\+|String\.format\s*\()", max_matches=20)
```

**PreparedStatementCreatorFactory with variable:**
```
grep(pattern="PreparedStatementCreatorFactory\s*\(\s*\w+\s*\+|PreparedStatementCreatorFactory\s*\(\s*\".*\"\s*\+", max_matches=15)
```

→ Submit: violated_invariant="JDBC/Hibernate query assembled with string concatenation from HTTP parameter; SQLi via [parameter]", severity=10, confidence=8, exposure="internet", cwe="CWE-89"

---

## Step 4 — SQL injection: Go

```
grep(pattern="\.(Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Select|Raw|Where|Order|Joins|Having|Group)\s*\(.*fmt\.Sprintf\s*\(|fmt\.Sprintf\s*\(\s*[\"`](?i:select|insert|update|delete|with)\b[^\"`]*%[svq]", file_glob="*.go", max_matches=20)
```

```
grep(pattern="\.(Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Raw|Where|Order|Joins|Having|Group|Select)\s*\(.*\"\s*\+\s*\w", file_glob="*.go", max_matches=20)
```

→ Submit: violated_invariant="Go db query built via fmt.Sprintf/string concatenation with user input; parameterized query missing", severity=10, confidence=8, exposure="internet", cwe="CWE-89"

---

## Step 5 — SQL injection: PHP

**MySQL / PDO raw:**
```
grep(pattern="(mysql_query|pg_query|sqlite_query)\s*\(\s*(\$\w+\s*,\s*)?(\"[^\"]*\$\w|['\"].*['\"]\s*\.\s*\$)|mysqli_(multi_)?query\s*\(\s*\$\w+\s*,\s*(\"[^\"]*\$\w|['\"].*['\"]\s*\.\s*\$)|->(query|exec|prepare)\s*\(\s*(\"[^\"]*\$\w|['\"].*['\"]\s*\.\s*\$)|\$\w*(sql|query|Sql|Query)\w*\s*\.?=\s*(\"[^\"]*\$\w|['\"].*['\"]\s*\.\s*\$)", file_glob="*.{php,phtml,inc}", max_matches=20)
```

**Laravel raw DB / WordPress:**
```
grep(pattern="DB::(select|statement|raw|unprepared|insert|update|delete)\s*\(\s*(\"[^\"]*\$\w|['\"].*['\"]\s*\.\s*\$)|->(whereRaw|orWhereRaw|selectRaw|orderByRaw|havingRaw|groupByRaw)\s*\(\s*(\"[^\"]*\$\w|['\"].*['\"]\s*\.\s*\$)|\$wpdb->(query|get_results|get_row|get_var|get_col)\s*\(\s*(\"[^\"]*\$\w|['\"].*['\"]\s*\.\s*\$)", file_glob="*.{php,phtml,inc}", max_matches=20)
```

→ Submit: violated_invariant="PHP SQL query with direct variable interpolation; attacker breaks out of query via [param]", severity=10, confidence=8, exposure="internet", cwe="CWE-89"

---

## Step 6 — SQL injection: Ruby (ActiveRecord)

**String interpolation in where / order / find_by_sql:**
```
grep(pattern="\.(where|order|reorder|group|having|joins|select|pluck|from|find_by|exists\?|update_all|delete_all|lock)\s*\(?\s*\"[^\"]*#\{|find_by_sql\s*\(?.*#\{|\.(execute|exec_query|select_all|select_value|select_rows)\s*\(?.*#\{", max_matches=20)
```

**String concatenation:**
```
grep(pattern="\.(where|order|reorder|group|having|joins|select|from|find_by_sql|execute|exec_query)\s*\(?\s*['\"].*['\"]\s*\+\s*\w", max_matches=20)
```

→ Submit: violated_invariant="ActiveRecord query uses Ruby string interpolation #{ } or concatenation with params; bypasses parameterization", severity=10, confidence=8, exposure="internet", cwe="CWE-89"

---

## Step 7 — SQL injection: C# (ADO.NET / Dapper)

```
grep(pattern="new (Sql|OleDb|Npgsql|MySql|Odbc|Sqlite|SQLite|Oracle)Command\s*\(\s*((\$@?|@\$)\"|@?\"[^\"]*\"\s*\+|\w+\s*\+|[Ss]tring\.(Format|Concat)\s*\()|\.CommandText\s*=\s*((\$@?|@\$)\"|@?\"[^\"]*\"\s*\+|\w+\s*\+|[Ss]tring\.(Format|Concat)\s*\()|\.(Query|QueryAsync|QueryFirst\w*|QuerySingle\w*|Execute|ExecuteAsync|ExecuteScalar\w*)(<[^>]*>)?\s*\(\s*((\$@?|@\$)\"|@?\"[^\"]*\"\s*\+)", max_matches=20)
```

→ Submit: violated_invariant="ADO.NET SqlCommand string concatenation with user input; parameterized AddWithValue not used", severity=10, confidence=8, exposure="internet", cwe="CWE-89"

---

## Step 7b — SQL injection: C# (EF Core raw SQL)

```
grep(pattern="FromSqlRaw\s*\(|ExecuteSqlRaw(Async)?\s*\(|ExecuteSqlCommand(Async)?\s*\(|\.SqlQuery(Raw)?(<[^>]*>)?\s*\(", max_matches=20)
```

For each match: read the calling code. Is the `sql` parameter a raw string built with concatenation or string interpolation?
- `FromSqlRaw("SELECT ... WHERE id = " + id)` — string concat → **SUBMIT**
- `FromSqlRaw($"SELECT ... WHERE id = {id}")` — string interpolation → **SUBMIT**
- `FromSqlRaw("SELECT ... WHERE id = {0}", id)` — EF parameterized → **SKIP**
- EF Core `ExecuteSqlCommand($"…{id}")` / `SqlQuery($"…{id}")` with the `$"…"` literal passed directly — binds to the FormattableString overload and is parameterized → **SKIP**; the same string stored in a `string` variable first, or EF6 `Database.SqlQuery` / `ExecuteSqlCommand` with `$"…"` → **SUBMIT**
- `ExecuteSqlRawAsync(sql)` where `sql` is a method parameter → trace caller; if user-controlled → **SUBMIT**

→ Submit: violated_invariant="EF Core FromSqlRaw/ExecuteSqlRaw receives raw string without parameterization; SQL injection via caller-supplied input", severity=10, confidence=7, exposure="internet", cwe="CWE-89"

---

## Step 8 — Command injection: Python

**os.system / os.popen with format/concat:**
```
grep(pattern="os\.(system|popen)\s*\(\s*(f['\"]|\w+\s*\))|os\.(system|popen)\s*\(.*(\+|['\"]\s*%\s*[\w(]|\.format\s*\()", max_matches=20)
```

**subprocess with shell=True and user input:**
```
grep(pattern="\b(run|call|check_call|check_output|Popen)\s*\(.*shell\s*=\s*True|subprocess\.(getoutput|getstatusoutput)\s*\(|subprocess\.(run|call|Popen|check_output)\s*\(\s*f['\"]|^\s*shell\s*=\s*True\s*[,)]", max_matches=20)
```

**asyncio subprocess shell:**
```
grep(pattern="create_subprocess_shell\s*\(\s*(f['\"]|\w+\s*[,)])|create_subprocess_shell\s*\(.*(\+|['\"]\s*%\s*[\w(]|\.format\s*\()|\b(Popen|run|call|check_output|create_subprocess_exec)\s*\(\s*\[?\s*['\"](/bin/)?(ba)?sh['\"]\s*,\s*['\"]-c['\"]", max_matches=20)
```

For each match: does the string passed to `system()` or `shell=True` contain any variable derived from HTTP request data? The safe pattern is `subprocess.run(["cmd", arg], shell=False)`.

→ Submit: violated_invariant="Shell command constructed from user input via f-string or concatenation; arbitrary command execution", severity=10, confidence=8, exposure="internet", cwe="CWE-78"

---

## Step 9 — Command injection: JavaScript / TypeScript / Deno

**child_process exec/spawn with concat:**
```
grep(pattern="(^|[^.\w]|child_process\.|childProcess\.|cp\.|shell\.)(exec|execSync)\s*\((\s*\w+\s*[,)]|.*\+\s*\w)|\b(spawn|spawnSync|execFile|execFileSync)\s*\(.*shell\s*:\s*true|\b(spawn|spawnSync)\s*\(.*['\"](/bin/)?(ba)?sh['\"].*['\"]-c['\"]", file_glob="*.{js,jsx,ts,tsx,mjs,cjs}", max_matches=20)
```

**Deno.run / Deno.Command with user data:**
```
grep(pattern="Deno\.run\s*\(\s*\{.*cmd.*\[.*(req\.|input|param|query|body)|new Deno\.Command\s*\(", max_matches=15)
```

**Template literal in shell command:**
```
grep(pattern="\b(exec|execSync|spawn|spawnSync)\s*\(\s*`[^`]*\$\{", max_matches=20)
```

→ Submit: violated_invariant="Node child_process executes shell with user-controlled string; RCE via shell metacharacter injection", severity=10, confidence=8, exposure="internet", cwe="CWE-78"

---

## Step 10 — Command injection: Go

```
grep(pattern="exec\.Command(Context)?\s*\(.*\"(/bin/|/usr/bin/)?(ba|z)?sh\"\s*,\s*\"-c\"|exec\.Command(Context)?\s*\(.*\"(cmd|cmd\.exe|powershell|powershell\.exe)\"\s*,\s*\"(/[cC]|-Command|-c)\"", max_matches=20)
```

→ Submit: violated_invariant="Go exec.Command passes user input to shell via sh -c; shell injection possible", severity=10, confidence=8, exposure="internet", cwe="CWE-78"

---

## Step 11 — Command injection: PHP

```
grep(pattern="(^|[^>\w$])(system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*(\$|\"[^\"]*\$\w|['\"].*['\"]\s*\.\s*\$)|pcntl_exec\s*\(", file_glob="*.{php,phtml,inc}", max_matches=20)
```

**PHP backtick operator:**
```
grep(pattern="(=|echo|print|return)\s*`[^`]*\$\w", file_glob="*.{php,phtml,inc}", max_matches=15)
```

→ Submit: violated_invariant="PHP shell function receives user-controlled variable; OS command injection via [$_GET/$_POST/cookie]", severity=10, confidence=8, exposure="internet", cwe="CWE-78"

---

## Step 12 — Command injection: Java / Kotlin

**Runtime.exec with concat:**
```
grep(pattern="Runtime\.getRuntime\s*\(\s*\)\.exec\s*\((\s*\w+\s*\)|.*\+|.*['\"](/bin/)?(ba)?sh['\"]|.*['\"]cmd(\.exe)?['\"]|\s*String\.format)", max_matches=20)
```

**ProcessBuilder with user data:**
```
grep(pattern="ProcessBuilder\s*\(.*['\"](/bin/)?(ba|z)?sh['\"].*['\"]-c['\"]|ProcessBuilder\s*\(.*['\"]cmd(\.exe)?['\"].*['\"]/[cC]['\"]|\.command\s*\(.*['\"](/bin/)?(ba)?sh['\"].*['\"]-c['\"]", max_matches=20)
```

**C# Process.Start with concat:**
```
grep(pattern="Process\.Start\s*\(.*(\+|(\$@?|@\$)\"|[Ss]tring\.Format)|new ProcessStartInfo\s*\(.*(\+|(\$@?|@\$)\")|Arguments\s*=\s*.*(\+|(\$@?|@\$)\"|[Ss]tring\.Format)|ManagementClass.*InvokeMethod\s*\(\s*['\"]Create['\"]|\.AddScript\s*\(\s*(\w+\s*[+)]|(\$@?|@\$)\")", max_matches=20)
```

→ Submit: violated_invariant="ProcessBuilder/Runtime.exec/Process.Start passes user-controlled data to shell; RCE", severity=10, confidence=8, exposure="internet", cwe="CWE-78"

---

## Step 13 — Command injection: Rust (Actix-web / Rocket / Hyper)

**Actix / Rocket — Command::new with user param:**
```
grep(pattern="std::process::Command::new\s*\(|Command::new\s*\(.*\).*\.arg\s*\(|Command::new\s*\(.*\).*\.args\s*\(", max_matches=20)
```

```
grep(pattern="Command::new\s*\(\s*\"(/bin/|/usr/bin/)?(ba|z)?sh\"|Command::new\s*\(\s*\"(cmd|cmd\.exe|powershell|powershell\.exe|pwsh)\"", max_matches=15)
```

For each `Command::new`: trace the argument chain. Is any `.arg()` or `.args()` value derived from `web::Query`, `web::Path`, `web::Json`, or `req.match_info()`? Rust does not automatically sanitize — untrusted args reach the process directly.

→ Submit: violated_invariant="std::process::Command receives user-controlled argument; RCE without shell interpretation still runs attacker-chosen binary/flags", severity=10, confidence=8, exposure="internet", cwe="CWE-78"

---

## Step 14 — Command injection: Ruby (shell delegation)

```
grep(pattern="\b(system|exec|spawn)\s*\(?\s*\"[^\"]*#\{|\b(system|exec|spawn)\s*\(.*params\[|`[^`]*#\{|(Open3\.\w+|IO\.popen|PTY\.spawn)\s*\(\s*(\"[^\"]*#\{|.*params\[)", max_matches=20)
```

```
grep(pattern="%x[\{\(\[][^\}\)\]]*#\{|Kernel\.(system|exec|spawn|open)\s*\(.*(params|#\{)|IO\.popen\s*\(.*(params|#\{)|\bopen\s*\(\s*\"\|", max_matches=20)
```

→ Submit: violated_invariant="Ruby system/exec/backtick receives user params; RCE via shell metacharacter injection", severity=10, confidence=8, exposure="internet", cwe="CWE-78"

---

## Step 15 — SQL injection: Kotlin (JPA / Spring JDBC)

```
grep(pattern="(createNativeQuery|createQuery|\.query|\.queryForObject|\.queryForList|\.update|\.execute|\bexec)\s*\(\s*(\"[^\"]*\$(\{|[A-Za-z_])|\"[^\"]*\"\s*\+|\w+\s*\+)", file_glob="*.{kt,kts}", max_matches=20)
```

```
grep(pattern="\w*[Jj]dbc\w*\.\w+\s*\(\s*(\"[^\"]*\$(\{|[A-Za-z_])|[^,]*\+)", file_glob="*.{kt,kts}", max_matches=15)
```

Kotlin string templates (`"… $name"`, `"… ${user.id}"`) are plain string concatenation, not bind parameters; `$1` / `:name` / `?` placeholders are safe.

→ Submit: violated_invariant="Kotlin JPA/JdbcTemplate query built with string concat from user input; SQL injection", severity=10, confidence=8, exposure="internet", cwe="CWE-89"

---

## Step 16 — SQL injection: Scala (Slick / Doobie / Anorm / JDBC)

```
grep(pattern="(sql|sqlu|tsql)\"[^\"]*#\$|Fragment\.const0?\s*\(|SQL\s*\(\s*s\"|s\"(?i:select|insert|update|delete)\b[^\"]*\$", max_matches=20)
```

```
grep(pattern="(createNativeQuery|createQuery|execute|executeQuery|executeUpdate|prepareStatement)\s*\(\s*(s\"|\w+\s*\+|\"[^\"]*\"\s*\+)", file_glob="*.scala", max_matches=15)
```

Doobie `sql"…$x"` / `fr"…$x"`, Slick `sql"…$x"` / `sqlu"…$x"` and Anorm `SQL"…$x"` bind `$x` as a JDBC parameter → **SKIP**. Vulnerable: Slick `#$x` / `#${x}` (spliced literally), Doobie `Fragment.const(userString)`, Anorm `SQL(s"…$x")`, and any plain `s"…"` string handed to JDBC/JPA.

→ Submit: violated_invariant="Scala SQL built by literal splicing (#$, Fragment.const, s-interpolator) of user input; SQL injection", severity=10, confidence=8, exposure="internet", cwe="CWE-89"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
