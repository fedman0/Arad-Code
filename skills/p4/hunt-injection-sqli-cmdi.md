# SKILL: hunt-injection-sqli-cmdi

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

Run grep, read context with `get_code_snippet`, submit immediately. 2 tool calls per step max.

---

## Step 1 — SQL injection: Python (Django / SQLAlchemy / raw)

**Django raw / extra:**
```
grep(pattern="\.objects\.raw\s*\(\s*\w*\s*[\+%]|objects\.extra\s*\(.*where.*format\s*\(|RawSQL\s*\(.*format\s*\(|RawSQL\s*\(.*\+|RawSQL\s*\(.*%\s*\(", max_matches=20)
```

**Django cursor execute with string concat / format:**
```
grep(pattern="cursor\.execute\s*\(.*format\s*\(|cursor\.execute\s*\(.*\+|cursor\.execute\s*\(f['\"]", max_matches=20)
```

**SQLAlchemy text() with format:**
```
grep(pattern="text\s*\(.*format\s*\(|text\s*\(f['\"]|engine\.execute\s*\(.*\+|session\.execute\s*\(.*\+", max_matches=20)
```

For each match: is the variable that enters the query derived from `request.GET`, `request.POST`, `request.json()`, `request.args`, or any other user-supplied source? Parameterized queries (`cursor.execute("...", (var,))`) are safe — flag only string interpolation.

→ Submit: violated_invariant="SQL query built with string concatenation/format from user input; attacker injects arbitrary SQL", severity=10, confidence=8, exposure="internet"

---

## Step 2 — SQL injection: JavaScript / TypeScript

**Raw db.query with concatenation:**
```
grep(pattern="db\.query\s*\(.*\+|pool\.query\s*\(.*\+|connection\.query\s*\(.*\+|client\.query\s*\(.*\+", max_matches=20)
```

**Knex raw:**
```
grep(pattern="knex\.raw\s*\(.*\+|knex\.raw\s*\(.*\$\{|\.whereRaw\s*\(.*\+|\.whereRaw\s*\(.*\$\{", max_matches=20)
```

**Sequelize raw query:**
```
grep(pattern="sequelize\.query\s*\(.*\+|sequelize\.query\s*\(.*\$\{|\.query\s*\(.*type.*QueryTypes", max_matches=20)
```

**MongoDB $where with string (NoSQLi):**
```
grep(pattern="\\\$where\s*:\s*\w+|\\\$where\s*:\s*req\.|\.find\s*\(\s*\{[^}]*\\\$where", max_matches=20)
```

→ Submit: violated_invariant="SQL/NoSQL query string built from user input via concatenation; attacker controls query structure", severity=10, confidence=8, exposure="internet"

---

## Step 3 — SQL injection: Java (Spring JDBC / Hibernate)

**JdbcTemplate with concatenation:**
```
grep(pattern="jdbcTemplate\.(query|queryForObject|queryForList|update|execute)\s*\(\s*\w+\s*\+|jdbcTemplate\.(query|queryForObject)\s*\(\s*\".*\"\s*\+", max_matches=20)
```

**Hibernate createQuery / createNativeQuery with concat:**
```
grep(pattern="createNativeQuery\s*\(.*\+|createQuery\s*\(.*\+|session\.createQuery\s*\(.*\+", max_matches=20)
```

**PreparedStatementCreatorFactory with variable:**
```
grep(pattern="PreparedStatementCreatorFactory\s*\(\s*\w+\s*\+|PreparedStatementCreatorFactory\s*\(\s*\".*\"\s*\+", max_matches=15)
```

→ Submit: violated_invariant="JDBC/Hibernate query assembled with string concatenation from HTTP parameter; SQLi via [parameter]", severity=10, confidence=8, exposure="internet"

---

## Step 4 — SQL injection: Go

```
grep(pattern="db\.Query\s*\(.*fmt\.Sprintf\s*\(|db\.QueryRowContext\s*\(.*fmt\.Sprintf\s*\(|db\.ExecContext\s*\(.*fmt\.Sprintf\s*\(|db\.Exec\s*\(.*fmt\.Sprintf\s*\(", max_matches=20)
```

```
grep(pattern="db\.Query\s*\(.*\+\s*\w+|db\.Exec\s*\(.*\+\s*\w+|gorm\.Where\s*\(.*\+\s*\w+", max_matches=20)
```

→ Submit: violated_invariant="Go db query built via fmt.Sprintf/string concatenation with user input; parameterized query missing", severity=10, confidence=8, exposure="internet"

---

## Step 5 — SQL injection: PHP

**MySQL / PDO raw:**
```
grep(pattern="mysqli_query\s*\(.*\\\$|mysql_query\s*\(.*\\\$|pg_query\s*\(.*\\\$|sqlite_query\s*\(.*\\\$", max_matches=20)
```

**Laravel raw DB:**
```
grep(pattern="DB::select\s*\(.*\\\$|DB::statement\s*\(.*\\\$|DB::raw\s*\(.*\\\$|\\\$wpdb->query\s*\(.*\\\$", max_matches=20)
```

→ Submit: violated_invariant="PHP SQL query with direct variable interpolation; attacker breaks out of query via [param]", severity=10, confidence=8, exposure="internet"

---

## Step 6 — SQL injection: Ruby (ActiveRecord)

**String interpolation in where / find_by_sql:**
```
grep(pattern="\.where\s*\(['\"].*#\{|find_by_sql\s*\(.*#\{|connection\.execute\s*\(.*#\{", max_matches=20)
```

**String concatenation:**
```
grep(pattern="\.where\s*\(.*\+\s*params\[|find_by_sql\s*\(.*\+\s*params|\.where\s*\(\".*\"\s*\+", max_matches=20)
```

→ Submit: violated_invariant="ActiveRecord query uses Ruby string interpolation #{ } or concatenation with params; bypasses parameterization", severity=10, confidence=8, exposure="internet"

---

## Step 7 — SQL injection: C# (ADO.NET)

```
grep(pattern="new SqlCommand\s*\(.*\+|new OleDbCommand\s*\(.*\+|new NpgsqlCommand\s*\(.*\+|ExecuteReader\s*\(\s*CommandBehavior|SqlCommand\s*\(string\.Format", max_matches=20)
```

→ Submit: violated_invariant="ADO.NET SqlCommand string concatenation with user input; parameterized AddWithValue not used", severity=10, confidence=8, exposure="internet"

---

## Step 8 — Command injection: Python

**os.system with format/concat:**
```
grep(pattern="os\.system\s*\(f['\"]|os\.system\s*\(.*\+|os\.system\s*\(.*format\s*\(|os\.system\s*\(.*%\s*\(", max_matches=20)
```

**subprocess with shell=True and user input:**
```
grep(pattern="subprocess\.(run|call|Popen|check_output)\s*\(.*shell\s*=\s*True|subprocess\.(run|call|Popen)\s*\(f['\"]", max_matches=20)
```

**asyncio subprocess shell:**
```
grep(pattern="asyncio\.create_subprocess_shell\s*\(.*\+|asyncio\.create_subprocess_shell\s*\(f['\"]|\bPopen\s*\(.*['\"]sh['\"].*['\"](-c)['\"]", max_matches=20)
```

For each match: does the string passed to `system()` or `shell=True` contain any variable derived from HTTP request data? The safe pattern is `subprocess.run(["cmd", arg], shell=False)`.

→ Submit: violated_invariant="Shell command constructed from user input via f-string or concatenation; arbitrary command execution", severity=10, confidence=8, exposure="internet"

---

## Step 9 — Command injection: JavaScript / TypeScript / Deno

**child_process exec/spawn with concat:**
```
grep(pattern="exec\s*\(.*\+\s*\w+|execSync\s*\(.*\+\s*\w+|spawn\s*\(.*['\"]sh['\"].*['\"](-c)['\"]|spawnSync\s*\(.*['\"]sh['\"]", max_matches=20)
```

**Deno.run with user data:**
```
grep(pattern="Deno\.run\s*\(\{.*cmd.*\[.*req\.|Deno\.run\s*\(\{.*cmd.*\[.*input", max_matches=15)
```

**Template literal in shell command:**
```
grep(pattern="exec\s*\(`[^`]*\$\{|execSync\s*\(`[^`]*\$\{|spawn\s*\(`[^`]*\$\{", max_matches=20)
```

→ Submit: violated_invariant="Node child_process executes shell with user-controlled string; RCE via shell metacharacter injection", severity=10, confidence=8, exposure="internet"

---

## Step 10 — Command injection: Go

```
grep(pattern="exec\.Command\s*\(['\"]sh['\"],\s*['\"](-c)['\"],\s*\w+|exec\.CommandContext\s*\(.*['\"]sh['\"].*['\"](-c)['\"].*\w+|exec\.Command\s*\(['\"]bash['\"].*['\"](-c)['\"]", max_matches=20)
```

→ Submit: violated_invariant="Go exec.Command passes user input to shell via sh -c; shell injection possible", severity=10, confidence=8, exposure="internet"

---

## Step 11 — Command injection: PHP

```
grep(pattern="system\s*\(\s*\\\$|exec\s*\(\s*\\\$|passthru\s*\(\s*\\\$|shell_exec\s*\(\s*\\\$|popen\s*\(\s*\\\$|pcntl_exec\s*\(", max_matches=20)
```

**PHP backtick operator:**
```
grep(pattern="`[^`]*\\\$_(GET|POST|REQUEST|COOKIE)|`[^`]*\\\$\w+`", max_matches=15)
```

→ Submit: violated_invariant="PHP shell function receives user-controlled variable; OS command injection via [$_GET/$_POST/cookie]", severity=10, confidence=8, exposure="internet"

---

## Step 12 — Command injection: Java / Kotlin

**Runtime.exec with concat:**
```
grep(pattern="Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(.*\+|Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(.*['\"]sh['\"]", max_matches=20)
```

**ProcessBuilder with user data:**
```
grep(pattern="ProcessBuilder\s*\(.*Arrays\.asList\s*\(.*['\"]sh['\"].*['\"](-c)['\"]|ProcessBuilder\s*\(.*['\"]sh['\"].*['\"](-c)['\"]", max_matches=20)
```

**C# Process.Start with concat:**
```
grep(pattern="Process\.Start\s*\(.*\+|Process\.Start\s*\(.*string\.Format|ManagementClass.*InvokeMethod\s*\(['\"]Create['\"],|PowerShell.*AddScript\s*\(\s*\w+\s*\+", max_matches=20)
```

→ Submit: violated_invariant="ProcessBuilder/Runtime.exec/Process.Start passes user-controlled data to shell; RCE", severity=10, confidence=8, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
