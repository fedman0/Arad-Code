# SKILL: hunt-ai-llm-mcp-security

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns (p_mcp, p_shadow-ai, p_agent-skills)

**grep = CANDIDATES only.** Follow the flow to confirm before submitting.

---

## FLOW VERIFICATION PROTOCOL — run for every candidate before submitting

For each grep match:

**a.** `get_code_snippet("containing_function_or_class")` — read the full MCP tool handler / LLM call site.

**b.** Trace the dangerous variable to its source:
- Hardcoded literal / server-internal config → **SKIP**
- MCP tool parameter / LLM API response / user prompt content → **CONTINUE**
- Unclear → `trace_path("function_name", mode="data_flow")` upstream

**c.** Check for sanitization/validation:
- URL allowlist before HTTP call → **SKIP** (for SSRF)
- Input sanitization before shell call → **SKIP** (for CMDi)
- Template sanitization before render → **SKIP** (for SSTI)
- None of the above → **SUBMIT**

**Submit**: name the MCP tool, the parameter, the sink, and the impact.

---

# Part A — MCP Server Security

## Step 1 — MCP shell injection (Python / JS / Go / Java / C#)

**Python MCP server — tool parameter → shell:**
```
grep(pattern="@server\.tool\s*\(|@mcp\.tool\s*\(|server\.add_tool\s*\(", max_matches=20)
```

For each tool handler file/function found, `get_code_snippet("tool_handler_function")` to read the full function body. Then check whether that same function also calls:
```
grep(pattern="subprocess\.(run|Popen|call|check_output)\s*\(|os\.system\s*\(|os\.popen\s*\(", max_matches=20)
```

**Verify** (both must be true in the SAME function):
1. The subprocess/os.system call is inside the MCP tool handler (not a utility called with a fixed argument).
2. The variable passed to subprocess originates from the tool's parameter dict (`ctx.arguments[...]`, `arguments.get(...)`, function arg) — not from a hardcoded config or fixed list.

If the tool handler calls a helper function, `trace_path("helper_function", mode="data_flow")` to confirm the parameter reaches the shell call.

→ Submit: violated_invariant="MCP tool parameter flows into shell execution without sanitization; attacker controls LLM tool call to achieve RCE on MCP server host", severity=10, confidence=9, exposure="network"

---

## Step 2 — MCP SSRF (Python / JS / Go / Java / C#)

**Python MCP server — tool parameter → HTTP request:**
```
grep(pattern="@server\.tool|@mcp\.tool|server\.add_tool", max_matches=15)
```

For each tool handler found, `get_code_snippet("tool_handler_function")` to read the full function body. Look for HTTP calls inside that same function:

```
grep(pattern="requests\.(get|post|put)\s*\(|httpx\.(get|post|AsyncClient)\s*\(|urllib\.request\.urlopen\s*\(", max_matches=20)
```

**Verify** (both must be true in the SAME function):
1. The HTTP call is inside the MCP tool handler body.
2. The URL argument comes from the tool's parameter dict (`ctx.arguments["url"]`, function arg like `url: str`) — not from a hardcoded config, environment variable, or allowlist lookup.
3. No host allowlist check: `if urlparse(url).hostname not in ALLOWED_HOSTS` → **SKIP**; no such check → **CONTINUE**.

If the HTTP call is in a helper, `trace_path("helper", mode="data_flow")` to confirm the URL parameter flows from the tool input.

→ Submit: violated_invariant="MCP tool parameter flows into HTTP request URL; attacker sends crafted tool call to pivot to internal network (metadata service, K8s API)", severity=10, confidence=9, exposure="network"

---

## Step 3 — MCP auth passthrough (credentials forwarded to arbitrary host)

```
grep(pattern="headers\s*=\s*\{[^}]*['\"]Authorization['\"]|headers\s*=\s*\{[^}]*['\"]api.key['\"]|headers\s*=\s*\{[^}]*['\"]bearer['\"]", max_matches=20)
```

**Verify**: does the `Authorization` / `api_key` / `bearer` header value originate from an MCP tool argument, OR from the client's credential store? Is the URL it's sent to also user-controlled (making this SSRF + credential theft)?

→ Submit: violated_invariant="MCP tool forwards caller credentials (Authorization header / API key) to attacker-controlled URL; credential theft via SSRF", severity=10, confidence=8, exposure="network"

---

## Step 4 — MCP tool poisoning (malicious docstring directives)

```
grep(pattern="\"\"\"[^\"]*IGNORE\s+PREVIOUS\s+INSTRUCTIONS|\"\"\"[^\"]*Do\s+not\s+show\s+the\s+user|\"\"\"[^\"]*secretly|\"\"\"[^\"]*system:\s*you\s+are", max_matches=10)
```

```
grep(pattern="description\s*=\s*['\"].*ignore\s+previous|description\s*=\s*['\"].*do\s+not\s+tell\s+the\s+user|\"\"\"[^\"]*\[SYSTEM\]", max_matches=10)
```

No flow verification needed — the pattern itself is the finding. Tool descriptions containing LLM manipulation directives are tool poisoning by definition.

→ Submit: violated_invariant="MCP tool description contains hidden LLM directives (tool poisoning); attacker tool manipulates agent behavior when the tool is registered", severity=9, confidence=9, exposure="network"

---

## Step 5 — MCP overly permissive bind / no origin validation

**Python — binding to all interfaces:**
```
grep(pattern="host\s*=\s*['\"]0\.0\.0\.0['\"]|host\s*=\s*['\"]['\"]|uvicorn\.run\s*\(.*host\s*=\s*['\"]0\.", max_matches=15)
```

**Go — missing origin header check:**
```
grep(pattern="r\.Header\.Get\s*\(['\"]Origin['\"]|r\.Header\.Get\s*\(['\"]X-Forwarded-For['\"]", max_matches=10)
```

**Verify** for each bind match:

`get_code_snippet("server_startup_function")` to read the full server initialization:
1. Is this file an MCP server (contains `@server.tool`, `mcp.Server`, `FastMCP`, `McpServer`)? If it's a public web API, `0.0.0.0` is expected → **SKIP**.
2. Is authentication middleware applied before the MCP routes? Look for `app.add_middleware(BearerTokenMiddleware)`, API key header check, mTLS config → **SKIP**.
3. No auth on a confirmed MCP server → **SUBMIT**.

→ Submit: violated_invariant="MCP HTTP server bound to 0.0.0.0 (all interfaces) without authentication; any host on the network can call MCP tools as if they were the LLM client", severity=8, confidence=8, exposure="network"

---

## Step 6 — MCP insecure connection (no TLS)

Only HTTP-transport MCP clients are in scope here. `StdioServerTransport` uses stdin/stdout — skip it entirely.

```
grep(pattern="SSEServerTransport\s*\(.*['\"]http://|mcp\.connect\s*\(.*['\"]http://", max_matches=15)
```

```
grep(pattern="mcp_client.*url\s*=\s*['\"]http://[^l]|McpClient.*url\s*=\s*['\"]http://[^l]|ClientSession.*['\"]http://[^l]", max_matches=15)
```

The `[^l]` excludes `http://localhost` and `http://127.` — those are local dev connections, not a network threat.

**Verify** for each match: `get_code_snippet` to confirm:
1. The `http://` URL is a non-localhost remote host (not `127.0.0.1`, `localhost`, `::1`).
2. No TLS termination proxy sits in front (no nginx/envoy config nearby that upgrades to HTTPS).

→ Submit: violated_invariant="MCP client connects to remote MCP server via unencrypted HTTP; tool calls, parameters, and API keys transmitted in plaintext on the network", severity=7, confidence=8, exposure="network"

---

# Part B — LLM Application Security

## Step 7 — Prompt injection: user input in system prompt

**Python (OpenAI / Anthropic / Gemini / Mistral / Cohere):**
```
grep(pattern="client\.chat\.completions\.create\s*\(\s*\)|anthropic\.Anthropic\s*\(\s*\)\.messages\.create\s*\(\s*\)|genai\.GenerativeModel\s*\(", max_matches=20)
```

For each LLM API call found, `get_code_snippet` to read the messages construction. Is user input concatenated directly into the `system` parameter?

```
grep(pattern="\"role\"\s*:\s*\"system\".*\+|messages\s*=\s*\[\s*\{[^}]*\"system\"[^}]*\+\s*\w+", max_matches=20)
```

```
grep(pattern="system_prompt\s*=.*\+.*request\.\|system\s*=.*f['\"].*\{.*request\.", max_matches=15)
```

**Verify**: is the user-supplied text directly embedded in the system prompt without escaping or separation? System prompt injection lets users override the application's intended behavior.

→ Submit: violated_invariant="User input concatenated into LLM system prompt without separator; prompt injection overwrites agent behavior and bypasses application restrictions", severity=9, confidence=8, exposure="internet"

---

## Step 8 — LLM output → code execution (unsandboxed)

**Python — LLM response → exec/eval/subprocess:**
```
grep(pattern="exec\s*\(\s*response\.|eval\s*\(\s*response\.|exec\s*\(\s*completion\.|eval\s*\(\s*llm_output", max_matches=15)
```

```
grep(pattern="subprocess\.(run|Popen|call)\s*\(.*response\.|os\.system\s*\(.*response\.|os\.system\s*\(.*llm_", max_matches=15)
```

**JavaScript — LLM response → eval/Function/child_process:**
```
grep(pattern="eval\s*\(\s*response\.\w+|new Function\s*\(\s*response\.|exec\s*\(\s*response\.|execSync\s*\(\s*response\.", max_matches=15)
```

**Verify**: does the LLM response (`.content`, `.text`, `.choices[0].message.content`) flow directly into `exec/eval/subprocess`? No sandboxing (e.g. Python `RestrictedPython`, JS `vm.runInNewContext` with allowlist)? This is **prompt injection → RCE**: attacker injects into any data the LLM reads, causing it to respond with malicious code that then executes.

→ Submit: violated_invariant="LLM API response flows into exec()/eval() without sandbox; prompt injection in any user-influenced input leads to arbitrary code execution on the server", severity=10, confidence=9, exposure="internet"

---

## Step 9 — LangChain dangerous execution tools

```
grep(pattern="PythonREPLTool\s*\(\s*\)|BashProcess\s*\(\s*\)|PythonAstREPLTool\s*\(\s*\)|LLMMathChain\s*\(\s*\)", max_matches=15)
```

```
grep(pattern="from langchain.*import.*PythonREPL|from langchain.*import.*BashProcess|load_tools\s*\(.*python_repl|load_tools\s*\(.*terminal", max_matches=15)
```

No flow verification needed — these tool classes unconditionally execute LLM-generated code. Their presence in a user-facing agent is inherently dangerous unless the agent is fully isolated and user-trusted.

→ Submit: violated_invariant="LangChain PythonREPL/BashProcess in agent enables arbitrary code execution; any prompt injection reaching the agent achieves RCE", severity=10, confidence=9, exposure="internet"

---

## Step 10 — Claude Code / Cursor hooks: RCE via hook config

**Find hook config files specifically:**
```
grep(pattern="\"hooks\"\s*:\s*\{|\"PreToolUse\"\s*:|\"PostToolUse\"\s*:|\"Stop\"\s*:", max_matches=15)
```

For each match: `get_code_snippet` to confirm the file is `.claude/settings.json`, `.claude/settings.local.json`, or equivalent hook config. Only these files are in scope.

**Check 1 — hook command fetches and pipes to shell:**
```
grep(pattern="\"command\"\s*:\s*\"[^\"]*curl[^\"]*\\|(bash|sh)|\"command\"\s*:\s*\"[^\"]*wget[^\"]*\\|(bash|sh)", max_matches=10)
```

**Check 2 — unconditional allow (bypasses all tool permissions):**
```
grep(pattern="\"permissionDecision\"\s*:\s*\"allow\"", max_matches=15)
```

For each `permissionDecision: "allow"` match: `get_code_snippet` to read the surrounding hook rule. Is the allow inside a conditional `if` block (e.g. checking tool name, path pattern)? Or is it the only response for that hook event with no condition? Unconditional blanket allow → **SUBMIT**. Conditional allow (specific tool/path) → **lower severity** but still flag.

→ Submit: violated_invariant="Claude Code hook unconditionally allows all tool execution OR hook command fetches external script and pipes to shell; malicious repo `.claude/settings.json` achieves full shell RCE on developer machine on clone", severity=10, confidence=9, exposure="local"

---

## Step 11 — API base URL override (MITM all LLM calls)

```
grep(pattern="ANTHROPIC_BASE_URL\s*=|OPENAI_BASE_URL\s*=|baseURL\s*=.*http://|api_base\s*=.*http://", max_matches=15)
```

```
grep(pattern="\"ANTHROPIC_BASE_URL\"\s*:\s*['\"]http://|\"OPENAI_BASE_URL\"\s*:\s*['\"]http://|openai\.base_url\s*=\s*['\"]http://", max_matches=15)
```

No flow verification needed — any `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` pointing to a non-official domain is a MITM attempt against all LLM calls. Flag immediately.

→ Submit: violated_invariant="LLM API base URL overridden to non-official endpoint; all prompts, system instructions, and API keys exfiltrated to attacker-controlled server", severity=10, confidence=10, exposure="local"

---

## Step 12 — Hardcoded LLM API keys (OpenAI / Anthropic / Gemini / Cohere / HuggingFace)

```
grep(pattern="sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{86,}|AIzaSy[A-Za-z0-9_-]{33}", max_matches=20)
```

```
grep(pattern="['\"]sk-(proj|org)-[A-Za-z0-9]{48}['\"]|['\"]claude-[a-z0-9-]+['\"].*api_key\s*=\s*['\"][a-zA-Z0-9_-]{40,}['\"]", max_matches=15)
```

No flow verification needed — API key regex matches are definitive. Confirm the matched string is an actual key format (not a test/example value).

→ Submit: violated_invariant="LLM API key hardcoded in source; key extracted by any repo access grants unlimited LLM usage and potential access to organization's conversation history", severity=9, confidence=9, exposure="internet"

---

## Step 13 — Indirect prompt injection (RAG / tool output → LLM)

```
grep(pattern="retrieval\s*=.*query\s*\(|vector_store\s*=.*search\s*\(|retrieve\s*\(.*query|search_results\s*=", max_matches=20)
```

For each retrieval call: `get_code_snippet` to see if the retrieved content is directly embedded in the next LLM prompt without sanitization:

```
grep(pattern="messages.*content.*\+.*retrieval|prompt.*\+.*documents|system.*\+.*search_result", max_matches=15)
```

**Verify**: does the content returned from a vector DB / web search / tool call flow directly into the next LLM prompt message? Attackers who can write to indexed content (web pages, documents, user-accessible files) can inject instructions into the LLM's context.

→ Submit: violated_invariant="Retrieved external content concatenated into LLM prompt without sanitization; indirect prompt injection via user-accessible documents/web pages", severity=8, confidence=7, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
