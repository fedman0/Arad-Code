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
- Unclear → `trace_path("function_name", mode="data_flow")` upstream; if still unclear, **submit with confidence=5** (uncertain is not safe)

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
grep(pattern="@\w+\.(tool|call_tool)\s*\(|\.add_tool\s*\(|\b\w+\.(tool|registerTool)\s*\(\s*['\"]|CallToolRequestSchema|\.AddTool\s*\(|\[McpServerTool|@Tool\s*\(", max_matches=20)
```

For each tool handler file/function found, `get_code_snippet("tool_handler_function")` to read the full function body. Then check whether that same function also calls:
```
grep(pattern="subprocess\.(run|Popen|call|check_call|check_output)\s*\(|os\.(system|popen)\s*\(|create_subprocess_(shell|exec)\s*\(|\b(exec|execSync|spawn|spawnSync)\s*\(|exec\.Command(Context)?\s*\(|Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(|new\s+ProcessBuilder\s*\(|Process\.Start\s*\(", max_matches=20)
```

**Verify** (both must be true in the SAME function):
1. The subprocess/os.system call is inside the MCP tool handler (not a utility called with a fixed argument).
2. The variable passed to subprocess originates from the tool's parameter dict (`ctx.arguments[...]`, `arguments.get(...)`, function arg) — not from a hardcoded config or fixed list.

If the tool handler calls a helper function, `trace_path("helper_function", mode="data_flow")` to confirm the parameter reaches the shell call.

→ Submit: violated_invariant="MCP tool parameter flows into shell execution without sanitization; attacker controls LLM tool call to achieve RCE on MCP server host", severity=10, confidence=9, exposure="internal" ("internet" if the MCP endpoint is internet-facing), cwe="CWE-78"

---

## Step 2 — MCP SSRF (Python / JS / Go / Java / C#)

**MCP server — tool parameter → HTTP request** (reuse the tool-handler list from Step 1 if you already have it):
```
grep(pattern="@\w+\.(tool|call_tool)\s*\(|\.add_tool\s*\(|\b\w+\.(tool|registerTool)\s*\(\s*['\"]|CallToolRequestSchema|\.AddTool\s*\(|\[McpServerTool|@Tool\s*\(", max_matches=15)
```

For each tool handler found, `get_code_snippet("tool_handler_function")` to read the full function body. Look for HTTP calls inside that same function:

```
grep(pattern="requests\.(get|post|put|patch|delete|request)\s*\(|httpx\.(get|post|put|request|Client|AsyncClient)\s*\(|urllib\.request\.urlopen\s*\(|aiohttp\.ClientSession|\bfetch\s*\(|axios(\.(get|post|put|request))?\s*\(|http\.(Get|Post|NewRequest|NewRequestWithContext)\s*\(|HttpRequest\.newBuilder|\.Get(String)?Async\s*\(", max_matches=20)
```

**Verify** (both must be true in the SAME function):
1. The HTTP call is inside the MCP tool handler body.
2. The URL argument comes from the tool's parameter dict (`ctx.arguments["url"]`, function arg like `url: str`) — not from a hardcoded config, environment variable, or allowlist lookup.
3. No host allowlist check: `if urlparse(url).hostname not in ALLOWED_HOSTS` → **SKIP**; no such check → **CONTINUE**.

If the HTTP call is in a helper, `trace_path("helper", mode="data_flow")` to confirm the URL parameter flows from the tool input.

→ Submit: violated_invariant="MCP tool parameter flows into HTTP request URL; attacker sends crafted tool call to pivot to internal network (metadata service, K8s API)", severity=10, confidence=9, exposure="internal" ("internet" if the MCP endpoint is internet-facing), cwe="CWE-918"

---

## Step 3 — MCP auth passthrough (credentials forwarded to arbitrary host)

```
grep(pattern="headers\s*[=:]\s*\{[^}]*(?i:authorization|x-api-key|api[-_]key)|['\"](?i:authorization|x-api-key)['\"]\s*:", max_matches=20)
```

**Verify**: does the `Authorization` / `api_key` / `bearer` header value originate from an MCP tool argument, OR from the client's credential store? Is the URL it's sent to also user-controlled (making this SSRF + credential theft)?

→ Submit: violated_invariant="MCP tool forwards caller credentials (Authorization header / API key) to attacker-controlled URL; credential theft via SSRF", severity=10, confidence=8, exposure="internal" ("internet" if the MCP endpoint is internet-facing), cwe="CWE-522"

---

## Step 4 — MCP tool poisoning (malicious docstring directives)

```
grep(pattern="(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions|do\s+not\s+(tell|show|mention|inform)\s+the\s+user|<important>|\[system\]|system:\s*you\s+are", max_matches=10)
```

```
grep(pattern="(?i)(description|desc)\s*[=:].*(ignore\s+previous|do\s+not\s+tell|secretly|without\s+(telling|informing|notifying)\s+the\s+user|~/\.ssh|id_rsa|\.cursor/mcp\.json|claude_desktop_config)", max_matches=10)
```

Docstrings span several lines, so these greps match the directive text itself. For each match, `read_file` around the line and confirm it sits inside an MCP tool description/docstring/input schema (or a tool list the server returns) — not in tests, docs, prompt-injection detectors or deny-lists. Once confirmed, no flow verification is needed: tool descriptions containing LLM manipulation directives are tool poisoning by definition.

→ Submit: violated_invariant="MCP tool description contains hidden LLM directives (tool poisoning); attacker tool manipulates agent behavior when the tool is registered", severity=9, confidence=9, exposure="internet", cwe="CWE-1427"

---

## Step 5 — MCP overly permissive bind / no origin validation

**Binding to all interfaces (Python / Node / Go):**
```
grep(pattern="host\s*=\s*['\"]0\.0\.0\.0['\"]|host\s*=\s*['\"]['\"]|uvicorn\.run\s*\(.*host\s*=\s*['\"]0\.|\.listen\s*\(\s*\w+\s*,\s*['\"]0\.0\.0\.0['\"]|ListenAndServe\s*\(\s*\"(0\.0\.0\.0)?:", max_matches=15)
```

**Origin / Host validation present? (no match inside an MCP HTTP server = missing check):**
```
grep(pattern="Header\.Get\s*\(\s*\"Origin\"\s*\)|headers\.get\s*\(\s*['\"](?i:origin)['\"]|CheckOrigin|allowed_?[oO]rigins|enable_?[dD]ns_?[rR]ebinding_?[pP]rotection|enableDnsRebindingProtection", max_matches=10)
```

**Verify** for each bind match:

`get_code_snippet("server_startup_function")` to read the full server initialization:
1. Is this file an MCP server (contains `@server.tool`, `mcp.Server`, `FastMCP`, `McpServer`)? If it's a public web API, `0.0.0.0` is expected → **SKIP**.
2. Is authentication middleware applied before the MCP routes? Look for `app.add_middleware(BearerTokenMiddleware)`, API key header check, mTLS config → **SKIP**.
3. No auth on a confirmed MCP server → **SUBMIT**. If the second grep finds no Origin/Host validation in that server, mention it in the same finding (DNS rebinding reaches even a localhost-bound MCP server).

→ Submit: violated_invariant="MCP HTTP server bound to 0.0.0.0 (all interfaces) without authentication; any host on the network can call MCP tools as if they were the LLM client", severity=8, confidence=8, exposure="internal" ("internet" if the host is internet-facing), cwe="CWE-306"

---

## Step 6 — MCP insecure connection (no TLS)

Only HTTP-transport MCP clients are in scope here. `StdioServerTransport` uses stdin/stdout — skip it entirely.

```
grep(pattern="(SSEClientTransport|StreamableHTTPClientTransport)\s*\(\s*new\s+URL\s*\(\s*['\"]http://|(sse_client|streamablehttp_client|streamable_http_client)\s*\(\s*(url\s*=\s*)?['\"]http://|mcp\.connect\s*\(.*['\"]http://", max_matches=15)
```

```
grep(pattern="(mcp_client|McpClient|ClientSession|MCP_SERVER_URL|mcp_server_url).*['\"]http://", max_matches=15)
```

```
grep(pattern="\"(url|serverUrl)\"\s*:\s*\"http://", file_glob="*mcp*.json", max_matches=15)
```

These greps also return `http://localhost`, `http://127.0.0.1` and `http://[::1]` — skip those during verification; they are local dev connections, not a network threat.

**Verify** for each match: `get_code_snippet` (or `read_file` for a JSON config match) to confirm:
1. The `http://` URL is a non-localhost remote host (not `127.0.0.1`, `localhost`, `::1`).
2. No TLS termination proxy sits in front (no nginx/envoy config nearby that upgrades to HTTPS).

→ Submit: violated_invariant="MCP client connects to remote MCP server via unencrypted HTTP; tool calls, parameters, and API keys transmitted in plaintext on the network", severity=7, confidence=8, exposure="internal", cwe="CWE-319"

---

# Part B — LLM Application Security

## Step 7 — Prompt injection: user input in system prompt

**Python (OpenAI / Anthropic / Gemini / Mistral / Cohere):**
```
grep(pattern="\.chat\.completions\.create\s*\(|\.messages\.create\s*\(|\.responses\.create\s*\(|GenerativeModel\s*\(|\.generate_content\s*\(|\.chat\.complete\s*\(|\bco\.chat\s*\(", max_matches=20)
```

For each LLM API call found, `get_code_snippet` to read the messages construction. Is user input concatenated directly into the `system` parameter?

```
grep(pattern="['\"]?role['\"]?\s*:\s*['\"]system['\"].*(\+|\bf['\"]|\.format\s*\(|\$\{)", max_matches=20)
```

```
grep(pattern="system(_prompt|_message|_instruction)?\s*=.*\+.*(request\.|req\.|user_input|user_message|query)|system(_prompt|_message|_instruction)?\s*=\s*f['\"].*\{[^}]*(request|user|input|query|message)", max_matches=15)
```

**Verify**: is the user-supplied text directly embedded in the system prompt without escaping or separation? System prompt injection lets users override the application's intended behavior.

→ Submit: violated_invariant="User input concatenated into LLM system prompt without separator; prompt injection overwrites agent behavior and bypasses application restrictions", severity=9, confidence=8, exposure="internet", cwe="CWE-1427"

---

## Step 8 — LLM output → code execution (unsandboxed)

**Python — LLM response → exec/eval/subprocess:**
```
grep(pattern="\b(exec|eval)\s*\(\s*(response|completion|llm_\w*|ai_\w*|generated_\w*|model_output)\b|\b(exec|eval)\s*\(.*\.(choices\[0\]|content\[0\]\.text|output_text)", max_matches=15)
```

```
grep(pattern="subprocess\.(run|Popen|call|check_output)\s*\(.*(response\.|completion\.|llm_)|os\.system\s*\(.*(response\.|completion\.|llm_)", max_matches=15)
```

**JavaScript — LLM response → eval/Function/child_process:**
```
grep(pattern="\b(eval|new\s+Function|exec|execSync|vm\.runIn\w+Context)\s*\(\s*(response|completion|llm\w*|ai\w*Response|result\.text|message\.content)\b", max_matches=15)
```

**Verify**: does the LLM response (`.content`, `.text`, `.choices[0].message.content`) flow directly into `exec/eval/subprocess`? No real isolation (separate container / microVM / WASM runtime / `isolated-vm`)? Node's `vm` module is not a security boundary and Python `exec` with restricted globals is escapable, so neither counts as a sandbox. This is **prompt injection → RCE**: attacker injects into any data the LLM reads, causing it to respond with malicious code that then executes.

→ Submit: violated_invariant="LLM API response flows into exec()/eval() without sandbox; prompt injection in any user-influenced input leads to arbitrary code execution on the server", severity=10, confidence=9, exposure="internet", cwe="CWE-94"

---

## Step 9 — LangChain dangerous execution tools

```
grep(pattern="PythonREPLTool\s*\(|PythonAstREPLTool\s*\(|PythonREPL\s*\(|BashProcess\s*\(|ShellTool\s*\(|allow_dangerous_code\s*=\s*True", max_matches=15)
```

```
grep(pattern="from langchain.*import.*(PythonREPL|PythonAstREPL|BashProcess|ShellTool)|load_tools\s*\(.*(python_repl|terminal)", max_matches=15)
```

No flow verification needed — these tool classes unconditionally execute LLM-generated code. Their presence in a user-facing agent is inherently dangerous unless the agent is fully isolated and user-trusted.

→ Submit: violated_invariant="LangChain PythonREPL/BashProcess in agent enables arbitrary code execution; any prompt injection reaching the agent achieves RCE", severity=10, confidence=9, exposure="internet", cwe="CWE-94"

---

## Step 10 — Claude Code / Cursor hooks: RCE via hook config

**Find hook config files specifically:**
```
grep(pattern="\"hooks\"\s*:\s*\{|\"PreToolUse\"\s*:|\"PostToolUse\"\s*:|\"Stop\"\s*:", max_matches=15)
```

For each match: confirm from the path that the file is `.claude/settings.json`, `.claude/settings.local.json`, or equivalent hook config, and `read_file` it (these are JSON files, not indexed symbols — `get_code_snippet` cannot read them). Only these files are in scope.

**Check 1 — hook command fetches and pipes to shell:**
```
grep(pattern="\"command\"\s*:\s*\".*(curl|wget)\s.*\|\s*(sudo\s+)?(ba|z)?sh\b|\"command\"\s*:\s*\".*(ba|z)?sh\s+(-c\s+\S*\$\(|<\()\s*(curl|wget)\s", max_matches=10)
```

**Check 2 — unconditional allow (bypasses all tool permissions):**
```
grep(pattern="\"permissionDecision\"\s*:\s*\"allow\"", max_matches=15)
```

For each `permissionDecision: "allow"` match: `read_file` around the match (JSON config or the hook script that prints it) to read the surrounding hook rule. Is the allow inside a conditional `if` block (e.g. checking tool name, path pattern)? Or is it the only response for that hook event with no condition? Unconditional blanket allow → **SUBMIT**. Conditional allow (specific tool/path) → **lower severity** but still flag.

→ Submit: violated_invariant="Claude Code hook unconditionally allows all tool execution OR hook command fetches external script and pipes to shell; malicious repo `.claude/settings.json` achieves full shell RCE on developer machine on clone", severity=10, confidence=9, exposure="internet", cwe="CWE-494" (use "CWE-862" for an unconditional permission allow)

---

## Step 11 — API base URL override (MITM all LLM calls)

```
grep(pattern="(ANTHROPIC_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE)\s*=|baseURL\s*[=:].*http://|api_base\s*=.*http://|base_url\s*=\s*['\"]http://", max_matches=15)
```

```
grep(pattern="\"(ANTHROPIC_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE)\"\s*:\s*['\"]https?://|openai\.(base_url|api_base)\s*=\s*['\"]https?://", max_matches=15)
```

**Verify** from the matched value: SKIP official endpoints (`api.anthropic.com`, `api.openai.com`, `*.openai.azure.com`, Bedrock/Vertex endpoints), `localhost`/`127.0.0.1` model servers, and values read from the environment at runtime (gateways such as LiteLLM are legitimate). SUBMIT when a committed config (`.claude/settings.json` `env`, a checked-in `.env`, a source constant) points the SDK at plaintext `http://` on a non-local host or at an unrelated third-party domain.

→ Submit: violated_invariant="LLM API base URL overridden to non-official endpoint; all prompts, system instructions, and API keys exfiltrated to attacker-controlled server", severity=10, confidence=10, exposure="internet", cwe="CWE-200" (use "CWE-319" for a plaintext http:// endpoint)

---

## Step 12 — Hardcoded LLM API keys (OpenAI / Anthropic / Gemini / Cohere / HuggingFace)

```
grep(pattern="sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{86,}|AIzaSy[A-Za-z0-9_-]{33}", max_matches=20)
```

```
grep(pattern="['\"]sk-(proj|svcacct|admin)-[A-Za-z0-9_-]{20,}['\"]|['\"]claude-[a-z0-9-]+['\"].*api_key\s*=\s*['\"][a-zA-Z0-9_-]{40,}['\"]", max_matches=15)
```

No flow verification needed — API key regex matches are definitive. Confirm the matched string is an actual key format (not a test/example value).

→ Submit: violated_invariant="LLM API key hardcoded in source; key extracted by any repo access grants unlimited LLM usage and potential access to organization's conversation history", severity=9, confidence=9, exposure="internet", cwe="CWE-798"

---

## Step 13 — Indirect prompt injection (RAG / tool output → LLM)

```
grep(pattern="\.similarity_search\w*\s*\(|\.as_retriever\s*\(|\.get_relevant_documents\s*\(|retriever\.a?invoke\s*\(|retrieve\s*\(.*query|\.query\s*\(\s*query_(texts|embeddings)\s*=|search_results\s*=", max_matches=20)
```

For each retrieval call: `get_code_snippet` to see if the retrieved content is directly embedded in the next LLM prompt without sanitization:

```
grep(pattern="(prompt|messages|content|system|context)\w*['\"\]]*\s*[=:+].*(\+\s*|\{)\s*(docs|documents|context|search_results?|retrieved\w*|retrieval\w*|chunks|page_content)\b|\.join\s*\(.*page_content", max_matches=15)
```

**Verify**: does the content returned from a vector DB / web search / tool call flow directly into the next LLM prompt message? Attackers who can write to indexed content (web pages, documents, user-accessible files) can inject instructions into the LLM's context.

→ Submit: violated_invariant="Retrieved external content concatenated into LLM prompt without sanitization; indirect prompt injection via user-accessible documents/web pages", severity=8, confidence=7, exposure="internet", cwe="CWE-1427"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
