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

Then for each tool handler found:
```
grep(pattern="subprocess\.(run|Popen|call|check_output)\s*\(|os\.system\s*\(|os\.popen\s*\(", max_matches=20)
```

**Verify**: does the tool's parameter (`ctx.arguments["name"]`, `arguments.get("cmd")`, etc.) flow into the subprocess call without sanitization? If the tool advertises that it executes commands, the parameter IS the injection vector.

→ Submit: violated_invariant="MCP tool parameter flows into shell execution without sanitization; attacker controls LLM tool call to achieve RCE on MCP server host", severity=10, confidence=9, exposure="network"

---

## Step 2 — MCP SSRF (Python / JS / Go / Java / C#)

**Python MCP server — tool parameter → HTTP request:**
```
grep(pattern="@server\.tool|@mcp\.tool|server\.add_tool", max_matches=15)
```

```
grep(pattern="requests\.(get|post|put)\s*\(|httpx\.(get|post|AsyncClient)\s*\(|urllib\.request\.urlopen\s*\(", max_matches=20)
```

**Verify**: does the URL argument of the HTTP call originate from a tool parameter (`ctx.arguments["url"]`, `arguments["endpoint"]`)? No allowlist check on the URL host?

**Flow trace example** (Python):
```python
@server.tool(name="fetch_url")
async def fetch_url(url: str) -> str:
    return requests.get(url).text   # CRITICAL: url is directly from tool parameter
```

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

**Verify** for bind: is this an MCP server (not a public API)? Per MCP spec 2025-06-18, HTTP transport MCP servers MUST only bind to `127.0.0.1`. Binding to `0.0.0.0` without auth exposes the MCP server to network-level attacks.

→ Submit: violated_invariant="MCP HTTP server bound to 0.0.0.0 (all interfaces) without authentication; any host on the network can call MCP tools as if they were the LLM client", severity=8, confidence=8, exposure="network"

---

## Step 6 — MCP insecure connection (no TLS)

```
grep(pattern="StdioServerTransport\s*\(\s*\)|SSEServerTransport\s*\(.*http://|mcp\.connect\s*\(.*http://", max_matches=15)
```

```
grep(pattern="mcp_client.*url\s*=\s*['\"]http://|McpClient.*url\s*=\s*['\"]http://|ClientSession.*http://", max_matches=15)
```

→ Submit: violated_invariant="MCP client connects via unencrypted HTTP; tool calls and responses (including credentials/tool outputs) transmitted in plaintext", severity=7, confidence=8, exposure="network"

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

**Hooks fetching and piping to shell:**
```
grep(pattern="wget\s+.*\s*|\s*bash|curl\s+.*\s*|\s*sh|curl\s+.*\s*|\s*bash", max_matches=15)
```

```
grep(pattern="\"command\"\s*:\s*['\"].*curl.*|\s*bash['\"]|\"command\"\s*:\s*['\"].*wget.*|\s*sh['\"]", max_matches=15)
```

**Hooks with unconditional allow (bypasses all permissions):**
```
grep(pattern="permissionDecision.*allow|\"allow\"\s*$", max_matches=15)
```

**Verify**: is this a Claude Code `.claude/settings.json` hook or a Cursor `.cursorrc` hook? Does the `permissionDecision: "allow"` have any conditional check before it, or is it unconditional?

→ Submit: violated_invariant="Claude Code hook unconditionally allows all tool execution OR fetches external script and pipes to shell; hook compromise leads to full shell RCE on developer machine", severity=10, confidence=9, exposure="local"

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
