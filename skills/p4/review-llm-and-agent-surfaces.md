# review-llm-and-agent-surfaces

Audit codebases that embed LLMs or agentic AI: prompt injection, tool boundary enforcement, capability escalation, and data exfiltration through AI-mediated paths.

## Scope

- Prompt injection: user-controlled data inserted into system prompt without sanitization
- Tool boundary: agent can invoke tools (code execution, file I/O, HTTP) based on LLM output — can an attacker escalate to unintended tools?
- Indirect injection: malicious content in retrieved documents, web pages, tool results fed back to LLM
- Exfiltration: LLM can make outbound requests or write files; attacker causes sensitive data to be included in an exfil payload
- Memory poisoning: persistent memory stores that accept untrusted input and influence future LLM decisions
- Agent-to-agent trust: multi-agent systems with insufficient authorization between agents

## Methodology

1. `get_architecture()` to identify AI frameworks (LangChain, AutoGen, CrewAI, custom).
2. Enumerate all places user input touches the prompt:
   - `search_graph(name_pattern="system_prompt|user_message|chat_completion")`
   - Read prompt construction code: is user input placed inside system or tool-result sections?
3. Enumerate available tools (function calling definitions):
   - What can the agent call? File write? Shell? HTTP to arbitrary URLs?
   - Is there an allowlist of callable tools, or is the full tool set always available?
4. Check retrieval pipelines (RAG):
   - Is retrieved content placed inside the prompt without a trust boundary marker?
   - Can an attacker write content to the knowledge base that gets retrieved?
5. Check outbound calls the agent can make:
   - Can the agent send HTTP requests to attacker-controlled URLs?
   - Can sensitive context (session, DB results) appear in those requests?
6. Check multi-agent boundaries:
   - Does a sub-agent trust instructions from a parent agent unconditionally?
   - Is there a capability downgrade when delegating to a sub-agent?

## Required proof_obligations

- `reachability`: can an attacker inject into the prompt (directly or via retrieved content)?
- `input_control`: does the injected content influence LLM behavior or tool selection?
- `guard`: is there no input sanitization, output validation, or capability restriction?
- `impact`: what action can the agent be made to perform, or what data can be exfiltrated?

## exposure

Set `exposure` based on who can inject:
- `internet`: public-facing chatbot with no auth
- `authenticated`: logged-in users only
- `internal`: only internal users / admin console

## anchor_text requirement

Point to the exact line where untrusted content is interpolated into the prompt, or where the tool dispatcher accepts LLM-chosen tool names without validation.

Call `reject_hypothesis` when tool invocation requires a cryptographically verified capability token.
Call `finish()` when complete.
