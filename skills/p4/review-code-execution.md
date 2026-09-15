# SKILL: review-code-execution

## Contract

**Trigger:** Phase 4. Run for any service executing shell commands, eval(), templates, or dynamic expressions.
**Phase:** 4 — Security Analysis
**Preconditions:** Entry point map, language runtime features
**Escalates to:** trace-input-to-effect

## Inputs
- repo_path

## Procedure
1. search_code(pattern="Process.Start|exec\(|shell_exec|os.system|subprocess|Runtime.exec|ProcessBuilder|eval\(|new Function\(|ScriptEngine") to find execution sinks.
2. For each sink: get_code_snippet and check if arguments come from user input.
3. For shell commands: are arguments shell-escaped? Is the executable path hardcoded?
4. For template engines (Handlebars, Jinja2, Razor, Thymeleaf): is user input injected into the template string itself (server-side template injection) or only into template variables?
5. Check expression evaluation: SpEL (Spring), OGNL, MVEL, Groovy eval — are these called with user-supplied expressions?
6. Check deserialization used for code execution (Ysoserial gadget chains) — see review-deserialization.
7. Find dynamic plugin/assembly loading: is a user-supplied path used to load a DLL, .so, or .class?
8. Find code generation followed by compilation and execution.
9. Find regex from user input: catastrophic backtracking (ReDoS) risk.
10. Check LLM tool/function call payloads: is the tool name or arguments user-controlled without validation?

## Required evidence
- All execution sinks: file:line, argument source
- Template injection: template string user-controlled vs. template variables user-controlled
- Expression evaluation with user input
- Dynamic loading with user-supplied path
- ReDoS-vulnerable regex patterns

## Counterchecks
- Shell escape functions (shlex.quote, escapeshellarg) prevent injection if applied to each argument separately.
- Template engines with autoescaping prevent injection into template variables but NOT template string injection.
- Sandboxed expression evaluators may prevent full RCE but can still be exploited for information disclosure.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses require: confirmed user input reaching execution sink with confirmed absence of escaping/sandboxing.

## Stop condition
When all execution sinks are classified as safe (hardcoded args / properly escaped / sandboxed) or vulnerable.

## Forbidden inferences
- Do not report SSTI without confirming the user input is in the template string, not just a template variable.
- Do not report shell injection without confirming the command is constructed without proper escaping.
