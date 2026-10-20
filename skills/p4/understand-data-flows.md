---
parallel: true
---

# SKILL: understand-data-flows

## Goal

Trace how data enters, moves through, and exits this application. Find where
attacker-controlled data reaches a dangerous operation without adequate validation,
and where sensitive data leaks to unauthorized recipients.

This skill is language-agnostic. Focus on the data flow pattern, not the library name.

---

## Phase 1 — Map every input surface

Use `get_architecture` to understand how the application receives external data.
Then read the entry-point code to find EVERY input vector — do not assume only body/params matter.

**HTTP inputs:**
- Request body (JSON, form fields, multipart, XML, binary)
- Query string parameters
- URL path segments (including dynamic route parameters)
- HTTP headers (ALL of them — especially: Authorization, Cookie, Host, X-Forwarded-For,
  X-Real-IP, Content-Type, Accept, Referer, Origin, X-API-Key, X-Request-ID, custom headers)
- Cookies (session, tracking, feature flags)

**Non-HTTP inputs:**
- Message queue / event bus payloads (Kafka, RabbitMQ, SQS, Redis Pub/Sub)
- Scheduled job / cron parameters
- Data received from external APIs and webhooks (the response is attacker-influenced too)
- File uploads (both the content AND the filename, content-type, and metadata)
- WebSocket messages
- gRPC / Thrift / custom protocol payloads

For each input vector: use `trace_path(mode="data_flow", direction="outbound")` to follow the value into the codebase.

---

## Phase 2 — Trace data to sensitive operations

For each input, follow it to every sensitive operation it reaches.
Do not search for specific function names — read the code and trace the actual path.

**Injection into query languages:**

*Relational databases (SQL):*
- Is user-controlled data placed into a query string by concatenation, interpolation, or formatting?
- Or is it passed as a bound parameter, placeholder, or prepared statement?
- Are there any ORM "escape hatch" APIs that allow raw SQL? (any framework has them — find them)
- A filter API that accepts arbitrary field names or operators from user input is injection-equivalent.

*Document stores / NoSQL (MongoDB, DynamoDB, Elasticsearch, Redis, CouchDB, etc.):*
- Is user-controlled data used as a query operator or query key (not just a value)?
  Example: passing `{"password": {"$ne": ""}}` where a string is expected.
- Is user input placed directly into a query document/filter without strict type enforcement?
- Read how the application constructs each database query — does it cast types before querying?

*LDAP, XPath, HQL, and other query languages:*
- Is user-controlled data inserted into a query string for any query language?
  The pattern is always the same: string concatenation into a structured query.

**Second-order injection:**

Data stored safely at write time (properly escaped) may be retrieved and used unsafely later.
- For each dangerous sink (SQL query, command execution, template rendering, file path):
  trace not only direct user input but also data fetched FROM THE DATABASE that originally
  came from user input in a different request.
- The question: is there any operation that retrieves stored user data and places it into a
  dangerous context WITHOUT re-validation at read time?
- Example: username stored as `admin'--` safely via parameterized query → later used in a
  raw SQL string → SQL injection at read time.

**Injection into template engines (SSTI — any language):**

Find every place the application renders templates. Then check:
- Is user-controlled data used as the TEMPLATE STRING itself?
  (not as a variable INSIDE a template, but as the template text being compiled/rendered)
- Common dangerous patterns:
  - Any call that takes a string and evaluates it as a template
  - Dynamically constructed template names that derive from user input
  - Error pages or email templates generated from user-supplied format strings
- This applies to every template engine in every language:
  Python (Jinja2, Mako, Chameleon, `str.format` on a user-controlled format string), PHP (Twig, Blade, Smarty),
  Java (Freemarker, Velocity, Thymeleaf SpEL in templates), JavaScript/Node (EJS, Pug, Handlebars,
  Nunjucks, Lodash template), Ruby (ERB, Haml), Go (text/template if user controls template string),
  .NET (Razor via RazorEngine/RazorLight when the template string is user-supplied; T4 can be misused).

**XSS — Output encoding failure (any server-side HTML rendering):**

If this application renders HTML responses, generates HTML emails, or produces HTML-containing PDFs:
- Find every place user-controlled data is rendered into an HTML context.
- Is the value HTML-encoded before insertion? Read the template output call — does it use auto-escaping?
- Is auto-escaping disabled for specific fields? (markers like `safe`, `noescape`, `raw`, `|html`,
  `Html.Raw()`, `@Html.Raw()`, `{{{ }}}`, `<%- %>`, `!{var}`, `v-html` — any escape-bypass annotation)
- Stored XSS: user data stored in DB → retrieved → rendered without encoding.
- Reflected XSS: user data from query/path/header → rendered into HTML response immediately.
- For file uploads: are SVG or HTML files served with their original content-type?
  A user-uploaded `.svg` served as `image/svg+xml` executes embedded `<script>` in browsers.

**Expression language injection (EL/SpEL/OGNL):**

Applies primarily to Java/Spring but the pattern exists elsewhere:
- Is user-controlled data used in an expression that gets evaluated by an expression engine?
- Spring SpEL: `parser.parseExpression(userInput).getValue()`
- OGNL (Struts): URL parameters evaluated as OGNL expressions
- Pebble/Thymeleaf: expression in template attribute with user-controlled value
- Look for any "evaluate expression from string" API call with user data.

**Prototype Pollution (JavaScript / Node.js only):**

- Does the application deep-merge or path-set user-supplied JSON into other objects?
  (lodash `merge`/`mergeWith`/`defaultsDeep`/`set`/`zipObjectDeep` in vulnerable versions, jQuery
  `$.extend(true, …)`, any recursive copy/merge utility, `JSON.parse` result used as merge source)
- `Object.assign` and object spread are shallow and do not pollute `Object.prototype`: a `__proto__`
  key from `JSON.parse` changes only the target's own prototype (`Object.assign`) or becomes a plain
  own property (spread).
- Can a user send `{"__proto__": {"isAdmin": true}}` or
  `{"constructor": {"prototype": {"isAdmin": true}}}`?
- If `Object.prototype` is polluted, every object in the process inherits the injected property.
  This can bypass `if (obj.isAdmin)` checks, cause DoS, or achieve RCE via spawned process
  environment and shell option injection.
- Read every merge/assign/copy utility call that takes user-controlled objects.

**Injection into system operations:**

- Is user-controlled data passed to an OS command execution API?
  (any language has one: subprocess, exec, shell_exec, Runtime.exec, system, popen, etc.)
- Is user-controlled data used in a shell command string rather than as a separate argument?
  (passing as a list/array of arguments is usually safe; string concatenation is not)
- Is user-controlled data passed to code evaluation (eval, compile-and-run patterns)?

**Log injection and Log4Shell:**

*Generic log injection (any language):*
- User-controlled data written to logs without newline stripping can forge log entries.
- Find where HTTP request data (headers, body, user-agent, X-Forwarded-For, path) is logged.
- If newlines are not stripped: an attacker can inject fake log entries.

*Log4Shell — Java log4j2 (CRITICAL):*
- If this is a Java application: find which logging library is used (check dependency manifest).
- For log4j2: what version? 2.0-beta9 through 2.14.1 is vulnerable to CVE-2021-44228 (Log4Shell), fixed in
  2.15.0 (2.12.2 on Java 7, 2.3.1 on Java 6). 2.15.0 remains exploitable with non-default pattern layouts that
  use Thread Context lookups (CVE-2021-45046, fixed in 2.16.0 / 2.12.2). CVE-2021-45105 (DoS, fixed in 2.17.0)
  and CVE-2021-44832 (RCE only with attacker control of the logging configuration, fixed in 2.17.1) are
  separate, lower-severity issues.
- Any user-controlled string passed to a log4j2 logger containing `${jndi:ldap://...}` triggers
  an outbound JNDI lookup → remote class loading → RCE.
- User data that is commonly logged: HTTP headers (User-Agent, X-Forwarded-For, custom headers),
  usernames, search terms, request paths.
- Read the dependency manifest — is log4j2 present? At what version?

**Deserialization of attacker-controlled data:**

The dangerous pattern: an API that deserializes bytes/strings into arbitrary objects.
- Python: `pickle`, `marshal`, `shelve`, `yaml.load` (without Loader=SafeLoader)
- Java: `ObjectInputStream.readObject()`, Kryo without whitelist, XStream without security config
- PHP: `unserialize()`
- Ruby: `Marshal.load()`
- .NET: `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter`
- Node.js: `node-serialize` `unserialize()`, `js-yaml` 3.x `load()` (its full schema constructs `!!js/function`;
  `safeLoad` and 4.x `load` are safe), `eval` / `new Function` used to revive serialized data
- Generic: any "read object from JSON/XML/binary and reconstruct its type" API

Find where the application deserializes data from: request bodies, headers, cookies,
cache entries, message queue payloads. Read whether the deserializer is the unsafe variant.

**XML parsing — XXE and entity expansion DoS (any XML parser):**

- Find where the application parses XML (uploads, API request bodies, configuration).
- Does the parser have external entity processing enabled? Defaults differ by parser — read its construction.
- Safe: explicit disabling of external entities AND DTD processing, use of a hardened library (e.g. defusedxml).
- Unsafe by default: Java's JAXP factories (DocumentBuilderFactory, SAXParserFactory, XMLInputFactory,
  TransformerFactory) unless hardened, lxml before 5.0 (`resolve_entities=True`, local-file XXE), .NET
  XmlDocument / XmlTextReader on .NET Framework before 4.5.2.
- Unsafe only when enabled: libxml2-based parsers (PHP SimpleXML/DOMDocument, Nokogiri, libxmljs) with entity
  substitution or DTD loading flags (`LIBXML_NOENT`, `NOENT`, `noent: true`, `DTDLOAD`), lxml
  `XMLParser(resolve_entities=True)`, .NET `DtdProcessing.Parse` with an `XmlUrlResolver`, Python
  `xml.sax` / `pulldom` with `feature_external_ges` enabled. Python's `xml.etree` and `minidom` do not fetch
  external entities.

- *Billion Laughs — XML DoS (no external request needed):*
  An attacker defines a chain of expanding internal entities. No network access required.
  Protection: disable DTD processing entirely (not just external entities).
  Read whether the parser configuration disables DTD processing, not just external entities.

**File operations — path traversal, arbitrary access, and upload abuse:**

- Is user-controlled data used in a file path construction (open, read, write, delete)?
- Is traversal prevented? Read the actual sanitization — `..` stripping is bypassable
  via URL encoding (`%2e%2e`), unicode normalization, null bytes on some systems.
- For archive extraction: is the extracted filename validated to stay inside the target
  directory? Zip Slip applies to any archive library in any language (Python's `zipfile.extractall`
  already strips `..` and absolute paths; `tarfile.extractall` does not unless `filter="data"` is
  passed, which is the default only from Python 3.14).

*File upload specifics:*
- MIME type validation: is the actual file content inspected (magic bytes), or only the
  `Content-Type` header from the request? The header is attacker-controlled.
  SVG → XSS, HTML → phishing/XSS, polyglot files (valid image + valid HTML).
- Serve location: are uploaded files served from a URL without authentication?
  An uploaded malicious SVG served at a public URL = stored XSS.
- File size limit: is there an enforced maximum file size before reading the content?
  No limit = disk/memory exhaustion DoS via a large upload.

**ReDoS — Regular expression DoS:**

- Find every regex applied to user-controlled input (URL validation, email validation,
  password complexity checks, input sanitization patterns).
- Is the input length bounded BEFORE the regex runs?
- Does any regex contain nested quantifiers or overlapping alternatives?
  Patterns like `(a+)+`, `(a|aa)+`, `([0-9]+\.?)+`, `(\w+\s)+` on adversarial input
  can cause exponential backtracking, hanging the process.
- This applies to any language — PCRE, Java regex, Python re, .NET Regex, JS RegExp,
  Ruby Regexp all implement backtracking. RE2-based engines (Go) are safe.

**Mass assignment / parameter binding:**

The dangerous pattern: the framework automatically maps ALL request fields to model attributes.
- This exists in every framework: Rails strong parameters, Django/DRF serializer field allowlist,
  Spring `@ModelAttribute`, Laravel `$fillable`/`$guarded`, Mongoose schema, etc.
- Find how each state-changing endpoint deserializes the request body.
- Read the model/schema binding configuration. Are only expected fields mapped?
  Or can an attacker set `role`, `is_admin`, `balance`, `verified`, `permissions`?

**Response header injection:**

- Is user-controlled data placed into HTTP response headers without newline stripping?
  (Location, Content-Disposition, Set-Cookie, custom headers)
- A newline in a header value can inject additional headers or split the HTTP response.

---

## Phase 3 — Find sensitive data leaving the application

Trace every response that could reach an attacker.

**In HTTP responses:**
- Are authentication tokens, signing keys, OTPs, session IDs, or private keys ever included
  in responses to unprivileged actors?
- Do error responses include stack traces, internal paths, database queries, or config values?
- Do debug/test code paths add sensitive values to headers or response bodies?
  Read every `if debug/test/staging` branch in view handlers and middleware.

**In logs:**
- Are credentials, tokens, or session IDs logged at any log level?
  (Logging is often the only observable path for an insider or log-storage attacker)

---

## Phase 4 — Verify information isolation between users

For every endpoint that returns data:
- Is the data filtered to the requesting user's identity?
- Read the query/data access layer — does it include the authenticated user as a filter?
- Can one user access another user's records by knowing or guessing an ID?
- Are IDs sequential, short, or otherwise guessable/enumerable?

---

## What to produce

A hypothesis for each:
- SQL/NoSQL/LDAP/XPath/HQL injection via concatenation or operator injection
- Second-order injection: stored user data reused unsafely in a later operation
- SSTI: user data used as a template string (not a template variable)
- XSS: user data rendered into HTML without encoding / SVG uploaded and served
- EL/SpEL/OGNL injection: user data evaluated as an expression
- Prototype pollution: user-controlled object merged into application objects
- OS command injection via user data in a shell command string
- Log4Shell: log4j2 2.0-beta9–2.14.1 (or 2.15.0 with Thread Context lookups in a pattern layout) present + user data logged
- Unsafe deserialization: attacker-controlled bytes/string to a language-native deserializer
- XXE: XML parsed with external entity expansion or DTD processing enabled
- Billion Laughs: XML parsed without DTD processing disabled entirely
- Path traversal: user data in a file path without adequate normalization
- Zip Slip: archive extraction without path validation
- File upload: MIME not validated by content / uploaded file served without auth
- Mass assignment: request fields bound to model attributes without an allowlist
- ReDoS: catastrophically-backtracking regex applied to user-controlled input
- Sensitive data (tokens, keys, OTPs, PII) in responses to unprivileged actors
- Cross-user data access: query missing an owner/user filter

Set `cwe` on each hypothesis (e.g. CWE-89 SQL, CWE-943 NoSQL, CWE-90 LDAP, CWE-643 XPath, CWE-564 HQL,
CWE-1336 SSTI, CWE-79 XSS, CWE-917 EL injection and Log4Shell, CWE-1321 prototype pollution, CWE-78 OS
command, CWE-95 eval, CWE-117 log injection, CWE-502 deserialization, CWE-611 XXE, CWE-776 Billion Laughs,
CWE-22 path traversal and Zip Slip, CWE-434 file upload, CWE-915 mass assignment, CWE-1333 ReDoS, CWE-113
response header injection, CWE-200 sensitive data in responses, CWE-639 cross-user access).

## Forbidden

- Do not name a specific library as vulnerable without reading how the application uses it
- Do not assume a query builder or ORM is safe without reading the actual query construction
- Do not report mass assignment without reading the binding configuration
- Do not skip debug/test code paths — they are often the source of data leaks
- Do not assume XML parsing is safe or unsafe from the library name — read the parser construction and its
  entity/DTD settings (several common parsers, e.g. Java's JAXP factories, allow XXE by default)
- Do not report XSS for pure JSON APIs — only for HTML-rendering endpoints
- Do not report ReDoS without identifying the specific backtracking-vulnerable pattern
