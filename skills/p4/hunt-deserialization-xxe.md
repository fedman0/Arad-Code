# SKILL: hunt-deserialization-xxe

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

Run grep, read context with `get_code_snippet`, submit immediately. 2 tool calls per step max.

---

## Step 1 — Unsafe deserialization: Python

**pickle / marshal / shelve:**
```
grep(pattern="pickle\.loads\s*\(|pickle\.load\s*\(|marshal\.loads\s*\(|marshal\.load\s*\(|shelve\.open\s*\(", max_matches=20)
```

**YAML unsafe loaders:**
```
grep(pattern="yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.(Full|Loader|UnsafeLoader|CLoader)\b|yaml\.load\s*\(\s*\w+\s*\)|yaml\.unsafe_load\s*\(", max_matches=20)
```

**Other unsafe deserializers:**
```
grep(pattern="jsonpickle\.decode\s*\(|dill\.load\s*\(|dill\.loads\s*\(|torch\.load\s*\(|joblib\.load\s*\(", max_matches=20)
```

For each match: does the data source derive from HTTP request body, file upload, Redis, database field, or any network-received value? Safe: `pickle.loads` on data you generated yourself and signed.

→ Submit: violated_invariant="Untrusted data passed to [pickle/yaml.load/dill]; arbitrary code execution on deserialization", severity=10, confidence=8, exposure="internet"

---

## Step 2 — Unsafe deserialization: Java

**ObjectInputStream (Java native):**
```
grep(pattern="new ObjectInputStream\s*\(|ObjectInputStream\s*\(\s*\w+\s*\)|\.readObject\s*\(\s*\)", max_matches=20)
```

**Jackson enableDefaultTyping (polymorphic deserialization):**
```
grep(pattern="enableDefaultTyping\s*\(|activateDefaultTyping\s*\(|ObjectMapper\s*\(\s*\).*enableDefaultTyping|BLOCK_UNSAFE_POLYMORPHIC_BASE_TYPES", max_matches=20)
```

**XStream / XMLDecoder:**
```
grep(pattern="new XStream\s*\(|xstream\.fromXML\s*\(|new XMLDecoder\s*\(|XMLDecoder\s*\.readObject\s*\(", max_matches=20)
```

For each `new ObjectInputStream`: trace the constructor argument — is it from `request.getInputStream()`, a socket, or a user-uploaded file? SafeDeserialization wrappers like `ValidatingObjectInputStream` with allowed classes are safe.

→ Submit: violated_invariant="Java ObjectInputStream/XStream deserializes attacker-controlled bytes; known gadget chains lead to RCE", severity=10, confidence=8, exposure="internet"

---

## Step 3 — Unsafe deserialization: PHP

```
grep(pattern="unserialize\s*\(\s*\\\$_(GET|POST|REQUEST|COOKIE)|unserialize\s*\(\s*\\\$\w+\s*\)", max_matches=20)
```

```
grep(pattern="unserialize\s*\(\s*base64_decode\s*\(|unserialize\s*\(\s*file_get_contents", max_matches=15)
```

For each `unserialize`: is the input user-controlled? PHP object injection enables POP chains when target classes have `__wakeup`/`__destruct`.

→ Submit: violated_invariant="PHP unserialize() called on user-supplied data; POP chain exploitation via magic methods", severity=10, confidence=8, exposure="internet"

---

## Step 4 — Unsafe deserialization: Ruby

**Marshal (RCE):**
```
grep(pattern="Marshal\.load\s*\(|Marshal\.restore\s*\(", max_matches=15)
```

**YAML unsafe loaders:**
```
grep(pattern="YAML\.unsafe_load\s*\(|Psych\.unsafe_load\s*\(|YAML\.load\s*\([^)]*\)", max_matches=20)
```

**Rails cookie deserializer set to marshal:**
```
grep(pattern="cookies_serializer\s*=\s*:marshal|cookies_serializer\s*=\s*:hybrid", max_matches=10)
```

→ Submit: violated_invariant="Ruby Marshal.load/YAML.unsafe_load on user data; arbitrary object instantiation leads to RCE", severity=10, confidence=8, exposure="internet"

---

## Step 5 — Unsafe deserialization: C#

```
grep(pattern="BinaryFormatter\s*\(\s*\).*Deserialize\s*\(|new BinaryFormatter\s*\(\s*\)|SoapFormatter.*Deserialize\s*\(|NetDataContractSerializer.*Deserialize\s*\(", max_matches=20)
```

```
grep(pattern="LosFormatter.*Deserialize\s*\(|ObjectStateFormatter.*Deserialize\s*\(|TypeNameHandling\.(All|Auto|Objects|Arrays)", max_matches=15)
```

→ Submit: violated_invariant="BinaryFormatter/SoapFormatter/NetDataContractSerializer on untrusted data; .NET gadget chain RCE", severity=10, confidence=8, exposure="internet"

---

## Step 6 — Unsafe deserialization: JavaScript / Node

```
grep(pattern="require\s*\(['\"]node-serialize['\"].*unserialize\s*\(|require\s*\(['\"]serialize-to-js['\"].*deserialize\s*\(", max_matches=15)
```

```
grep(pattern="eval\s*\(\s*JSON\.parse\s*\(|Function\s*\(\s*JSON\.parse\s*\(", max_matches=15)
```

→ Submit: violated_invariant="node-serialize/serialize-to-js deserializes user input; IIFE in serialized data executes arbitrary JS", severity=10, confidence=8, exposure="internet"

---

## Step 7 — XXE: Java (XML parsers not hardened)

**XMLInputFactory external entities enabled:**
```
grep(pattern="XMLInputFactory.*setProperty.*isSupportingExternalEntities.*true|XMLInputFactory.*setProperty.*IS_SUPPORTING_EXTERNAL_ENTITIES.*true", max_matches=15)
```

**DocumentBuilderFactory without DTD disabled:**
```
grep(pattern="DocumentBuilderFactory\.newInstance\s*\(\s*\)", max_matches=20)
```

For each `DocumentBuilderFactory.newInstance()`: verify `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` is called on the factory. If not, XXE is live.

**SAXParserFactory / TransformerFactory:**
```
grep(pattern="SAXParserFactory\.newInstance\s*\(\s*\)|SAXTransformerFactory\.newInstance\s*\(\s*\)|TransformerFactory\.newInstance\s*\(\s*\)", max_matches=15)
```

→ Submit: violated_invariant="XML parser [factory] instantiated without disabling external entity processing; XXE reads arbitrary files / SSRF", severity=9, confidence=7, exposure="internet"

---

## Step 8 — XXE: PHP (libxml LIBXML_NOENT)

```
grep(pattern="simplexml_load_string\s*\(.*LIBXML_NOENT|simplexml_load_file\s*\(.*LIBXML_NOENT|DOMDocument.*loadXML\s*\(.*LIBXML_NOENT", max_matches=15)
```

```
grep(pattern="libxml_disable_entity_loader\s*\(\s*false\s*\)|libxml_set_external_entity_loader", max_matches=15)
```

→ Submit: violated_invariant="PHP XML parser loaded with LIBXML_NOENT flag or entity loader enabled; XXE via user-supplied XML", severity=9, confidence=8, exposure="internet"

---

## Step 9 — XXE: Python (stdlib xml parsers)

```
grep(pattern="xml\.etree\.ElementTree\.parse\s*\(|xml\.etree\.ElementTree\.fromstring\s*\(|xml\.dom\.minidom\.parse\s*\(|xml\.sax\.parse\s*\(|xml\.parsers\.expat\.ParserCreate", max_matches=20)
```

For each match: is `defusedxml` imported or used? Python stdlib xml parsers are vulnerable to XXE by default when user-supplied XML is parsed.

Safe signal: `import defusedxml.ElementTree as ET` instead of `xml.etree.ElementTree`.

→ Submit: violated_invariant="Python stdlib xml parser processes user XML without defusedxml; XXE reads local files", severity=9, confidence=7, exposure="internet"

---

## Step 10 — XXE: C# (.NET XmlDocument / XmlReader)

**XmlDocument without XmlResolver = null:**
```
grep(pattern="new XmlDocument\s*\(\s*\)|XmlDocument\s*\(\s*\)", max_matches=20)
```

For each `new XmlDocument()`: look for `XmlDocument { XmlResolver = null }` or `doc.XmlResolver = null` in the next 5 lines. If absent, external entity resolution is enabled.

**XmlReader without DtdProcessing = Prohibit:**
```
grep(pattern="XmlReader\.Create\s*\(|new XmlReaderSettings\s*\(\s*\)", max_matches=20)
```

For each `new XmlReaderSettings()`: verify `DtdProcessing = DtdProcessing.Prohibit` is set.

→ Submit: violated_invariant="C# XmlDocument/XmlReader created without disabling DTD/external entity processing; XXE via user XML", severity=9, confidence=7, exposure="internet"

---

## Step 11 — XXE: Kotlin / Scala

```
grep(pattern="DocumentBuilderFactory\.newInstance\s*\(\s*\)|SAXParserFactory\.newInstance\s*\(\s*\)|XMLInputFactory\.newInstance\s*\(\s*\)", max_matches=20)
```

```
grep(pattern="\\\$XMLFACTORY\.setProperty\s*\(.*isSupportingExternalEntities.*true|javax\.xml\.stream\.XMLInputFactory\.newInstance", max_matches=15)
```

→ Submit: violated_invariant="Kotlin/Scala XML factory instantiated without XXE mitigations; external entity injection possible", severity=9, confidence=7, exposure="internet"

---

## Step 12 — XXE: Swift (XMLParser / XMLDocument)

```
grep(pattern="shouldResolveExternalEntities\s*=\s*true", max_matches=15)
```

```
grep(pattern="XMLParser\s*\(|XMLDocument\s*\(.*url|NSXMLDocument\s*\(", max_matches=20)
```

For each `XMLParser` init: check if `shouldResolveExternalEntities` is set to `false` immediately after. Default value allows external entities — any `XMLParser` without explicit `false` is vulnerable when parsing untrusted XML.

→ Submit: violated_invariant="Swift XMLParser allows external entity resolution; XXE reads local files or triggers SSRF", severity=9, confidence=7, exposure="internet"

---

## Step 13 — Unsafe deserialization: Kotlin (Android / backend)

**Native Java ObjectInputStream:**
```
grep(pattern="ObjectInputStream\s*\(|readObject\s*\(\s*\)", max_matches=20)
```

**Jackson enableDefaultTyping (same as Java):**
```
grep(pattern="enableDefaultTyping\s*\(|activateDefaultTyping\s*\(|ObjectMapper\(\)\.enable\s*\(MapperFeature", max_matches=15)
```

For each: trace the constructor argument — is it a network stream, user upload, or Redis/DB-loaded byte[]? ValidatingObjectInputStream with an explicit allowlist is safe.

→ Submit: violated_invariant="Kotlin ObjectInputStream deserializes attacker-controlled bytes; gadget chains lead to RCE", severity=10, confidence=8, exposure="internet"

---

## Step 14 — Unsafe deserialization: Go (encoding/gob, json.Unmarshal to interface{})

```
grep(pattern="gob\.NewDecoder\s*\(|gob\.Decode\s*\(", max_matches=15)
```

```
grep(pattern="json\.Unmarshal\s*\([^,]+,\s*&\w+Interface\|json\.Unmarshal\s*\([^,]+,\s*&interface", max_matches=15)
```

```
grep(pattern="yaml\.Unmarshal\s*\([^,]+,\s*&\w+\)|xml\.Unmarshal\s*\([^,]+,\s*&\w+\)", max_matches=20)
```

For each: is the source `r.Body`, a user-uploaded file, or a Redis/Kafka message with attacker-controlled content? Go's standard library is generally safe against RCE, but `gob` with complex types can expose memory corruption.

→ Submit: violated_invariant="Go gob.Decode on untrusted data; gob encoding trusts type information in the stream", severity=7, confidence=6, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
