# SKILL: review-deserialization

## Contract

**Trigger:** Phase 4. Run for any service deserializing external data with type information.
**Phase:** 4 — Security Analysis
**Preconditions:** Entry point map, serialization library
**Escalates to:** trace-input-to-effect

## Inputs
- repo_path
- serializer_library: Newtonsoft.Json | System.Text.Json | Jackson | BinaryFormatter | ObjectInputStream | pickle | marshal | PHP unserialize

## Procedure
1. search_code(pattern="JsonConvert.Deserialize|JsonSerializer.Deserialize|ObjectInputStream|pickle.loads|unserialize|BinaryFormatter") to find deserialize calls.
2. For each deserialization call: what type is being deserialized? Is TypeNameHandling or polymorphic type info enabled?
3. For Newtonsoft.Json: is TypeNameHandling != None? If so, is TypeNameAssemblyFormatHandling.Full used?
4. For Java ObjectInputStream: is the class being deserialized from untrusted data? Is there a whitelist of allowed classes?
5. For Python pickle/marshal: is the data from user input? Pickle is RCE-equivalent.
6. For PHP unserialize: is there a POP chain available? Are magic methods (__wakeup, __destruct) on loaded classes dangerous?
7. Find gadget chain candidates: search_graph(name_pattern="__wakeup|__destruct|Dispose|Finalize") for dangerous magic methods.
8. For custom binary protocols: is the length field validated before allocation?
9. Find JWT: is the header's "alg" field accepted as-is, allowing algorithm confusion (e.g., alg:none, RS256→HS256)?

## Required evidence
- All deserialization calls with: library, type control, data source
- TypeNameHandling configuration for JSON
- Class whitelist for Java ObjectInputStream
- Pickle/unserialize with user data: confirmed or denied
- JWT algorithm validation: explicit allowlist confirmed or absent

## Counterchecks
- System.Text.Json has no TypeNameHandling — not vulnerable to type confusion by default.
- Jackson polymorphic type handling requires @JsonTypeInfo with USE.CLASS — check if this annotation is present.
- SerializationBinder in .NET can restrict allowed types — check if it's registered.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses require: confirmed untrusted data reaching deserializer AND confirmed type-control mechanism enabled AND confirmed gadget chain reachability.

## Stop condition
When all deserializers handling external data are classified for type-control exposure.

## Forbidden inferences
- Do not report Newtonsoft.Json as vulnerable without confirming TypeNameHandling != None.
- Do not report Java deserialization without confirming the stream comes from an untrusted source.
