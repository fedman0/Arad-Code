# SKILL: resolve-build-context

## Contract

**Trigger:** After inventory-repository completes.
**Phase:** 1 — Project Understanding
**Preconditions:** Service list (Repository Inventory section of the Threat Model in Known Context)
**Escalates to:** map-entry-points

## Inputs
- repo_path
- service_list from the Repository Inventory section of the Threat Model

## Procedure
1. For each service, read the project/build file (*.csproj, package.json, go.mod, etc.).
2. Extract direct dependencies and their versions.
3. Identify which projects are libraries vs. deployable services.
4. Find conditional compilation flags (#if DEBUG, build constraints, feature flags affecting compilation).
5. Identify parts of the codebase excluded from default build (commented-out project refs, optional modules).
6. Check for multi-target frameworks (e.g., net6.0;net8.0) — different targets may have different code paths.
7. Find NuGet/npm/pip packages known for security-relevant behavior: authentication libraries, serializers, query builders, template engines, HTTP clients.
8. Check for package version pinning vs. floating ranges.

## Required evidence
- Per-service: build file path, framework version, target runtime
- Direct dependency list with versions for each service
- Conditional compilation flags that affect security-relevant code
- Security-relevant packages identified (serializers, auth libs, HTTP clients, query builders)
- Any unbuild/excluded code sections

## Counterchecks
- Multi-target projects: a guard present in one target may not exist in another.
- Debug-only compilation blocks (#if DEBUG) do not contribute to production attack surface.
- Transitive dependency vulnerabilities are out of scope unless a direct call chain can be traced.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses at this phase relate to dangerous transitive dependencies
with known CVEs that are reachable (must have evidence of call chain, not just presence).
Set `cwe` to the CVE's own CWE when known, otherwise CWE-1395 (dependency on a vulnerable third-party component).

Persist the build context (per-service build file, framework and runtime version, security-relevant packages with versions, conditional compilation flags) with `amend_threat_model` as a short `## Build Context` section (if no threat model exists yet,
call `save_threat_model` with `## Overview`, `## Trust Boundaries`, `## Attack Surface`, `## Severity Calibration`
and this section). Later skills read it from the Threat Model in Known Context.

## Stop condition
When every service has a resolved dependency tree and framework version.

## Forbidden inferences
- Do not report a dependency CVE as a finding without tracing actual usage in the codebase.
- Do not assume a floating version range resolves to a vulnerable version without checking lock file.
- Do not assume debug compilation paths are reachable in production.
