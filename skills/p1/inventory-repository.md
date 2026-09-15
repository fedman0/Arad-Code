# SKILL: inventory-repository

## Contract

**Trigger:** First skill to run on any new repository. Run before all others.
**Phase:** 1 — Project Understanding
**Preconditions:** repo_path available, commit known
**Escalates to:** resolve-build-context

## Inputs
- repo_path: path to the repository root
- commit: current HEAD

## Procedure
1. Call get_architecture() to get the top-level project map.
2. search_graph(label="Module") and search_graph(label="File") to enumerate root namespaces and file structure.
3. Detect languages: look for *.csproj, package.json, go.mod, Cargo.toml, pom.xml, build.gradle, *.gemspec.
4. Identify service boundaries: directories with their own entry-point files (Program.cs, main.go, index.ts, main.py, Application.java).
5. Locate generated code directories (obj/, generated/, .g.cs, *.pb.go, *.pb.ts, protobuf outputs).
6. Locate test projects: *Test*, *Tests*, *Spec*, __tests__, test/.
7. List infrastructure-as-code files: Dockerfile, docker-compose.*, *.yaml in k8s/ or helm/, terraform/ or *.tf.
8. Find configuration files: appsettings*.json, .env*, config/*.yaml, secrets.*.
9. Scan for FIXME, TODO, HACK, XXX, SECURITY, NOAUTH comments — these are research leads.

## Required evidence
- Language list with file count per language
- Service/project list (name, root path, entry point file)
- Generated code directories (excluded from manual review)
- Test project list
- Config file locations
- Any SECURITY/NOAUTH/FIXME comments found

## Counterchecks
- Do not assume a directory is a service without confirming an entry point.
- Generated code findings are excluded from the hypothesis set (mark coverage as excluded with reason).
- Test-only code vulnerabilities need a separate invariant source (cannot transfer to production path without verification).

## Output schema
Standard FINDINGS_SCHEMA. hypotheses should be empty or minimal at this phase.
Coverage items should map every discovered service and significant directory.

## Stop condition
When all directories at depth 2 are classified (service / library / generated / test / infra / config).

## Forbidden inferences
- Do not infer that a pattern in test code exists in production code.
- Do not flag generated protobuf files as injection points without tracing to production parsing code.
- Do not conclude a service is unauthenticated from the absence of auth files in its directory.
