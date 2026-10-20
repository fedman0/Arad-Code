# SKILL: resolve-configuration

## Contract

**Trigger:** Early in Phase 1, after inventory-repository.
**Phase:** 1 — Project Understanding
**Preconditions:** Config file locations (Repository Inventory section of the Threat Model in Known Context)
**Escalates to:** map-deployment-context, hunt-insecure-config-defaults, hunt-secrets-detection

## Inputs
- repo_path
- config file locations

## Procedure
1. Read all configuration files: appsettings.json, appsettings.Production.json, .env.example, config/*.yaml.
2. Identify the override order: which config source wins (env var > secrets manager > appsettings.Production > appsettings).
3. Find security-relevant settings: JWT issuer/audience/signing-key source, CORS allowed origins, cookie secure flags, TLS settings, auth scheme names.
4. Identify settings that can be overridden by environment variables — and whether an attacker who can set env vars escalates privilege.
5. Find hardcoded credentials or secrets in config files checked into the repo.
6. Find development-only settings that could be accidentally active in production (e.g., AllowAll CORS, DisableAuth=true).
7. Locate feature flag configuration: which flags are on/off in production vs. dev.
8. Find connection strings — are they pointing to shared databases across tenants?

## Required evidence
- Config override chain
- Security-relevant settings and their values per environment
- Any hardcoded secrets or credentials
- Dev-only settings that could reach production
- Feature flags affecting auth or data isolation

## Counterchecks
- A setting in appsettings.Development.json only matters if the app runs in Development mode in production.
- Hardcoded dev credentials are only a finding if they could authenticate against production systems.
- A wildcard origin (`*`, AllowAnyOrigin) is not credentialed — browsers refuse to expose credentialed responses with `*` — so it only matters for data readable without credentials. The exploitable case is a reflected or pattern-matched origin (e.g. `SetIsOriginAllowed(_ => true)`, echoing the request `Origin`) combined with `Access-Control-Allow-Credentials: true` on cookie-authenticated endpoints.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: hardcoded secrets, dev settings reachable in prod, DisableAuth flags.
Set `cwe` on each hypothesis (e.g. CWE-798 hardcoded secret, CWE-1188 insecure development default reachable in production, CWE-306 authentication disabled by flag).

Persist the effective production configuration (override chain, security-relevant settings per environment, auth/isolation feature flags) with `amend_threat_model` as a short `## Configuration` section (if no threat model exists yet,
call `save_threat_model` with `## Overview`, `## Trust Boundaries`, `## Attack Surface`, `## Severity Calibration`
and this section). Later skills read it from the Threat Model in Known Context.

## Stop condition
When the complete effective configuration for production is understood including override chain.

## Forbidden inferences
- Do not flag a permissive CORS origin on Bearer-token-only APIs — the browser never attaches the token to a cross-origin request.
- Do not report a secret in .env.example as a leaked credential without confirming it matches production.
- Do not assume ASPNETCORE_ENVIRONMENT=Production means all Development-only config is disabled without checking.
