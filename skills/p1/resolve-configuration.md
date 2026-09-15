# SKILL: resolve-configuration

## Contract

**Trigger:** Early in Phase 1, after inventory-repository.
**Phase:** 1 — Project Understanding
**Preconditions:** Config file locations from inventory-repository
**Escalates to:** map-deployment-context, review-cryptographic-usage

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
- CORS AllowAnyOrigin is only a finding if the endpoint uses cookie-based auth (CORS does not protect token auth).

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: hardcoded secrets, dev settings reachable in prod, DisableAuth flags.

## Stop condition
When the complete effective configuration for production is understood including override chain.

## Forbidden inferences
- Do not flag CORS AllowAnyOrigin as a CSRF vector for Bearer token-only APIs.
- Do not report a secret in .env.example as a leaked credential without confirming it matches production.
- Do not assume ASPNETCORE_ENVIRONMENT=Production means all Development-only config is disabled without checking.
