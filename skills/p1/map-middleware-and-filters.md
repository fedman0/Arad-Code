---
order: 60
---

# SKILL: map-middleware-and-filters

## Contract

**Trigger:** After resolve-dependency-injection.
**Phase:** 1 — Project Understanding
**Preconditions:** DI map and framework version (Threat Model in Known Context), entry point list (Known entry points)
**Escalates to:** understand-authorization-and-access, hunt-missing-authz-on-sensitive-endpoints

## Inputs
- repo_path
- framework

## Procedure
1. Find the middleware pipeline construction: app.Use*, app.UseMiddleware<T>, app.UsePipeline.
2. Record the order of middleware: authentication → authorization → routing → endpoint.
3. For ASP.NET Core: find action filters (IActionFilter, IAuthorizationFilter, IResultFilter) and their global vs. controller vs. method scope.
4. For MediatR: find IPipelineBehavior<TRequest, TResponse> implementations and registration order.
5. For NestJS: find guards (@UseGuards), interceptors, pipes — global, controller, method scope.
6. Find exception handling middleware — does it catch auth errors and swallow them, allowing execution to continue?
7. Identify rate-limiting, CORS, CSRF, and anti-forgery middleware and their configuration.
8. Determine which endpoints are BEFORE the authentication middleware (short-circuit paths).
9. Check for endpoint filters that skip authorization (e.g., [AllowAnonymous], RequireAuthorization(false)).
10. For each discovered entry point, determine which middleware runs before the handler executes.

## Required evidence
- Ordered middleware pipeline list for each service
- Global vs. scoped filters and their coverage
- Endpoints that execute before authentication middleware
- Exception handling behavior on auth failure (swallow vs. propagate)
- Anti-CSRF token validation scope

## Counterchecks
- Middleware registered globally but with path exclusions — check the exclusion patterns.
- Filters marked with Order property — lower order executes first; verify the auth filter order.
- Short-circuit middleware may bypass authorization for specific paths; check those paths against entry point list.

## Output schema
Standard FINDINGS_SCHEMA. Populate guards_found for each confirmed middleware acting as a guard.
Hypotheses for: missing auth middleware on a sensitive path, CSRF disabled globally, auth exception swallowed.
Set `cwe` on each hypothesis (e.g. CWE-306 missing authentication, CWE-862 missing authorization, CWE-352 CSRF disabled, CWE-636 auth failure swallowed so execution continues).

Persist the ordered middleware pipeline per service (global vs. scoped filters, pre-auth endpoints, auth-failure behavior, CSRF scope) with `amend_threat_model` as a short `## Middleware Map` section (if no threat model exists yet,
call `save_threat_model` with `## Overview`, `## Trust Boundaries`, `## Attack Surface`, `## Severity Calibration`
and this section). Later skills read it from the Threat Model in Known Context.

## Stop condition
When every entry point has a fully mapped middleware chain from ingress to handler.

## Forbidden inferences
- Do not conclude an endpoint lacks CSRF protection without checking both the global middleware AND method-level attributes.
- Do not assume middleware order is the same as registration order — some frameworks use explicit ordering.
