# SKILL: resolve-dependency-injection

## Contract

**Trigger:** After map-entry-points. Run before security analysis skills.
**Phase:** 1 — Project Understanding
**Preconditions:** Entry point list, framework version
**Escalates to:** map-middleware-and-filters, review-object-authorization

## Inputs
- repo_path
- framework (ASP.NET Core / Spring / NestJS / Go / etc.)

## Procedure
1. Locate the DI registration site: Startup.cs / Program.cs / Module.cs / app.module.ts / wire.go.
2. search_graph(name_pattern="AddScoped|AddSingleton|AddTransient|services.Add") for .NET.
3. For each security-relevant interface, find all registered implementations.
4. Identify conditional registrations (if (env.IsDevelopment()), feature flags, environment variables).
5. Identify decorators / interceptors registered around security-relevant services.
6. Find open generic registrations that might resolve to unexpected implementations.
7. Identify any manual service locator patterns (IServiceProvider.GetService) that bypass DI.
8. For authorization: find IAuthorizationHandler, PolicyBuilder, IPermissionService registrations.
9. For multi-tenancy: find ITenantResolver, ITenantStore, ICurrentTenant registrations.

## Required evidence
- Interface → implementation mapping for: IAuthorizationService, ICurrentUser, ICurrentTenant, IRepository<T>, IPermissionChecker
- Conditional registrations (environment/flag-dependent)
- Any service locator usages that could resolve a different implementation at runtime
- Decorator chain order for security-relevant services

## Counterchecks
- A development-only registration does not affect production.
- Open generics resolve at runtime; multiple candidates mean the actual type must be confirmed via runtime config or convention.
- The wrong implementation being registered is only a finding if the security property differs from the expected one.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses relate to wrong implementation resolving (e.g., mock auth handler
registered in production, or dev-mode service leaking to staging).

## Stop condition
When all security-relevant interfaces have confirmed implementations for the production configuration.

## Forbidden inferences
- Do not assume the dev-only registration is the one used in production without checking environment detection logic.
- Do not conclude that an interface with one implementation is safe — interceptors and decorators can change behavior.
