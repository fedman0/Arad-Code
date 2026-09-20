# SKILL: map-entry-points

## Contract

**Trigger:** After resolve-build-context. Run for each service.
**Phase:** 1 — Project Understanding
**Preconditions:** Service list, framework versions, dependency tree
**Escalates to:** resolve-dependency-injection, map-middleware-and-filters

## Inputs
- repo_path
- service: name, root path, framework

## Procedure
1. search_graph(label="Route") or search_graph(name_pattern="Controller|Handler|Resolver") to find HTTP entry points.
2. For ASP.NET Core: find [ApiController], [Route], [HttpGet/Post/Put/Delete/Patch] attributes. Map minimal API MapGet/MapPost calls.
3. For Express/Fastify/Koa: find app.get(), router.post(), fastify.register() patterns.
4. For Go: find http.HandleFunc, mux.Handle, gin.GET, echo.GET patterns.
5. For gRPC: find service definitions in .proto files and their server implementations.
6. For message consumers: find IConsumer<T>, @KafkaListener, @RabbitListener, bus.Subscribe, consumer.Receive patterns.
7. For background jobs: find IHostedService, Quartz.IJob, Hangfire attributes, cron expressions.
8. For CLI commands: find [Command], cobra.Command, click commands.
9. For each entry point, record: path/topic, HTTP method, handler qualified name, file:line, auth-related decorators/attributes.
10. Identify which entry points have no authentication decorator at all.

## Required evidence
- Complete entry point list per service with: kind, path, method, handler_qn, file:line
- Auth decorator/attribute presence per entry point
- Entry points with no auth decoration (flagged, not yet a finding)

## Counterchecks
- Absence of auth attribute does NOT mean unauthenticated — check global middleware, filters, and policies in map-middleware-and-filters before making that claim.
- An entry point decorated with [AllowAnonymous] is intentionally public; verify this is expected scope.
- Consumer/Job entry points may have different auth models — check the message source trust boundary.

## Output schema
Standard FINDINGS_SCHEMA. Populate entry_points_found list.
Hypotheses only for clear cases where both the path AND absence of any auth layer is confirmed.

Every `entry_points_found` entry MUST carry:
- `kind` — route / consumer / job / command / hook / callback. Peer comparison
  groups by kind, so a mislabelled consumer gets compared against HTTP routes.
- `auth_decorators` — every authorization marker present on that handler, verbatim
  (`@requires_scope`, `[Authorize(Policy="X")]`, `@login_required`). Use an empty
  list when there is genuinely none. This is the single field peer-consistency
  analysis reads: if you leave it empty on a protected route, that route becomes
  the apparent outlier and a real unprotected one is hidden.
- `notes` — describe the handler, never restate a decorator that is absent.
  Write "public by design" rather than "missing @requires_scope".
- `path` — the route template or the queue/topic/command name for non-routes.

Prefer `parse_file_structure` over grep when enumerating handlers: it returns
decorators and exact line ranges, which raises evidence quality from textual
(confidence capped at 4) to structural (capped at 7).

## Stop condition
When all HTTP routes, consumers, jobs, and CLI commands are enumerated.

## Forbidden inferences
- Do not conclude an endpoint is unauthenticated from the absence of [Authorize] alone.
- Do not assume all routes under a controller inherit the controller's auth — check individual method attributes.
- Do not treat a 404-returning endpoint as a non-entry point.
