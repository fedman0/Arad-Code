# SKILL: map-service-boundaries

## Contract

**Trigger:** After map-deployment-context.
**Phase:** 1 — Project Understanding
**Preconditions:** Service list, deployment context, DI map
**Escalates to:** trace-cross-service-messages, review-tenant-isolation

## Inputs
- repo_path
- service list with deployment info

## Procedure
1. Find all inter-service HTTP calls: HttpClient, IHttpClientFactory, RestClient, Feign, Refit usage.
2. Find all message bus interactions: IPublishEndpoint, IBus, KafkaProducer, RabbitMQ BasicPublish, SNS.Publish.
3. Find shared database access: are multiple services connecting to the same database/schema?
4. Find shared cache: Redis, Memcached — which services read/write which keys?
5. For each inter-service call: what headers/claims does the caller include? Is there a service-to-service auth mechanism (mTLS, service token, HMAC)?
6. Find the trust model: does ServiceB trust all claims forwarded from ServiceA without re-validation?
7. Find fan-out patterns: one request triggering messages to N services.
8. Find synchronous vs. asynchronous boundaries — async boundaries can decouple auth context.
9. Identify saga/orchestration patterns: who owns compensation logic?

## Required evidence
- Service communication graph (caller → callee, protocol, auth mechanism)
- Shared databases and their access patterns
- Shared cache key namespacing (or lack thereof)
- Trust model at each service boundary
- Services that re-trust forwarded identity claims

## Counterchecks
- Service-to-service mTLS does not validate the logical identity of the USER making the original request.
- A service token grants service-level access, not user-level access — the service must enforce user-level auth itself.
- Shared cache without tenant-keyed namespacing is a cross-tenant finding only if different tenants' data shares the same key space.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: blind trust of forwarded claims, shared DB without row-level isolation, cache key collision enabling cross-tenant read.

## Stop condition
When all inter-service edges are mapped with their auth mechanisms and trust model.

## Forbidden inferences
- Do not conclude a shared database is a finding without confirming what data is shared and whether tenant isolation exists at the query level.
- Do not assume message consumers validate message integrity; verify this explicitly.
