---
order: 70
tier: fast
max_turns: 40
---

# SKILL: map-deployment-context

## Contract

**Trigger:** After resolve-configuration.
**Phase:** 1 — Project Understanding
**Preconditions:** Config file locations and service list (Repository Inventory and Configuration sections of the Threat Model in Known Context)
**Escalates to:** map-service-boundaries

## Inputs
- repo_path
- infrastructure file locations (Dockerfile, k8s manifests, terraform)

## Procedure
1. Read Dockerfiles: identify exposed ports, base images, USER directive (running as root?), volume mounts.
2. Read k8s deployments/services: identify NodePort vs. ClusterIP vs. LoadBalancer services. Which services are internet-facing?
3. Read ingress rules: path-based routing, TLS termination, auth annotations (oauth2-proxy, JWT middleware at ingress).
4. Read service accounts and RBAC: what k8s permissions does each service pod have?
5. Find secrets management: k8s secrets, Vault agent, CSI driver, AWS Secrets Manager sidecar.
6. Identify network policies: which pods can talk to which? Default deny or default allow?
7. Check resource limits: CPU/memory limits set? (relevant for resource exhaustion analysis)
8. Find environment variable injection sources: ConfigMap, Secret, Downward API.
9. Cross-reference: for each service, confirm which config values come from env vars vs. files vs. secrets manager.

## Required evidence
- Internet-facing surface: which services and ports are reachable from outside the cluster
- Auth at ingress: what auth is enforced before traffic reaches the service
- Pod permissions: service account, k8s RBAC grants
- Network policy: default deny/allow, inter-service communication rules
- Secret injection mechanism per service

## Counterchecks
- Ingress-level auth does not protect direct pod-to-pod traffic unless network policy enforces it.
- ClusterIP services are not internet-facing unless explicitly proxied.
- Vault agent injection does not prevent the app from logging secret values.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: service running as root with sensitive mounts, no network policy (default allow), auth bypass via direct pod IP, over-privileged service account.
Set `cwe` on each hypothesis (e.g. CWE-250 root container, CWE-284 missing network policy, CWE-288 direct pod access bypassing ingress auth, CWE-269 over-privileged service account).

Persist the deployment context (internet-facing services and ports, ingress auth, pod permissions, network policy, secret injection) with `amend_threat_model` as a short `## Deployment Context` section (if no threat model exists yet,
call `save_threat_model` with `## Overview`, `## Trust Boundaries`, `## Attack Surface`, `## Severity Calibration`
and this section). Later skills read it from the Threat Model in Known Context.

## Stop condition
When every internet-facing entry point has a confirmed auth layer and the cluster communication model is mapped.

## Forbidden inferences
- Do not assume a ClusterIP service is unreachable if there is no network policy — internal attackers or compromised pods can reach it.
- Do not conclude TLS at ingress means E2E encryption without checking inter-service traffic.
