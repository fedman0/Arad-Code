---
parallel: true
requires: [iac]
---

# SKILL: hunt-iac-cicd-misconfig

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns (p_terraform, p_kubernetes, p_dockerfile, p_github-actions, p_trailofbits)

These are **configuration patterns** — no runtime data flow to trace. Each match is inherently the misconfiguration. Verify the resource type and intent; skip only if the setting is explicitly justified (e.g. intentional public access).

---

# Part A — Terraform (AWS / Azure / GCP)

## Step 1 — S3 / storage buckets: public access

```
grep(pattern="resource\s+\"aws_s3_bucket(_acl|_public_access_block|_policy)?\"\s+|acl\s*=\s*\"(public-read|public-read-write|authenticated-read)\"|(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false", file_glob="*.tf", max_matches=15)
```

For each S3 bucket resource: `read_file` the `.tf` file around the match to check:
- `acl = "public-read"` or `acl = "public-read-write"` → **SUBMIT**
- `aws_s3_bucket_public_access_block` resource with `block_public_acls = false` → **SUBMIT**
- `block_public_acls = true`, `ignore_public_acls = true`, `block_public_policy = true`, `restrict_public_buckets = true` → **SKIP**

→ Submit: violated_invariant="S3 bucket configured with public ACL; any internet user can read/write bucket objects", severity=9, confidence=9, exposure="internet", cwe="CWE-732"

---

## Step 2 — Security groups / firewall rules: open to world

```
grep(pattern="ingress\s*\{[^}]*\"0\.0\.0\.0/0\"|resource\s+\"aws_security_group_rule\"[^}]*\"ingress\"[^}]*\"0\.0\.0\.0/0\"|resource\s+\"aws_vpc_security_group_ingress_rule\"[^}]*\"0\.0\.0\.0/0\"", file_glob="*.tf", multiline=true, max_matches=20)
```

```
grep(pattern="source_ranges\s*=\s*\[[^\]]*\"0\.0\.0\.0/0\"|source_address_prefix(es)?\s*=\s*\[?\s*\"(\*|0\.0\.0\.0/0|Internet|Any)\"|cidr_ipv4\s*=\s*\"0\.0\.0\.0/0\"|ipv6_cidr_blocks\s*=\s*\[[^\]]*\"::/0\"", file_glob="*.tf", max_matches=20)
```

The multiline grep prints the whole block up to the CIDR, so `from_port`/`to_port` are visible; for single-line hits `read_file` the resource. Egress rules to `0.0.0.0/0` are normal — only ingress counts. For each match: what port? Port 22 (SSH), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB) open to `0.0.0.0/0` → critical. Port 80/443 to world → normal for web servers, skip.

→ Submit: violated_invariant="Security group allows [protocol/port] from 0.0.0.0/0 to non-web port; database/admin service directly exposed to internet", severity=9, confidence=9, exposure="internet", cwe="CWE-284"

---

## Step 3 — RDS / database: no encryption, public, deletion protection off

```
grep(pattern="resource\s+\"aws_db_instance\"\s+|resource\s+\"aws_rds_cluster\"\s+", max_matches=15)
```

For each RDS instance: check for:
- `storage_encrypted = false` (or absent, defaults to false) → **SUBMIT**
- `publicly_accessible = true` → **SUBMIT**
- `deletion_protection = false` (or absent) → note as lower severity finding

```
grep(pattern="storage_encrypted\s*=\s*false|publicly_accessible\s*=\s*true|backup_retention_period\s*=\s*0", max_matches=15)
```

→ Submit: violated_invariant="RDS database unencrypted at rest OR publicly accessible; data exposed if EBS snapshot leaked or DB directly reachable from internet", severity=8, confidence=9, exposure="internet", cwe="CWE-311"

---

## Step 4 — Lambda / compute: hardcoded credentials in environment

```
grep(pattern="^\s*environment\s*\{|^\s*variables\s*=\s*\{", file_glob="*.tf", max_matches=15)
```

For each Lambda environment block: `read_file` the `.tf` file around the match to check variable names. Look for `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `DB_PASSWORD`, `API_KEY`, `SECRET` in the `variables` map.

```
grep(pattern="\"?(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|[A-Z_]*(PASSWORD|SECRET|API_KEY|TOKEN))\"?\s*=\s*\"[^\"$]+\"", file_glob="*.tf", max_matches=15)
```

→ Submit: violated_invariant="AWS Lambda environment variable contains hardcoded credential; credential visible in Lambda console, CloudTrail logs, and AWS API responses", severity=9, confidence=9, exposure="internet", cwe="CWE-798"

---

## Step 5 — Terraform: unencrypted data stores (Kinesis, EBS, RDS snapshots)

```
grep(pattern="resource\s+\"aws_kinesis_stream\"|encryption_type\s*=\s*\"NONE\"", file_glob="*.tf", max_matches=15)
```

```
grep(pattern="resource\s+\"aws_ebs_volume\"\s+|encrypted\s*=\s*false", file_glob="*.tf", max_matches=15)
```

For each `aws_kinesis_stream` / `aws_ebs_volume` resource: `read_file` the block — no `encryption_type = "KMS"` (Kinesis) or no `encrypted = true` (EBS, unless account-level EBS default encryption is enabled) means the data is stored unencrypted.

→ Submit: violated_invariant="AWS Kinesis stream / EBS volume has encryption disabled; data stored in plaintext accessible if physical media or snapshot is obtained", severity=7, confidence=9, exposure="internet", cwe="CWE-311"

---

# Part B — Kubernetes (YAML manifests)

## Step 6 — Privileged containers / host namespace sharing

```
grep(pattern="privileged:\s*true|hostPID:\s*true|hostIPC:\s*true|hostNetwork:\s*true", max_matches=20)
```

No flow verification needed — these YAML keys are configuration facts. Confirm context is a Kubernetes manifest (`kind: Pod`, `kind: Deployment`, etc.).

→ Submit: violated_invariant="Container runs with privileged=true or hostPID/hostIPC/hostNetwork=true; container can escape to host — reads host processes, network interfaces, or gains root on node", severity=10, confidence=9, exposure="internal", cwe="CWE-250"

---

## Step 7 — Docker socket mounted as volume (container escape)

```
grep(pattern="/var/run/docker\.sock", max_matches=15)
```

For each match: `read_file` around the match to confirm this is a `hostPath` volume mount in a Kubernetes pod/deployment spec (or a Docker Compose `volumes:` bind mount). Mounting the Docker socket into a container gives it full control of the Docker daemon (and therefore the host).

→ Submit: violated_invariant="Docker socket /var/run/docker.sock mounted into container; any process in the container can create privileged containers and escape to host root", severity=10, confidence=9, exposure="internal", cwe="CWE-250"

---

## Step 8 — Writable root filesystem / seccomp disabled

```
grep(pattern="readOnlyRootFilesystem:\s*false|seccompProfile\s*:\s*\{\s*type:\s*['\"]?Unconfined|^\s*type:\s*['\"]?Unconfined", max_matches=15)
```

```
grep(pattern="seccomp\.security\.alpha\.kubernetes\.io/pod:\s*['\"]?unconfined|container\.(seccomp\.security\.alpha|apparmor\.security\.beta)\.kubernetes\.io/[^:]+:\s*['\"]?unconfined|seccomp[:=]unconfined", max_matches=10)
```

→ Submit: violated_invariant="Container has writable root filesystem and/or seccomp disabled; exploited process can modify binaries and make unrestricted syscalls", severity=7, confidence=8, exposure="internal", cwe="CWE-250"

---

## Step 9 — allowPrivilegeEscalation not set / runAsRoot

```
grep(pattern="allowPrivilegeEscalation:\s*true|runAsUser:\s*0\b|runAsNonRoot:\s*false", max_matches=20)
```

```
grep(pattern="(add|cap_add):[ \t]*\n([ \t]*-[ \t]*\S+[ \t]*\n)*?[ \t]*-[ \t]*['\"]?(CAP_)?(SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|ALL)\b|(add|cap_add):[ \t]*\[[^\]]*(SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|ALL)", multiline=true, max_matches=15)
```

→ Submit: violated_invariant="Container allows privilege escalation or runs as UID 0 / adds dangerous capabilities; setuid binary in container grants root access", severity=8, confidence=9, exposure="internal", cwe="CWE-250"

---

# Part C — Dockerfile / Docker Compose

## Step 10 — Running as root user in Dockerfile

```
grep(pattern="^USER\s+root\b|^USER\s+0\b", max_matches=15)
```

```
grep(pattern="^FROM\s+", file_glob="*Dockerfile*", max_matches=20)
```

The second grep lists every Dockerfile (and its stages) so you can spot files with no `USER` directive at all. For each Dockerfile that matches (or has no `USER` directive): read the **full Dockerfile** with `read_file` (Dockerfiles are not indexed symbols).

**Verify** — multi-stage builds require reading the whole file:
1. Is `USER root` in a **build stage** (before a `FROM ... AS final` line)? Build stages running as root are common (need root to install packages). What matters is the **final stage**.
2. After the last `FROM` line, is there a `USER <non-root>` instruction before `CMD`/`ENTRYPOINT`? If yes → **SKIP**.
3. Last `FROM` stage has no `USER` directive, or has `USER root` without a subsequent `USER` change → **SUBMIT**.

→ Submit: violated_invariant="Dockerfile final stage runs as root (no USER directive or USER root); container process has UID 0 — any app exploit gives root inside the container", severity=7, confidence=8, exposure="internal", cwe="CWE-250"

---

## Step 11 — Docker Compose: ports exposed on all interfaces / privileged mode

```
grep(pattern="privileged:\s*true", max_matches=15)
```

```
grep(pattern="^\s*-\s*['\"]?(0\.0\.0\.0:)?[0-9]{2,5}(-[0-9]{2,5})?:[0-9]{2,5}|^\s*published:\s*['\"]?[0-9]", file_glob="*compose*.y*ml", max_matches=20)
```

This grep returns short-syntax port mappings with no host IP or with `0.0.0.0` (mappings prefixed with `127.0.0.1:` are not returned) and long-syntax `published:` entries. For each match: `read_file` around it to read the full port mapping, including any `host_ip`.

**Verify**:
- `"127.0.0.1:5432:5432"` — bound to localhost only → **SKIP** (safe)
- `"5432:5432"` (no IP prefix) — defaults to `0.0.0.0` in Docker → **CONTINUE**
- `"0.0.0.0:5432:5432"` — explicit all-interfaces bind → **CONTINUE**

For the CONTINUE cases: is the port a database/cache port (5432, 3306, 6379, 27017, 9200, 5984) or admin port (9090, 8080 management)? These are dangerous to expose. Port 80/443 for a web service → **SKIP**.

→ Submit: violated_invariant="Docker Compose binds [database_port] to 0.0.0.0 (all interfaces); database directly reachable from network, bypassing application auth layer", severity=8, confidence=8, exposure="internal", cwe="CWE-1327"

---

# Part D — GitHub Actions / CI-CD

## Step 12 — GHA: shell injection via `${{ github.* }}` interpolation

The first grep matches single-line `run:` steps (direct hits). The second matches the same attacker-controlled expressions anywhere in a workflow — including multi-line `run: |` blocks (the common case) and safe `env:` uses — so each of its hits needs the context check below.

```
grep(pattern="run:.*\$\{\{\s*(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label)|comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|head_commit\.message|commits[^}]*\.message|pages[^}]*\.page_name)|github\.head_ref)", path=".github/workflows", max_matches=20)
```

```
grep(pattern="\$\{\{\s*(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label)|comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|head_commit\.message|commits[^}]*\.message|pages[^}]*\.page_name)|github\.head_ref)", path=".github/workflows", max_matches=30)
```

For each match: `read_file` the workflow around the match to read the surrounding YAML context. Confirm the expression is:
1. Inside a `run:` block (single line, or indented under `run: |` / `run: >`), or inside `script:` of `actions/github-script` (JavaScript injection)
2. **Not** inside an `env:` block assignment like `env:\n  TITLE: ${{ ... }}`

Safe pattern (not a finding):
```yaml
env:
  TITLE: ${{ github.event.issue.title }}
run: echo "$TITLE"        # env var — shell-quoted, safe
```

Dangerous (submit):
```yaml
run: echo ${{ github.event.issue.title }}   # direct interpolation into shell
```

→ Submit: violated_invariant="GHA run: step interpolates ${{github.event.*}} directly into shell command; attacker creates issue/PR with title containing \`$(malicious_cmd)\` to execute arbitrary commands in the CI runner", severity=9, confidence=9, exposure="internet", cwe="CWE-78"

---

## Step 13 — GHA: pull_request_target + code checkout (pwn-requests)

```
grep(pattern="\bpull_request_target\b", path=".github/workflows", max_matches=10)
```

```
grep(pattern="ref:\s*\$\{\{\s*github\.(event\.pull_request\.head\.(sha|ref)|head_ref)|github\.event\.pull_request\.head\.repo\.full_name", path=".github/workflows", max_matches=15)
```

For each workflow with a `pull_request_target` trigger (first grep — covers `on: pull_request_target`, list and block forms): `read_file` it to check if it does `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}` or `ref: ${{ github.head_ref }}` (second grep) and then runs scripts or builds from that checkout. This runs attacker-controlled code with `pull_request_target` (trusted) permissions.

→ Submit: violated_invariant="pull_request_target workflow checks out PR fork code; attacker fork modifies CI scripts to exfiltrate GITHUB_TOKEN and all repository secrets", severity=10, confidence=9, exposure="internet", cwe="CWE-829"

---

## Step 14 — GHA: curl/wget piped to shell / secrets in env block

**curl | bash:**
```
grep(pattern="(curl|wget)\s.*\|\s*(sudo\s+)?(ba|z)?sh\b|(ba|z)?sh\s+(-c\s+\S*\$\(|<\()\s*(curl|wget)\s", path=".github/workflows", max_matches=15)
```

**Secrets in workflow-level env (exposed to all jobs):**
```
grep(pattern="^env:[ \t]*\n([ \t]+.*\n)*?[ \t]+[A-Za-z_][A-Za-z0-9_]*:[ \t]*\$\{\{\s*secrets\.", path=".github/workflows", multiline=true, max_matches=15)
```

The second grep only matches a top-level (column 0) `env:` block, i.e. workflow level. For secrets in env: are they at workflow level (all jobs see them) vs job/step level? Workflow-level exposure unnecessarily broadens the attack surface.

→ Submit: violated_invariant="GHA workflow pipes curl/wget output to shell, or exposes secrets at workflow level to all jobs including untrusted ones", severity=8, confidence=8, exposure="internet", cwe="CWE-494" (use "CWE-200" for workflow-level secrets)

---

## Step 15 — GHA: mutable action tags (supply chain)

```
grep(pattern="uses:\s*['\"]?[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@(v[0-9][A-Za-z0-9._-]*|[0-9]+\.[0-9][A-Za-z0-9._-]*|main|master|latest|dev|develop|stable|release)\b", max_matches=20)
```

No flow verification needed. A mutable tag (`@v3`, `@main`) is always a supply chain risk — the tag can be moved to point at malicious code. Only full commit SHAs (`@abc1234...`) are safe. Flag all mutable references.

→ Submit: violated_invariant="GitHub Actions step uses mutable tag @vN or @main; maintainer or attacker moving the tag delivers malicious code to all runs without PR/review", severity=7, confidence=9, exposure="internet", cwe="CWE-829"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
