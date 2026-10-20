---
parallel: true
---

# SKILL: hunt-secrets-detection

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns (p_secrets, p_ai-best-practices, p_terraform)

These patterns use **exact regex** derived from real secret formats. A regex match is near-definitive.

**Verification step**: after each match, check 2 things:
1. `read_file(file, start_line, end_line)` around the match (`get_code_snippet` only reads indexed code symbols, not `.env`/YAML/JSON) — is this a test file or fixture (`tests/`, `fixtures/`, `testdata/`), an example file (`.env.example`, `*.sample`), or commented-out code? If so: **SKIP**.
2. Is the matched string a placeholder like `"your_key_here"`, `"XXXXXXXX"`, `"example"`, `"changeme"`, `"password"`, `"<replace>"`, an interpolation (`${VAR}`, `%s`, `{password}`), or 5+ repeated chars? If so: **SKIP**.
If neither exclusion applies: **SUBMIT immediately** — exposed secrets are critical.

---

## Step 1 — AWS credentials

**AWS Access Key ID (AKIA / ASIA / AROA / etc.):**
```
grep(pattern="\b(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b", max_matches=20)
```

`AROA` / `AIDA` / `AGPA` / `ANPA` / `AIPA` / `ANVA` prefixes are unique IDs of roles, users, groups, policies and instance profiles — identifiers, not credentials. Do not report them.

**AWS Secret Access Key:**
```
grep(pattern="(?i)aws[_-]?secret[_-]?(access[_-]?)?key['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}", max_matches=15)
```

**AWS Session Token:**
```
grep(pattern="(?i)aws[_-]?session[_-]?token['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{16,}", max_matches=15)
```

→ Submit: violated_invariant="AWS IAM credential hardcoded in source; allows full AWS API access to all services in that account", severity=10, confidence=9, exposure="internet", cwe="CWE-798"

---

## Step 2 — LLM / AI provider API keys

**OpenAI (sk-proj / sk-org / legacy sk- prefix):**
```
grep(pattern="\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b|\bsk-(proj|svcacct|admin)-[A-Za-z0-9_-]{48,}|\bsk-[a-zA-Z0-9]{48,}\b", max_matches=15)
```

**Anthropic:**
```
grep(pattern="\bsk-ant-api[0-9]{2}-[A-Za-z0-9_-]{86,}\b", max_matches=15)
```

**Google Gemini / AI Platform:**
```
grep(pattern="\bAIzaSy[A-Za-z0-9_-]{33}\b", max_matches=15)
```

**HuggingFace / Cohere / Mistral:**
```
grep(pattern="\bhf_[A-Za-z0-9]{34,}\b|\bco-[a-zA-Z0-9]{40,}\b", max_matches=15)
```

→ Submit: violated_invariant="LLM provider API key hardcoded; attacker can consume quota, read org conversation history, or access fine-tuned models", severity=9, confidence=9, exposure="internet", cwe="CWE-798"

---

## Step 3 — Payment / financial API keys

**Stripe live key:**
```
grep(pattern="\b(sk|rk)_live_[0-9a-zA-Z]{24,}\b", max_matches=15)
```

**Square:**
```
grep(pattern="\bsq0atp-[0-9A-Za-z\-_]{22}\b|\bsq0csp-[0-9A-Za-z\-_]{43}\b", max_matches=10)
```

→ Submit: violated_invariant="Live payment API key hardcoded; attacker can charge cards, issue refunds, or access customer PII", severity=10, confidence=9, exposure="internet", cwe="CWE-798"

---

## Step 4 — Communication / collaboration secrets

**Slack tokens and webhooks:**
```
grep(pattern="\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}(-[0-9]{10,13})?-[A-Za-z0-9]{24,34}\b|\bxapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-z0-9]{32,}\b", max_matches=15)
```

```
grep(pattern="https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24}", max_matches=10)
```

**Telegram bot token:**
```
grep(pattern="\b[0-9]{8,10}:AA[0-9A-Za-z\-_]{33}\b", max_matches=10)
```

→ Submit: violated_invariant="Slack/Telegram token hardcoded; attacker can read/write messages, impersonate bot, enumerate workspace members", severity=8, confidence=9, exposure="internet", cwe="CWE-798"

---

## Step 5 — Private keys and certificates

```
grep(pattern="-----BEGIN\s*(RSA\s*|EC\s*|OPENSSH\s*|DSA\s*|ENCRYPTED\s*|PGP\s*)?PRIVATE KEY(-----| BLOCK-----)", max_matches=15)
```

```
grep(pattern="PuTTY-User-Key-File-[0-9]+:", max_matches=15)
```

**Verify**: is this under a test fixtures dir (`tests/`, `fixtures/`, `testdata/`) or an obviously generated test key used only by test code? → **SKIP** (same rule as the verification step above). In non-test code/config → severity 10. A `-----BEGIN CERTIFICATE-----` block is a public certificate, not a secret — never report it on its own.

→ Submit: violated_invariant="Private key hardcoded; allows forging signatures, decrypting TLS traffic, impersonating service identity", severity=10, confidence=9, exposure="internet", cwe="CWE-321"

---

## Step 6 — Database connection strings with credentials

**MongoDB connection string:**
```
grep(pattern="mongodb(\+srv)?://[A-Za-z][A-Za-z0-9_-]{1,31}:[^@\s]{1,64}@", max_matches=15)
```

**PostgreSQL / MySQL / MSSQL:**
```
grep(pattern="(postgres|postgresql|mysql|mariadb|mssql|sqlserver)(\+\w+)?://[A-Za-z][A-Za-z0-9_-]{1,31}:[^@\s]{1,64}@", max_matches=15)
```

**Redis with password:**
```
grep(pattern="rediss?://:[^@\s]{6,}@|rediss?://[A-Za-z][A-Za-z0-9_-]{1,31}:[^@\s]{1,64}@", max_matches=15)
```

**Generic URI credential pattern:**
```
grep(pattern="://[A-Za-z][A-Za-z0-9_-]{2,31}:[^@\s<>\"']{6,64}@[a-zA-Z0-9]", max_matches=20)
```

→ Submit: violated_invariant="Database connection string with plaintext credentials hardcoded; direct database access grants full data read/write", severity=10, confidence=8, exposure="internet", cwe="CWE-798"

---

## Step 7 — GitHub / GitLab / Bitbucket tokens

**GitHub PAT (classic ghp_ / gho_ / ghs_ / ghr_):**
```
grep(pattern="\bghp_[A-Za-z0-9]{36}\b|\bgho_[A-Za-z0-9]{36}\b|\bghs_[A-Za-z0-9]{36}\b|\bghr_[A-Za-z0-9]{36}\b|\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b", max_matches=15)
```

**GitLab personal / project access token:**
```
grep(pattern="\bglpat-[A-Za-z0-9_-]{20,}\b|\bglsoat-[A-Za-z0-9_-]{20,}\b", max_matches=10)
```

→ Submit: violated_invariant="GitHub/GitLab access token hardcoded; attacker can clone private repos, push code, read secrets, trigger CI/CD pipelines", severity=9, confidence=9, exposure="internet", cwe="CWE-798"

---

## Step 8 — JWT hardcoded signing secrets

**JWT / HMAC / session signing secret literal (hardcoded):**
```
grep(pattern="jwt\.sign\s*\(.*,\s*['\"][^'\"]+['\"]|jwt\.encode\s*\(.*,\s*['\"][^'\"]+['\"]|SECRET_KEY\s*=\s*['\"][^'\"]+['\"]", max_matches=20)
```

```
grep(pattern="(?i:jwt_secret)\w*['\"]?\s*[:=]\s*['\"][^'\"]+['\"]|^(JWT_SECRET|SECRET_KEY|APP_KEY)\w*=[^\s$'\"{]{4,}|(?i:hmac).*sha256['\"]?\s*,\s*['\"][^'\"]+['\"]|hmac\.new\s*\(\s*b?['\"][^'\"]+['\"]", max_matches=20)
```

**Verify**: a signing secret committed to the repo is exposed to anyone with repo access regardless of its length — SUBMIT unless it is a placeholder or used only by tests (verification step above). Short or dictionary values (`"secret"`, `"mysecret"`, `"changeme"`, `"supersecret"`) are additionally brute-forceable offline from any captured token. Confirm it is used as a JWT / HMAC / session signing key (the first grep can also hit an algorithm name such as `"HS256"` passed positionally — skip those).

→ Submit: violated_invariant="JWT signing secret is short/hardcoded; offline brute-force recovers the key and allows forging arbitrary tokens (auth bypass)", severity=9, confidence=8, exposure="internet", cwe="CWE-798"

---

## Step 9 — Cloud / infrastructure secrets

**GCP service account JSON key:**
```
grep(pattern="\"type\"\s*:\s*\"service_account\"\s*,|\"private_key_id\"\s*:\s*\"[a-f0-9]{40}\"", max_matches=10)
```

**Azure client secret / connection string:**
```
grep(pattern="DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88}|client_secret['\"]?\s*[:=]\s*['\"][a-zA-Z0-9._~-]{34,40}['\"]", max_matches=10)
```

**Terraform / AWS config files — static AWS keys (provider block, Lambda env, credentials file):**
```
grep(pattern="(?i:aws_access_key_id)\s*=\s*['\"]?(AKIA|ASIA)[A-Z0-9]{16}['\"]?|(?i:aws_secret_access_key)\s*=\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?|\baccess_key\s*=\s*\"(AKIA|ASIA)[A-Z0-9]{16}\"|\bsecret_key\s*=\s*\"[A-Za-z0-9/+=]{40}\"", max_matches=10)
```

→ Submit: violated_invariant="Cloud service account credential / Azure connection string hardcoded; full cloud resource access at the permission level of the credential", severity=10, confidence=9, exposure="internet", cwe="CWE-798"

---

## Step 10 — Miscellaneous high-value tokens

**Twilio / SendGrid / Mailgun:**
```
grep(pattern="\bSK[0-9a-fA-F]{32}\b|\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b|key-[0-9a-zA-Z]{32}", max_matches=10)
```

**SSH password in command:**
```
grep(pattern="sshpass\s+-p\s*['\"][^%][^'\"]+['\"]|sshpass\s+-p\s+[^\s]+", max_matches=10)
```

**bcrypt hash or /etc/shadow row with a password hash (credential material):**
```
grep(pattern="\$2[aby]?\$[0-9]{2}\$[./A-Za-z0-9]{53}|^[a-z_][a-z0-9_-]*:\$(1|2[aby]?|5|6|y)\$[^:\s]+:", max_matches=10)
```

→ Submit: violated_invariant="Hardcoded token/hash detected; immediate key rotation required — exposure via version control history, logs, or error messages", severity=8, confidence=9, exposure="internet", cwe="CWE-798"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
