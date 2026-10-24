<div align="center">

# Arad Code

**A security code auditor that reads your codebase like a reviewer would,<br>and only reports what it can point to in the code.**

![python](https://img.shields.io/badge/python-3.10%20to%203.14-3776AB?logo=python&logoColor=white)
![interface](https://img.shields.io/badge/interface-TUI%20%2B%20CLI-0d1117)
![output](https://img.shields.io/badge/output-SARIF%202.1.0-2ea043)
![version](https://img.shields.io/badge/version-2.3.8-informational)

</div>

<p align="center">
  <img src="docs/screenshot.png" alt="Arad Code scanning OWASP Juice Shop: each finished skill with its findings, time and tokens, one skill opened with the gate status of every finding, and the workflow tree on the right" width="900">
</p>

Arad Code drives an LLM through a set of audit "skills" (plain markdown playbooks) against a repository. The model gets real tools: a code graph, ripgrep, an AST parser, semgrep, a read-only shell. It maps the project first (entry points, middleware, identities, ownership), then traces data and hunts for concrete vulnerability patterns.

Every finding goes through an evidence gate before it's allowed out. The engine re-reads the cited file, checks the quoted code is actually at those lines, caps confidence by how the evidence was gathered (a grep hit counts for less than a traced call chain), and keeps anything with unresolved proof obligations out of the report. What survives is something you can open in your editor and check.

## Why Arad Code

There are plenty of SAST tools. Most of them match patterns: they're fast, but they can't tell whether the line they flagged is reachable, who can reach it, or whether a check two calls up already stops it. You get hundreds of results and spend the afternoon closing them. The newer LLM scanners go the other way. They hand files to a model and print what it says, and nothing stands between a confident guess and your report.

Arad Code is built around one rule: nothing reaches the report unless it can be pointed to in the code. The model does the reading and the reasoning, and the engine treats everything it says as a claim that still has to be checked.

- **Every finding points at real code.** Evidence names a file, a line range and a verbatim quote. The engine re-reads the file and throws out anything that isn't actually there. When the code changes later, the anchor goes stale and the finding is checked again.
- **Confidence is earned, not claimed.** A finding backed by a grep hit is capped far below one backed by a traced call chain, whatever the model says about itself.
- **Proof obligations.** Each finding carries the questions that decide whether it's real: is the input attacker controlled, is the endpoint reachable, does a guard cover this path. It stays out of the report until they're answered with evidence.
- **It learns the project before it hunts.** Entry points, middleware, identities, ownership, tenants, trust boundaries and business invariants are mapped first and stored, so the hunts start from a threat model instead of a blank page. That's what lets it find broken authorization and business logic bugs, which no pattern can describe.
- **It also writes down why something is safe.** With `-N`, a skill records the exact guard line that protects an entry point. If a later commit removes that line, the entry point is flagged again.
- **Small findings add up.** The last phase looks for low severity issues that combine into a serious one, and only reports a chain when the link between the steps is shown in the code.
- **Some checks need no model at all.** `peers` finds routes that are missing a protection nearly all their siblings have, straight from the mapped entry points.
- **You stay in charge.** Your triage decisions survive rescans. `verify` hands a finding to an adversarial pass, optionally on a different model, whose only job is to refute it. `calibrate` shows how the model's stated confidence compares with what you actually accepted.
- **Safe to point at hostile code.** The model's tools are read-only and can't leave the repository, and the whole scan runs in a locked down container by default.
- **You know what it costs.** Every call is metered per skill and model, a budget stops a run before it overspends, skills that can't apply to your stack are skipped, independent skills run side by side, and every conversation is saved so you can see how a finding was reached.
- **It fits what you already use.** SARIF 2.1.0 for GitHub code scanning, a Markdown report, any OpenAI compatible endpoint (OpenAI, OpenRouter, a local model), and skills that are plain markdown files you can write yourself.

## Contents

- [Why Arad Code](#why-arad-code)
- [How a scan works](#how-a-scan-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Quick start](#quick-start)
- [The sandbox](#the-sandbox)
- [The terminal UI](#the-terminal-ui)
- [CLI reference](#cli-reference)
- [Reading the results](#reading-the-results)
- [Cost, budgets and transcripts](#cost-budgets-and-transcripts)
- [Project profile (.llmsast.yaml)](#project-profile-llmsastyaml)
- [Workflow scripts](#workflow-scripts)
- [Extra MCP servers](#extra-mcp-servers)
- [Writing your own skills](#writing-your-own-skills)
- [Where things are stored](#where-things-are-stored)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## How a scan works

Skills live in `skills/`, one folder per phase. A full run goes through them in order:

| Phase | What happens | Skills |
|---|---|---|
| `p0` | Resolve blocking open questions left by earlier skills. Runs before a phase only when something is actually blocked. | 1 |
| `p1` | Project understanding: inventory, build, config, entry points, DI, middleware, deployment, service boundaries | 8 |
| `p2` | Identity and ownership: identities, authorization model, resource ownership, tenants, state machines, invariants, trust boundaries, sensitive data | 8 |
| `p3` | Path analysis: input to effect, effect back to callers, identity propagation, persisted data reuse, cross-service messages | 6 |
| `p4` | Hunting: 17 `hunt-*` breadth scans (SQLi, SSRF, XSS, auth bypass, secrets, IaC, LLM/MCP issues and more) plus 9 optional `understand-*` deep-dive reviews | 26 |
| `p5` | Compose individual findings into attack chains | 1 |

Earlier phases write what they learn (a threat model, entry points, guards, function summaries) into a local SQLite store, and later phases start from that context instead of rediscovering it. The maps the `p1` and `p2` skills add to the threat model are shown to later skills as the short summary the writing skill gave with it, and `get_threat_model` returns a map in full when a skill needs the details. A skill can add its map before anyone has saved the base threat model, and one that reaches its closing turns (where only `finish()` is allowed) before saving it can hand the map over in `finish()` instead.

`p1` and `p2` run one skill at a time because each builds on the one before. The `p3` and `p4` skills don't depend on each other, so up to three of them run at once (`--concurrency` changes that). `trace-input-to-effect` goes through every entry point the earlier phases found: it runs once per batch of six, and each entry point ends with a recorded decision (see [Writing your own skills](#writing-your-own-skills)).

Before a run starts, Arad Code takes a quick look at the repository without calling the model: file types, dependency manifests (`package.json`, `requirements.txt`, `go.mod`, `pom.xml` and the like) and a few telltale lines of code. Skills that can't apply are skipped. A command line tool with no HTML, no templates and no web framework doesn't get the XSS or open redirect hunts, a repo without Docker, Terraform or CI files doesn't get the IaC hunt, and so on. Each skip is printed with its reason and recorded in `coverage`. The check only skips when nothing points the other way, and when it can't finish looking (a huge repository), it skips nothing. `--all-skills` turns it off for one run, `skill_gating: false` for good.

Each finding is a hypothesis with an actor, an entry point, an execution path, the invariant it breaks and the impact. Its status moves like this:

```
initial --> evidence_supported --> human_confirmed     (you accept it in triage)
   |               |
   |               +--> refuted / rejected             (verification or triage says no)
   |
   +--> stays initial while proof obligations are unresolved, a blocking
        question is open, or the evidence is only textual
```

Only `evidence_supported`, `reproduced` and `human_confirmed` findings are exported to SARIF.

## Requirements

- Python 3.10 or newer. 3.10, 3.11, 3.12, 3.13 and 3.14 are all tested. The 3.15 betas don't work yet because PyYAML has no build for them.
- An OpenAI compatible chat completions endpoint with tool calling. OpenAI, OpenRouter and self-hosted gateways that speak the same API all work.
- `git` and [ripgrep](https://github.com/BurntSushi/ripgrep) (`rg`). The grep tool depends on ripgrep's regex syntax.
- Recommended: [codebase-memory-mcp](https://github.com/DeusData/codebase-memory-mcp) for the code graph (`search_graph`, `trace_path`, `get_code_snippet`). Without it the agent falls back to grep and reads more files by hand.
- Optional: `semgrep`, `jq`, `tree`, `file`.
- Docker or Podman. Scans run in a container by default (see [The sandbox](#the-sandbox)). Without one, pass `--allow-dangerously-trust`.

## Installation

```bash
git clone https://github.com/fedman0/Arad-Code.git
cd Arad-Code
./install.sh
```

`install.sh` creates a virtualenv in `.venv`, installs the Python packages, installs ripgrep and the other system tools with your package manager (apt, dnf, pacman, apk or Homebrew), installs semgrep in its own environment, and downloads the tree-sitter grammars so the first scan doesn't need the network.

| Flag | Effect |
|---|---|
| `--tier core` | Only what the engine needs to run |
| `--tier recommended` | Core plus the shell tools and codebase-memory-mcp (default) |
| `--tier all` | Everything, including language servers, secret scanners and benchmark repos |
| `--check` | Verify what's installed, change nothing |
| `--dry-run` | Print the commands without running them |
| `--no-venv` | Install Python packages into the current environment |

You can move things around with `LLMSAST_VENV`, `LLMSAST_BIN` (default `~/.local/bin`), `LLMSAST_SEMGREP_VENV` and `LLMSAST_BENCH`.

Prefer doing it by hand:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

and install `ripgrep` from your package manager. The minimum versions in `requirements.txt` are the oldest ones the test suite passes with; anything newer, up to the current releases, works too. semgrep is intentionally not in `requirements.txt`; its pinned dependencies fight with the rest, so give it its own environment (`pipx install semgrep` is the easy way).

If you'd rather have it as a normal command, install the checkout with pipx (or `uv tool install .`):

```bash
pipx install .
arad --version
arad --headless list-skills
```

That gives you an `arad` command on your `PATH` with the skills bundled in, and it takes the same subcommands as `python pentest.py`. ripgrep and codebase-memory-mcp still come from your system, so install those separately.

## Configuration

The fastest way is the interactive setup:

```bash
python pentest.py --headless config-init
```

It asks for the endpoint, key, model and the codebase-memory-mcp binary, keeps whatever else is already in the file, and writes `~/.pentest/config.yaml` with `0600` permissions. The file it writes lists every setting, so you can open it and change the rest by hand.

### The config file

Everything Arad Code can be told on the command line or through an environment variable can also live in the config file: the endpoint and models, budgets, concurrency, `-N`, `-v`, `--headless`, the sandbox settings, all of it. Keep one file per setup and point Arad at it.

Settings are read from the first of these that applies:

1. `--config FILE`. Put it before the command and it counts for everything, the terminal UI included (`arad --config ~/audits/acme.yaml`); after a command it counts for that command only. The file has to exist.
2. `PENTEST_CONFIG=FILE`, the same thing as an environment variable. Handy in a shell profile or a CI job.
3. `config.yaml` next to `pentest.py`, in your Arad Code checkout.
4. `~/.pentest/config.yaml`.

A `config.yaml` in the directory you happen to be in is never read. When you audit someone else's code you usually run Arad from inside their repository, and a config file planted there could otherwise send your API key to another server or swap the code graph binary for its own.

[`config.example.yaml`](config.example.yaml) lists every key with its default. A typical file:

```yaml
model: gpt-5.5
api_base: https://api.openai.com/v1
api_key: sk-your-key

mcp_server: codebase-memory-mcp
mcp_args: []

db_path: ~/.pentest/evidence.db
skills_dir: ""

max_tokens: 16384
temperature: 0.0
reasoning_effort: ""

profile_path: ~/audit-profiles/acme-shop.yaml
trust_repo_profile: false

mcp_allow:
  github: [get_file_contents]

max_retries: 4
budget_usd: 5
transcripts: true

pricing:
  gpt-5.5:
    input: 1.25
    cached_input: 0.125
    output: 10
```

The prices above only show the shape. Copy the real numbers from your provider's price list; they're in US dollars per million tokens.

| Key | Default | What it does |
|---|---|---|
| `model` | `gpt-5.5` | Model name sent to the endpoint |
| `api_base` | `https://api.openai.com/v1` | Base URL of the OpenAI compatible API |
| `api_key` | none | Required for anything that talks to the model |
| `mcp_server` | `codebase-memory-mcp` | Binary started for the code graph (looked up on `PATH`) |
| `mcp_args` | `[]` | Extra arguments for that binary |
| `db_path` | `~/.pentest/evidence.db` | SQLite evidence store, shared by every repo you scan |
| `skills_dir` | empty | Use a different skills folder. Empty means `./skills` next to `pentest.py` |
| `max_tokens` | `16384` | Longest reply the model may send. A reply cut off at this limit is retried with up to four times the room (see [Cost, budgets and transcripts](#cost-budgets-and-transcripts)) |
| `temperature` | `0.0` | Sampling temperature |
| `reasoning_effort` | empty | `low`, `medium` or `high` for reasoning models. Sent as `reasoning.effort` to OpenRouter and as `reasoning_effort` everywhere else |
| `profile_path` | empty | Path to a project profile kept outside the target repo (see below) |
| `trust_repo_profile` | `false` | Allow a `.llmsast.yaml` committed inside the target repo to be loaded |
| `mcp_allow` | `{}` | Per server list of non read-only MCP tools you explicitly allow (see [Extra MCP servers](#extra-mcp-servers)) |
| `max_retries` | `4` | How many times a rate limited or failed request is retried before the skill gives up |
| `pricing` | `{}` | Price per million tokens for each model: `input`, `output` and optionally `cached_input`. Used to show costs and to enforce `budget_usd` |
| `budget_usd` | none | Stop once spend reaches this many dollars (see [Cost, budgets and transcripts](#cost-budgets-and-transcripts)) |
| `token_budget` | none | Stop once this many tokens have been used |
| `transcripts` | `true` | Save every conversation with the model as JSON lines |
| `transcripts_dir` | empty | Where to save them. Empty means a `transcripts` folder next to `db_path` |
| `fast_model` | empty | Cheaper model for the `p1` mapping skills. Empty means `model` (see [Using more than one model](#using-more-than-one-model)) |
| `verify_model` | empty | Model for `verify`. Empty means `model` |
| `concurrency` | `3` | How many `p3`/`p4` skills may run at the same time. `1` runs everything in order |
| `context_char_limit` | `200000` | Once a skill's conversation grows past this many characters, older tool output is shortened. `0` turns this limit off |
| `history_char_limit` | `110000` | The same shortening starts once the tool calls and results after the skill's first message pass this many characters. This keeps calls cheaper and gives every skill the same room, however long its Known Context is. `0` turns it off; set both to `0` to keep everything |
| `skill_gating` | `true` | Skip skills that don't apply to the project's stack |
| `optional_skills` | `false` | Also run the skills marked `optional`, which are the nine `understand-*` reviews. They cost about a seventh of a scan's tokens, and in benchmark runs every known bug they found was also found by other skills in another run. `--all-skills` runs them for one scan |
| `negative_evidence` | `false` | Same as passing `-N` to every `run` and `skill` (also applies to scans started in the UI) |
| `verbose` | `false` | Same as passing `-v` to every `run` |
| `headless` | `false` | Never open the terminal UI, as if every command had `--headless` |
| `allow_dangerously_trust` | `false` | Run without the container sandbox (see [The sandbox](#the-sandbox)) |
| `sandbox_runtime` | empty | `docker` or `podman`, or a path to either. Empty means whichever is installed, Docker first |
| `sandbox_image` | empty | Use this image instead of building one |
| `sandbox_network` | empty | Container network. Empty means the default bridge, or the host network when the model endpoint is on localhost |
| `sandbox_memory` | `4g` | Memory limit for the container |
| `sandbox_pids` | `1024` | Process limit for the container |
| `sandbox_semgrep` | `true` | Include semgrep when the image is built |

### Environment variables

These override the file, and command line flags override both:

| Variable | Same as |
|---|---|
| `PENTEST_CONFIG` | `--config` before the command |
| `PENTEST_API_KEY` | `api_key` / `--api-key` |
| `PENTEST_API_BASE` | `api_base` / `--api-base` |
| `PENTEST_MODEL` | `model` / `--model` |
| `PENTEST_REASONING_EFFORT` | `reasoning_effort` |
| `PENTEST_FAST_MODEL` | `fast_model` / `--fast-model` |
| `PENTEST_VERIFY_MODEL` | `verify_model` / `--verify-model` |

Example with OpenRouter:

```bash
export PENTEST_API_BASE=https://openrouter.ai/api/v1
export PENTEST_API_KEY=sk-or-...
export PENTEST_MODEL=openai/gpt-5.5
```

### Using more than one model

Out of the box everything runs on the one model you set in `model`, and that's a fine way to use it. If you want to bring the cost down, two optional settings let you split the work:

```yaml
model: gpt-5.5
fast_model: gpt-5.4-mini
verify_model: gpt-5.4
```

- `fast_model` runs the `p1` skills (inventory, build, config, entry points, DI, middleware, deployment, services). That work is mostly reading files and writing down what's there, so a smaller model handles it well. Everything after `p1` still uses `model`.
- `verify_model` is used by `verify`. Checking a finding with a different model than the one that reported it catches more mistakes than asking the same model twice.

Which skills count as "fast" is set in each skill's header (`tier: fast`, see [Writing your own skills](#writing-your-own-skills)). Every model in use needs to be reachable through the same `api_base`, so on OpenRouter you can mix vendors freely. The usage table, `usage` command and TUI always show which model did what.

## Quick start

```bash
python pentest.py --headless sandbox build
python pentest.py --headless init ~/src/acme-shop
python pentest.py run ~/src/acme-shop
python pentest.py --headless report ~/src/acme-shop --md > report.md
python pentest.py --headless sarif ~/src/acme-shop --output-dir out/
python pentest.py --headless usage ~/src/acme-shop
```

1. `sandbox build` builds the container image the scans run in. You can skip it, since the first command that needs the image builds it anyway. It takes a few minutes, once.
2. `init` indexes the repo with codebase-memory-mcp and registers it in the evidence store. Run it again after big changes so the graph is fresh.
3. `run` opens the terminal UI and starts a full scan. A full scan is a few dozen skills, so expect it to take a while and spend real tokens. Ctrl+C stops it, and finished skills are kept. Once prices are in your config, `--budget 10` stops it at ten dollars.
4. `report --md` writes a Markdown report, deduplicated and sorted by priority.
5. `sarif` writes `out/findings.sarif` for GitHub code scanning or any other SARIF viewer.
6. `usage` shows what each run cost, step by step and model by model.

To scan only part of the pipeline, pass a phase: `--phase p4` (or just `--phase 4`). To run a single skill: `python pentest.py skill hunt-ssrf ~/src/acme-shop`.

## The sandbox

By default every command that lets the model drive tools on a repository (`run`, `skill`, `verify`, `init` and the terminal UI) runs inside a Docker or Podman container. The model reads code that somebody else wrote, and that code can try to talk it into things. The container is a second wall behind the path checks the tools already do.

What the container gets:

- the repository you scan, read-only
- the evidence store directory and `~/.cache/pentest`, read-write, so results and saved conversations land where they always did (a `transcripts_dir` you moved elsewhere is shared read-write too)
- your config file and Arad's own code, read-only
- the `PENTEST_*` and `ARAD_*` variables, passed by name so the key never ends up on a command line

Nothing else from your home directory is mounted. The root filesystem is read-only, all capabilities are dropped, privilege escalation is blocked, and the process runs with your uid under memory and process limits. The network is not restricted, because the model API needs it. Proxies come from your shell's `HTTP_PROXY` style variables, not from Docker's own proxy settings, so the container reaches the network the same way arad does without it. If your endpoint is on localhost (Ollama, a local gateway), or your proxy is, the container shares the host network so it can reach it.

The image is built the first time you need it and tagged with the Arad version, so an upgrade rebuilds it. To build it ahead of time or check the setup:

```bash
python pentest.py --headless sandbox build
python pentest.py --headless sandbox status
```

`sandbox build --no-semgrep` leaves semgrep out, which makes the image a lot smaller.

To run without the container, for example on a machine without Docker:

```bash
python pentest.py --allow-dangerously-trust run ~/src/acme-shop
```

`ARAD_ALLOW_DANGEROUSLY_TRUST=1`, or `allow_dangerously_trust: true` in your config file, does the same every time. A `config.yaml` sitting in the repository you scan is never read, so it can't turn the sandbox off. Only skip the sandbox for code you trust.

Good to know:

- The terminal UI only sees the directory you start it in. Start it inside the project you want to scan. Your home directory itself is never shared. `sarif` typed inside the UI can't write into that read-only directory, so run it headless.
- Extra MCP servers from `~/.claude.json` aren't available inside the container.
- The image has its own codebase-memory-mcp with its own index under `~/.cache/pentest/sandbox`, so run `init` again the first time you scan a repo in the sandbox.
- The `sandbox_*` keys in the config file change the defaults (runtime, image, network, memory, process limit, semgrep). The environment variables `ARAD_SANDBOX_RUNTIME`, `ARAD_SANDBOX_IMAGE`, `ARAD_SANDBOX_NETWORK`, `ARAD_SANDBOX_MEMORY`, `ARAD_SANDBOX_PIDS` and `ARAD_SANDBOX_SEMGREP` override them for one shell.

## The terminal UI

```bash
python arad.py
```

`python pentest.py` with no arguments does the same thing. Starting it with `run`, `skill`, `workflow` or `deep-research` launches the UI with that command already running, for example `python pentest.py run ~/src/acme-shop --phase p1`.

Commands typed into the UI:

| Command | Description |
|---|---|
| `run <repo> [--phase N] [--resume] [--restart] [--all-skills]` | Full scan, or one phase |
| `skill <name> <repo> [context]` | One skill. Anything after the repo is passed to the skill as extra context |
| `workflow <script.py> [--repo <path>]` | Run a workflow script (see [Workflow scripts](#workflow-scripts)) |
| `deep-research <question> [--repo <path>]` | Open ended research: past bug classes, attack surface, grep leads, priority files |
| `report`, `peers`, `coverage`, `sarif`, `doctor`, `calibrate`, `reconcile`, `verify`, `init`, `list-skills` | Passed straight to the CLI, run in your current directory |
| `query <repo> "<expression>"` | Query the evidence store (quote the expression) |
| `headless` | Leave the UI and continue in the plain CLI |
| `usage <repo>` | Tokens and cost of recent runs, passed to the CLI like `report` |
| `help`, `clear`, `exit` | |

`triage`, `config-init` and `query` without an expression ask questions interactively, so run those from the plain CLI.

Start a line with `>` to ask the model about the current or last run while it's going, for example `> which finding should I look at first?`. Two shortcuts don't call the model at all: `> status` and `> findings`.

| Key | Action |
|---|---|
| `Ctrl+C` | Stop the running task |
| `Ctrl+W` | Show or hide the workflow panel |
| `Tab` | Jump into the workflow tree, `Tab` or `Esc` to get back |
| `Enter` (in the tree) | Open a phase, skill or finding in detail |
| `Ctrl+L` | Clear the model's answers, keep the scan output |
| `End` | Follow new output again after you scrolled up |
| `↑` `↓` | Command history |
| `Ctrl+Q` | Quit |

The workflow tree shows which model ran each skill, and the line logged when a skill finishes has its model, token count and cost. The status bar keeps a running total for the session. Opening a skill in the tree shows its calls and tokens in detail, and opening a finding shows the model that reported it and, once you've run `verify`, the model that checked it.

While a command runs, new commands are queued and start one after another. `help`, `clear`, `exit` and `>` questions run immediately. Persian and other right-to-left text in model answers is shaped and reordered so it reads correctly in the terminal.

## CLI reference

Everything is a subcommand of `pentest.py`. `run` and `skill` open the UI unless you add `--headless`. `workflow` and `deep-research` only exist inside the UI. Every other command prints straight to the terminal.

Commands that call the model accept `--api-key`, `--api-base`, `--model` and `--config`. Commands that only read the store take `--config` and work without a key.

`--allow-dangerously-trust` goes before the subcommand (`pentest.py --allow-dangerously-trust run REPO`) and runs it without the container. See [The sandbox](#the-sandbox).

### Scanning

```
pentest.py init REPO
pentest.py run REPO [--phase P] [--resume] [--restart] [-N] [-v] [--concurrency N] [--all-skills]
                     [--fast-model M] [BUDGET OPTIONS]
pentest.py skill SKILL REPO [--context TEXT] [-N] [--fast-model M] [BUDGET OPTIONS]
pentest.py verify HYPOTHESIS_ID REPO [--verify-model M] [BUDGET OPTIONS]
pentest.py list-skills
pentest.py sandbox build [--no-semgrep]
pentest.py sandbox status
```

- `--resume` skips skills already finished at the current commit. If a run was interrupted and you start it again without a flag, you'll be asked whether to resume.
- `--restart` throws away saved progress and starts over.
- `-N` / `--negative-evidence` makes the `p3` and `p4` skills also record *why* an entry point is safe: the exact guard line that protects it. Those anchors are re-checked on later runs, and if the guard disappears from the code the entry point is flagged for review again.
- `-v` prints every tool call as it happens.
- `--concurrency N` sets how many `p3`/`p4` skills run at once (default 3). Raise it if your API key has the rate limit for it; `1` runs one skill at a time.
- `--all-skills` runs every skill, including the ones the stack check would skip and the optional ones.
- `--fast-model` and `--verify-model` override `fast_model` and `verify_model` for one command.
- `verify` sends one finding to an adversarial pass whose only job is to refute it, then updates its status. Your own triage decisions are never overwritten.
- Budget options: `--budget USD`, `--token-budget N` and `--no-transcripts`, explained in [Cost, budgets and transcripts](#cost-budgets-and-transcripts).

### Results

```
pentest.py report REPO [--min-severity N] [--min-confidence N] [--status S] [--md]
pentest.py sarif REPO [--output-dir DIR]
pentest.py query REPO [EXPRESSION]
pentest.py coverage REPO [--show STATUS]
pentest.py triage REPO [--min-priority N] [--all]
pentest.py calibrate [REPO] [--min-samples N]
pentest.py peers REPO [--save/--no-save]
pentest.py reconcile REPO
pentest.py doctor REPO
pentest.py usage REPO [--run ID] [--limit N]
pentest.py config-init [--path FILE]
```

| Command | What it's for |
|---|---|
| `report` | Table of findings. `--md` prints a full Markdown report with evidence snippets |
| `sarif` | SARIF 2.1.0 file. Includes the commit and the repo URL (taken from `origin`, credentials stripped) |
| `query` | Small query language over the store, see below. Without an expression it opens a prompt |
| `coverage` | What was analysed and, more usefully, what wasn't |
| `triage` | Walk findings by priority and answer `a` accept, `r` reject, `n` need info, `s` skip |
| `calibrate` | Compares the confidence the model claimed with what you accepted in triage |
| `peers` | Finds routes missing a protection that nearly all their siblings have. Needs `p1` to have run |
| `reconcile` | Re-checks every evidence anchor against the current code and recomputes statuses, no model calls |
| `doctor` | Explains why nothing (or little) is being exported |
| `usage` | Tokens, cost and models of recent runs; `--run ID` breaks one run down by step |

### Query language

```bash
python pentest.py --headless query ~/src/acme-shop "hypotheses where exposure=internet and status=evidence_supported"
python pentest.py --headless query ~/src/acme-shop "entry_points where auth=none"
python pentest.py --headless query ~/src/acme-shop "coverage where status=blocked"
python pentest.py --headless query ~/src/acme-shop "why 3fa94c1e"
```

| Collection | Filters |
|---|---|
| `hypotheses` | `status`, `exposure`, `reachability`, `input_control`, `guard_coverage`, `severity`, `confidence` |
| `entry_points` | `auth=none`, `auth=<decorator name>`, `kind` (`route`, `consumer`, `job`, `command`, `hook`, `callback`) |
| `coverage` | `status`, `kind` |
| `why <id>` | Everything about one finding: path, evidence, obligations, counterevidence, triage decision |

Join filters with `and`.

## Reading the results

| Status | Meaning |
|---|---|
| `initial` | Found, but not proven enough to export |
| `evidence_supported` | Passed the evidence gate |
| `reproduced` | Confirmed by a runtime check |
| `human_confirmed` | You accepted it in triage |
| `refuted` / `rejected` | Disproved by verification, by the model with a recorded reason, by you, or suppressed by the profile |
| `blocked` | Can't be decided with what's available |
| `needs_recheck` | You confirmed it, but all of its evidence has since gone stale |

Severity is an integer from 0 to 10: 9 and 10 are critical, 7 and 8 high, 4 to 6 medium, 1 to 3 low, 0 informational. Confidence is capped by how the evidence was gathered: 4 for a grep hit the model never opened, 7 when it read the cited lines themselves or used structural tools (AST, symbol search), 10 only when a call chain was actually traced. Each claim is checked against the calls made during the skill: reading counts only when a `read_file` range in that skill contains the cited lines and the quoted anchor was found there, and a traced chain only when a `trace_path` call names the cited file or function, or a `query_graph` call returned rows that name the cited file. A graph call that failed, was refused or returned nothing counts for nothing.

When a finding you expected isn't in the report, `doctor` and `query REPO "why <id>"` will usually tell you which obligation, open question or stale anchor is holding it back.

## Cost, budgets and transcripts

Every call to the model is metered: input tokens, how many of those the provider served from its prompt cache, output and reasoning tokens, time and cost. `run`, `skill` and `verify` end with a table that breaks this down by step and model, and the numbers are kept in the evidence store:

```bash
python pentest.py --headless usage ~/src/acme-shop
python pentest.py --headless usage ~/src/acme-shop --run 20261020-143502-9f3a1c
```

The first lists recent runs, the second shows one run step by step.

Costs come from the `pricing` table in your config. On OpenRouter the provider reports what each call cost, so you don't need the table there. A model with no known price shows `?` instead of a dollar amount; its token counts are still exact.

**Budgets.** `--budget 5` (dollars) or `--token-budget 2000000` stops the run before the next model call once the limit is reached. A call that's already in flight is allowed to finish, so the total can end up slightly over. Finished skills are kept, so after raising the limit `--resume` carries on from where it stopped. A run stopped this way exits with status 3. A dollar budget needs a price for every model in use; without one the command refuses to start rather than run unmetered. Both can also be set in the config as `budget_usd` and `token_budget`.

**Transcripts.** Each skill's whole conversation with the model (the prompt, every tool call and its result, the final answer, and the usage) is saved as JSON lines under `transcripts/<repo>/<run id>/`, next to the evidence store. When a finding looks wrong, that file shows how the model got there. The files are only readable by you, but they do contain source code from the scanned repo and whatever the model found in it, secrets included. `--no-transcripts` or `transcripts: false` turns them off.

**Long conversations.** A skill can make dozens of tool calls, and every call sends the whole conversation again, so cost grows quickly with length. Once a conversation passes `context_char_limit` characters, or the part after the first message passes `history_char_limit`, tool output older than the last six results is cut down to its first lines, with a note telling the model it can run the tool again for the rest. This happens in steps rather than on every call, so the provider's prompt cache keeps working. The evidence checks and the saved transcripts always use the full, untrimmed output. The threat model in a skill's first message shows each amendment by its summary; from the 26th on, an amendment gets one line, and `get_threat_model(section="N")` returns it in full.

**Replies cut off at the token limit.** The transcript records the `finish_reason` of every turn. When a reply ends with `length`, the engine tells the model what happened and gives the next call up to four times `max_tokens` (at most 65536) with low reasoning effort, so a long `finish()` can get through. The closing turns of a skill, where the model may only call `finish()`, always get that room. If the model returns nothing twice in a row during those turns, the skill ends right away with a note in its open questions instead of spending the remaining turns. A model that refuses the bigger limit stays at `max_tokens` for the rest of the run.

**The closing turns and the prompt cache.** The note that starts the closing turns is added to the end of the last tool result rather than sent as a new message, and those turns still offer every tool. Both keep the request a straight continuation of the previous one, so the provider serves it from its prompt cache; DeepSeek's thinking mode also drops the model's earlier reasoning when a new user message arrives, which the note avoids. A call to any tool other than `finish()` in those turns is not run, and after one such call only `finish()` is offered.

**Models that refuse a parameter.** Some newer models don't accept a custom `temperature`, or want `max_completion_tokens` instead of `max_tokens`. When the endpoint rejects one of those, the client retries without it (or under the other name) and remembers that for the rest of the run, so the same config works across models. Some reasoning models, DeepSeek's thinking mode among them, also refuse to be told which tool to call. The closing turns of a skill ask for `finish()` by name, so when that is refused the client asks for any tool call instead, then leaves the choice to the model.

## Project profile (.llmsast.yaml)

A profile tells the scanner things about your project it can't safely guess: which decorators count as authentication, which functions are real sanitizers, which paths are internal, and which known risks you've accepted.

```yaml
auth_markers:
  decorators: ["@login_required", "@requires_scope"]
  middleware: ["AuthMiddleware"]

sanitizers:
  - qn: app.security.escape_html
    neutralizes: [CWE-79]
    complete: true

trusted_sources:
  - values read from the internal settings service

exposure_overrides:
  "/admin/*": admin_only
  "/internal": internal
  "healthz": unreachable

suppress:
  - rule: CWE-89
    path: "migrations/**"
    reason: Migrations run offline by the DBA and never see request data
    expires: 2027-03-31
```

Some rules worth knowing:

- A profile can hide findings, so a `.llmsast.yaml` inside the repo you're scanning is **ignored by default**. Keep the profile outside the repo and point `profile_path` at it, or set `trust_repo_profile: true` if you trust the repo.
- Every suppression needs a `reason` and an `expires` date (`YYYY-MM-DD`). Expired ones stop applying, and the scan prompt says so. `rule: "*"` together with a `**` path is refused.
- `rule` is `*`, a CWE id, or a few words that must all appear in the finding.
- `exposure_overrides` match the route path, segment by segment. `/internal` covers `/internal` and `/internal/...` but not `/internals`. A pattern without a leading `/` can match at any segment.
- Allowed exposures: `internet`, `authenticated`, `internal`, `admin_only`, `unreachable`. An `unreachable` override keeps findings on that route out of the report.

## Workflow scripts

For audits the built-in phases don't cover, write a small Python script and run it from the UI with `workflow audit.py --repo ~/src/acme-shop`. These names are available inside the script without importing anything:

| Name | Use |
|---|---|
| `await phase(name, title=..., detail=...)` | Start a new phase in the workflow tree |
| `await agent(prompt, label=..., phase=..., schema=..., extra_context=...)` | One model run with the read-only tools. With a JSON `schema` you get a dict back |
| `await parallel([lambda: agent(...), ...], concurrency=10)` | Run several agents at once |
| `await pipeline(items, step1, step2, concurrency=10)` | Push items through async steps. A step can return a list to fan out, or `None` to drop the item |
| `await verify_finding(finding)` | Three adversarial votes. Returns the finding with `confirmed` set to `True`, `False` or `None` |
| `await submit_finding(hypothesis, evidence)` | Store a finding through the same evidence gate as the skills |
| `args` | Whatever was passed to the script (`None` from the UI) |

The script can define `run()` (sync or async). If its return value has a `findings` list, the UI prints how many were confirmed.

```python
SURFACE = {
    "type": "object",
    "properties": {
        "handlers": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "function": {"type": "string"},
                    "code": {"type": "string"},
                },
                "required": ["file", "line", "function", "code"],
            },
        }
    },
    "required": ["handlers"],
}


async def run():
    await phase("map", title="Upload handlers")
    surface = await agent(
        "Find every HTTP handler that writes an uploaded file to disk. "
        "For each one give the file, the line where the path is built, the function name "
        "and that line of code copied exactly.",
        schema=SURFACE,
    )

    await phase("Verify", title="Verify")
    findings = []
    for h in surface.get("handlers", []):
        finding = {
            "id": h["function"],
            "claim": f"{h['function']} joins the client file name into the storage path without normalising it",
            "location": f"{h['file']}:{h['line']}",
        }
        verdict = await verify_finding(finding)
        findings.append(verdict)
        if verdict.get("confirmed"):
            await submit_finding(
                {
                    "actor": "unauthenticated user",
                    "capability": "upload a file with a crafted name",
                    "entry_point": f"{h['file']}:{h['function']}",
                    "security_boundary": "HTTP request",
                    "violated_invariant": "uploaded file name joined to the storage path without normalising",
                    "observable_impact": "files written outside the upload directory",
                    "severity": 8,
                    "confidence": 7,
                    "cwe": "CWE-22",
                    "reachability": "proven",
                    "input_control": "full",
                    "guard_coverage": "no_paths",
                    "exposure": "internet",
                },
                [
                    {
                        "kind": "code",
                        "description": "client controlled name used in the path",
                        "file_path": h["file"],
                        "line_start": h["line"],
                        "line_end": h["line"],
                        "snippet": "",
                        "anchor_text": h["code"].strip(),
                        "analysis_quality": {"method": "structural"},
                    }
                ],
            )
    return {"findings": findings}
```

`anchor_text` has to be copied from the cited lines (at least 12 characters), because the engine re-reads the file to check it. Evidence sent from a workflow counts as structural at most.

## Extra MCP servers

Workflow scripts and `deep-research` can also use the MCP servers listed under `mcpServers` in `~/.claude.json` (`stdio`, `sse` or `http` transport). They show up to the model as `mcp__<server>__<tool>`.

Only read-only tools are offered: tools the server marks with `readOnlyHint`, or whose names start with `read_`, `list_`, `get_`, `search_`, `grep_`, `query_`, `describe_`, `show_`, `fetch_`, `find_` or `check_`. Anything else has to be listed explicitly in `mcp_allow` in your config, and a tool that wasn't offered can't be called.

## Writing your own skills

A skill is one markdown file in a phase folder. The file name is the skill name:

```
skills/
  p4/
    hunt-graphql-introspection.md
```

```bash
python pentest.py --headless list-skills
python pentest.py --headless skill hunt-graphql-introspection ~/src/acme-shop
```

Skills whose names start with `hunt-` run in breadth mode: short checks, many patterns, and a strict output format the engine already explains to the model. Every other skill runs in deep mode with the full analysis rules. Look at an existing skill in the same phase before writing one; they all follow the same layout (trigger, inputs, steps, what to submit).

Things that keep a skill working:

- Write grep patterns in ripgrep's syntax exactly as `rg` should receive them: `\.execute\(`, not `\\.execute\\(`. No lookarounds. Use `multiline=true` when the pattern contains `\n`.
- The tools are `search_graph`, `trace_path` (`direction="inbound"` for callers, `"outbound"` for callees), `get_code_snippet`, `search_code` (literal unless `regex=true`), `read_file`, `list_dir`, `grep`, `parse_file_structure`, `find_all_usages`, `run_semgrep` (a pattern needs a `language`) and `shell`.
- `shell` runs one read-only command at a time with no pipes: `git log/show/blame/diff/ls-files/ls-tree/rev-parse/status/shortlog/describe/grep`, `find` (tests only, no `-exec` or `-delete`), `tree`, `wc`, `head`, `tail`, `file`, `stat`, `sha256sum`, `sha1sum`, `md5sum`, `jq`, `diff`, `strings`, `cut`. Paths have to stay inside the repo. `ls`, `cat` and `sed` are refused with a pointer to `list_dir` and `read_file`, and the sandbox image ships every command on the list.
- Valid `exposure` values are `internet`, `authenticated`, `internal`, `admin_only` and `unreachable`. Anything else gets reset to `unspecified`.
- Evidence goes in the top-level `evidence` array of `finish()`, tied to its finding by `hypothesis_index`; a hypothesis has no field for evidence of its own. When a finding with confidence above 3 has no evidence item, or a hypothesis is missing a required field, `finish()` is sent back to the model with the list of problems, twice at most. Arguments that are almost valid JSON (a missing closing bracket, an unescaped quote or backslash) are repaired and recorded instead of being sent back; a reply cut off at the token limit is never repaired, and neither is one whose repair would drop text. A finding that still has no evidence is kept as a lead at confidence 3 and never reaches the report.
- A proof obligation's status is judged against the finding, not the wording of its question. For "Is any rate limiter applied?" with no limiter in the code, the answer supports the finding, so the obligation is `verified`; `refuted` means the evidence shows the finding does not hold. A finding sent with a required obligation marked `refuted` goes back to the model with that note, within the same two retries.
- `guard_coverage` describes the paths the attacker can use. `some_paths` means other paths are guarded but at least one usable path isn't, and that path goes in `uncovered_paths`. A finding with `some_paths` and no named path goes back to the model, and until a path is named the engine keeps an open guard obligation on it.
- A map the skill should keep goes to `amend_threat_model`, which works before any base threat model exists. When the skill reaches its closing turns first, the map can go in the `threat_model_update` field of `finish()`, with `base: true` for the base sections when none has been saved yet. Only a skill whose text mentions `save_threat_model` or `amend_threat_model` is reminded of this in its closing turns, and other skills are asked to leave the field out.

A skill file can start with a short YAML header:

```markdown
---
order: 35
tier: fast
parallel: true
requires: [web, multiservice]
max_turns: 40
---

# SKILL: map-graphql-schema
```

| Key | Default | Meaning |
|---|---|---|
| `order` | `100` | Where the skill runs inside its phase. Lower goes first; equal numbers run in alphabetical order. The built-in `p1` and `p2` skills use 10, 20, 30 and so on, which leaves room in between |
| `tier` | `main` | `fast` runs the skill on `fast_model` when one is set |
| `parallel` | `false` | The skill doesn't depend on others in its phase and may run alongside them |
| `requires` | none | Skip the skill unless the project shows at least one of these: `web`, `templates`, `iac`, `llm`, `messaging`, `multiservice`, `ldap`, `multitenant` |
| `optional` | `false` | Leave the skill out of `run` unless `optional_skills` is on or `--all-skills` is given. `skill <name>` still runs it |
| `max_turns` | `30` | How many model turns the skill gets (8 to 120). The last six only allow `finish()`. The built-in mapping, modelling, tracing and `understand-*` skills use 40; the `hunt-*` skills keep 30 |
| `fanout` | none | `entry_points` runs the skill once per batch of entry points instead of once for the whole application (see below) |
| `batch` | `6` | How many entry points one fan-out run gets (1 to 40) |

The header is stripped before the skill text goes to the model. A header that doesn't parse stops the run with the file name in the error, instead of being sent along as text.

**Fan-out over entry points.** With `fanout: entry_points` the engine builds an inventory first: the entry points the `p1` skills recorded, normalised and deduplicated, plus the routes the code graph sees registered (every page of them; routes that only test files call are left out). A `p1` entry that lists several methods or paths becomes one entry per method and path. It groups them by their first meaningful path segment, so `/rest/basket/:id` and `/rest/basket/:id/checkout` are reviewed together, and runs the skill once per batch, in parallel up to `concurrency`. Each run gets an "Assigned entry points" list and must record a coverage decision for every entry on it (`unseen` is not a decision). Entries that come back without a decision get one more pass, and are then marked `needs_follow_up`, so `coverage` shows exactly which entry points nobody looked at. That mark never replaces a decision another skill recorded, and a later decision on the entry replaces it. Every batch has its own transcript and usage line. `--resume` remembers which entry points were already reviewed and which still need their second pass, so a resumed scan runs only what is left, even when the inventory has grown since. Without any inventory the skill runs once and finds the entry points itself. Text given with `--context` reaches every batch.

**Findings that already exist.** Every skill sees a compact list of the findings already recorded. When a skill has new evidence for one of them, it sends an entry with `existing_id` set to that finding's id instead of reporting the bug again; the engine checks the new evidence like any other, attaches it to the recorded finding and runs the gate on all of its evidence, without changing its wording or a triage decision. A stronger reachability, input control or guard claim and any proof obligations the entry resolves are applied to the finding as well. New evidence reopens a finding that a model rejected or marked blocked; a human decision stays. Evidence added this way never lowers the finding's confidence cap.

## Where things are stored

| What | Where |
|---|---|
| Config | `--config`, `PENTEST_CONFIG`, `config.yaml` next to `pentest.py`, or `~/.pentest/config.yaml` |
| Evidence store | `~/.pentest/evidence.db` (`db_path`) |
| Resume state and profile cache | `$XDG_CACHE_HOME/pentest`, usually `~/.cache/pentest` |
| Model conversations | `transcripts/` next to the evidence store (`transcripts_dir`) |
| tree-sitter grammars | `~/.cache/tree-sitter-language-pack` |
| Code graph | managed by codebase-memory-mcp |
| Sandbox code graph and grammars | `~/.cache/pentest/sandbox` |

Nothing is written into the repository you scan.

## Troubleshooting

**`no container runtime found` or `daemon is not reachable`**
Scans run in a container by default. Install or start Docker or Podman, or use `--allow-dangerously-trust` for code you trust.

**`api_key is required`**
Set `PENTEST_API_KEY`, run `config-init`, or pass `--api-key`.

**grep tool errors, or `multiline search requires ripgrep`**
ripgrep isn't on `PATH`. Install it (`apt install ripgrep`, `brew install ripgrep`, ...). Without it the tool falls back to GNU grep, which doesn't understand most skill patterns.

**Graph tools return nothing**
codebase-memory-mcp isn't installed or the repo isn't indexed. Run `pentest.py --headless init <repo>`; it prints `Code graph project: <name>` when the index can be used. `install.sh --check` tells you whether the binary is on `PATH`. The sandbox has its own index, so run `init` in the same mode (sandboxed or not) as the scan.

**A skill ends with `produced no structured output`**
The model never completed a `finish()` call. The `turn` events in the skill's transcript show the `finish_reason` of each reply; `length` means it hit `max_tokens`. Raise `max_tokens`, lower `reasoning_effort`, or pick a model with a larger output limit.

**The scan runs but nothing is exported**
Run `doctor`. The usual reasons are unresolved proof obligations, a blocking open question, or evidence that's only textual. `query <repo> "why <id>"` shows the details for one finding.

**Symbol parsing is slow the first time on an offline machine**
tree-sitter grammars are downloaded on first use. Without network the parser gives up after 20 seconds and falls back to a simpler parser. Run `install.sh` once while online to pre-download them.

**`triage` does nothing inside the UI**
It's interactive. Type `headless`, or run `python pentest.py --headless triage <repo>`.

## Development

```bash
pip install -r requirements.txt pytest
python -m pytest
```

None of the tests need an API key or network access; the model is replaced by scripted fakes and the TUI is driven through Textual's test pilot. `tests/test_audit_regressions.py` can also be run directly as a script, and it prints one line per check.

`tests/sandbox_smoke.py` is the one check that needs Docker. It uses the real image (building it if needed), runs `init` and a skill inside the container against a fake model server, and then probes the container: the repository and root filesystem must be read-only, files outside the mounts invisible, all capabilities dropped, and the API key absent from the command line.

```bash
python tests/sandbox_smoke.py
```

The engine lives in `core/`:

| File | What's in it |
|---|---|
| `runner.py` | the agent loop for skills, verification and workflow prompts |
| `tool_exec.py` | the tools the model can call |
| `intake.py`, `evidence_gate.py` | turning the model's report into hypotheses, and the gate that decides what gets exported |
| `reconcile.py` | re-checking stored evidence against the current code |
| `prompts.py`, `tool_specs.py` | system prompts, output contracts and tool definitions |
| `skills.py` | loading skill files and their headers |
| `stack.py` | the quick look at the repository that decides which skills apply |
| `context.py` | shortening old tool output in long conversations |
| `llm.py`, `usage.py`, `transcript.py` | talking to the model, metering it, saving the conversation |
| `sandbox.py` | starting commands inside the container |
| `db.py` | the SQLite evidence store |

Changes to the evidence store's schema go in as numbered migrations in `db.py`. The database remembers which version it's at (`PRAGMA user_version`), so an older database is upgraded in place the first time a new release opens it, and a database written by a newer release is refused instead of being damaged.

Every push to `main` runs the suite on GitHub Actions: Python 3.10 to 3.14 on Ubuntu, 3.14 on macOS, once more with every dependency pinned to the oldest version `requirements.txt` allows, a job that builds the sandbox image and runs the smoke test, and a last one that builds the wheel, installs it into a clean virtualenv and runs the `arad` command.
