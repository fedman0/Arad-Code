#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# llmsast — dependency installer
#
#   ./install.sh                  install core + recommended
#   ./install.sh --tier core      minimum to run the engine
#   ./install.sh --tier all       everything incl. roadmap tooling
#   ./install.sh --check          verify only, install nothing
#   ./install.sh --dry-run        print what would happen
#   ./install.sh --no-venv        install python deps into the current env
#
# Supports: Debian/Ubuntu, Fedora/RHEL, Arch, Alpine, macOS (Homebrew).
# Idempotent: safe to re-run.
# ---------------------------------------------------------------------------
set -uo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
TIER="recommended"
CHECK_ONLY=0
DRY_RUN=0
USE_VENV=1
VENV_DIR="${LLMSAST_VENV:-$SCRIPT_DIR/.venv}"
BIN_DIR="${LLMSAST_BIN:-$HOME/.local/bin}"
REQ_FILE="$SCRIPT_DIR/requirements.txt"
SEMGREP_VENV="${LLMSAST_SEMGREP_VENV:-$HOME/.local/share/llmsast/semgrep-venv}"
PY_PKGS=(
  "openai:openai" "pydantic:pydantic" "mcp:mcp" "click:click" "pyyaml:yaml" "rich:rich"
  "tree-sitter>=0.25,<0.27:tree_sitter" "tree-sitter-language-pack>=1.20:tree_sitter_language_pack"
  "textual:textual" "arabic-reshaper:arabic_reshaper" "python-bidi:bidi"
)

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLU=$'\033[34m'; DIM=$'\033[2m'; RST=$'\033[0m'
ok()   { printf '  %s✓%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$RST" "$*"; }
err()  { printf '  %s✗%s %s\n' "$RED" "$RST" "$*"; }
hdr()  { printf '\n%s==>%s %s\n' "$BLU" "$RST" "$*"; }
note() { printf '    %s%s%s\n' "$DIM" "$*" "$RST"; }

MISSING=(); INSTALLED=(); FAILED=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier)     [[ $# -ge 2 ]] || { err "--tier needs a value: core|recommended|all"; exit 2; }
                TIER="$2"; shift 2 ;;
    --tier=*)   TIER="${1#*=}"; shift ;;
    --check)    CHECK_ONLY=1; shift ;;
    --dry-run)  DRY_RUN=1; shift ;;
    --no-venv)  USE_VENV=0; shift ;;
    -h|--help)  awk 'NR > 1 && /^# ----/ { if (++n == 2) exit; next } NR > 1 { sub(/^# ?/, ""); print }' "$SCRIPT_PATH"; exit 0 ;;
    *) err "unknown flag: $1"; exit 2 ;;
  esac
done
case "$TIER" in core|recommended|all) ;; *) err "tier must be core|recommended|all"; exit 2 ;; esac

# --------------------------------------------------------------------------
# platform detection
# --------------------------------------------------------------------------
OS="$(uname -s)"; ARCH="$(uname -m)"
case "$ARCH" in x86_64|amd64) GOARCH=amd64 ;; aarch64|arm64) GOARCH=arm64 ;; *) GOARCH="$ARCH" ;; esac

PKG=""
if   command -v brew    >/dev/null 2>&1; then PKG=brew
elif command -v apt-get >/dev/null 2>&1; then PKG=apt
elif command -v dnf     >/dev/null 2>&1; then PKG=dnf
elif command -v pacman  >/dev/null 2>&1; then PKG=pacman
elif command -v apk     >/dev/null 2>&1; then PKG=apk
fi

SUDO=""
[[ $EUID -ne 0 && "$PKG" != "brew" ]] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"

run() {
  if [[ $DRY_RUN -eq 1 ]]; then note "would run: $*"; return 0; fi
  "$@" >/dev/null 2>&1
}

have() { command -v "$1" >/dev/null 2>&1; }

pkg_for() {
  case "$PKG" in
    apt) echo "$1" ;; dnf) echo "$2" ;; pacman) echo "$3" ;; apk) echo "$4" ;; brew) echo "$5" ;;
  esac
}

pkg_install() {
  case "$PKG" in
    apt)    run $SUDO apt-get install -y "$1" ;;
    dnf)    run $SUDO dnf install -y "$1" ;;
    pacman) run $SUDO pacman -S --noconfirm "$1" ;;
    apk)    run $SUDO apk add --no-cache "$1" ;;
    brew)   run brew install "$1" ;;
    *)      return 1 ;;
  esac
}

# install a system package; args: <binary> <apt> <dnf> <pacman> <apk> <brew>
sys_pkg() {
  local bin="$1" name
  if have "$bin"; then ok "$bin $(note_ver "$bin")"; return 0; fi
  if [[ $CHECK_ONLY -eq 1 ]]; then err "$bin missing"; MISSING+=("$bin"); return 1; fi
  if [[ -z "$PKG" ]]; then err "no package manager; install '$bin' manually"; FAILED+=("$bin"); return 1; fi
  name="$(pkg_for "${@:2}")"
  if [[ -z "$name" || "$name" == "-" ]]; then err "no $PKG package for '$bin'; install it manually"; FAILED+=("$bin"); return 1; fi
  pkg_install "$name"
  if have "$bin" || [[ $DRY_RUN -eq 1 ]]; then ok "$bin installed"; INSTALLED+=("$bin")
  else err "$bin failed"; FAILED+=("$bin"); return 1; fi
}

opt_pkg() {
  local bin="$1" name
  if have "$bin"; then ok "$bin $(note_ver "$bin")"; return 0; fi
  if [[ $CHECK_ONLY -eq 1 ]]; then warn "$bin missing (optional)"; return 0; fi
  name="$(pkg_for "${@:2}")"
  if [[ -n "$name" && "$name" != "-" ]] && pkg_install "$name" && { have "$bin" || [[ $DRY_RUN -eq 1 ]]; }; then
    ok "$bin installed"; INSTALLED+=("$bin")
  else warn "$bin not installed (optional)"; fi
}

on_path() {
  local bin="$1"
  have "$bin" && return 0
  if [[ -x "$BIN_DIR/$bin" ]]; then
    err "$bin is in $BIN_DIR, which is not on PATH — the engine starts it by name"
    note "add: export PATH=\"$BIN_DIR:\$PATH\""
    MISSING+=("$bin(PATH)")
  fi
  return 1
}

note_ver() { "$1" --version 2>/dev/null | head -1 | cut -c1-48; }

summary() {
  hdr "summary"
  [[ ${#INSTALLED[@]} -gt 0 ]] && printf '  installed: %s\n' "${INSTALLED[*]}"
  [[ ${#MISSING[@]}   -gt 0 ]] && printf '  %smissing:%s   %s\n' "$YEL" "$RST" "${MISSING[*]}"
  [[ ${#FAILED[@]}    -gt 0 ]] && printf '  %sfailed:%s    %s\n' "$RED" "$RST" "${FAILED[*]}"

  if [[ ${#FAILED[@]} -eq 0 && ${#MISSING[@]} -eq 0 ]]; then
    printf '\n  %sall dependencies satisfied%s\n' "$GRN" "$RST"
    [[ $USE_VENV -eq 1 && -d "$VENV_DIR" ]] && note "activate with: source $VENV_DIR/bin/activate"
    note "verify the engine: $PY $SCRIPT_DIR/pentest.py list-skills"
    exit 0
  fi
  exit 1
}

# --------------------------------------------------------------------------
hdr "environment"
note "os=$OS arch=$ARCH pkg-manager=${PKG:-none} tier=$TIER"
[[ $CHECK_ONLY -eq 1 ]] && note "check-only mode — nothing will be installed"
[[ $DRY_RUN   -eq 1 ]] && note "dry-run mode"

mkdir -p "$BIN_DIR" 2>/dev/null
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) warn "$BIN_DIR is not on PATH — add: export PATH=\"$BIN_DIR:\$PATH\"" ;; esac

if [[ -n "$PKG" && $CHECK_ONLY -eq 0 && $DRY_RUN -eq 0 ]]; then
  case "$PKG" in
    apt)    $SUDO apt-get update -qq >/dev/null 2>&1 || true ;;
    brew)   brew update >/dev/null 2>&1 || true ;;
  esac
fi

# ==========================================================================
# TIER 1 — CORE
# ==========================================================================
hdr "core: system tools"

# python >= 3.10
if have python3; then
  PYV="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)"
  if python3 -c 'import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)'; then
    ok "python3 $PYV"
  else err "python3 $PYV is too old (need >= 3.10)"; FAILED+=(python3); fi
else
  sys_pkg python3 python3 python3 python python3 python@3.12
fi

sys_pkg git   git          git          git       git       git
sys_pkg curl  curl         curl         curl      curl      curl
# ripgrep: _rg_grep() in code_analysis.py uses it; the grep fallback is much slower
sys_pkg rg    ripgrep      ripgrep      ripgrep   ripgrep   ripgrep

hdr "core: python packages"
PY=python3
venv_ok() { [[ -x "$VENV_DIR/bin/python" ]] && "$VENV_DIR/bin/python" -m pip --version >/dev/null 2>&1; }
if [[ $USE_VENV -eq 1 && $CHECK_ONLY -eq 0 ]]; then
  if venv_ok; then ok "virtualenv exists at $VENV_DIR"
  else
    [[ "$PKG" == "apt" ]] && run $SUDO apt-get install -y python3-venv
    if run python3 -m venv "$VENV_DIR" && { [[ $DRY_RUN -eq 1 ]] || venv_ok; }; then
      ok "virtualenv created at $VENV_DIR"
    else
      err "virtualenv creation failed at $VENV_DIR (python3 -m venv / pip unavailable)"
      [[ "$PKG" == "apt" ]] && note "install python3-venv: $SUDO apt-get install python3-venv"
      FAILED+=(venv)
    fi
  fi
  [[ -x "$VENV_DIR/bin/python" ]] && PY="$VENV_DIR/bin/python"
elif [[ $USE_VENV -eq 1 ]]; then
  if [[ -x "$VENV_DIR/bin/python" ]]; then PY="$VENV_DIR/bin/python"; ok "virtualenv at $VENV_DIR"
  else warn "no virtualenv at $VENV_DIR — checking $PY"; fi
fi

pip_i() {
  if [[ $CHECK_ONLY -eq 1 ]]; then
    if "$PY" -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('${2:-$1}') else 1)" 2>/dev/null
    then ok "py:$1"; else err "py:$1 missing"; MISSING+=("py:$1"); fi
    return
  fi
  if run "$PY" -m pip install -q --upgrade "$1"; then ok "py:$1"; INSTALLED+=("py:$1")
  else err "py:$1 failed"; FAILED+=("py:$1"); fi
}

if [[ $CHECK_ONLY -eq 0 ]]; then run "$PY" -m pip install -q --upgrade pip setuptools wheel; fi

if [[ $CHECK_ONLY -eq 1 ]]; then
  for p in "${PY_PKGS[@]}"; do pip_i "${p%:*}" "${p##*:}"; done
elif [[ -f "$REQ_FILE" ]]; then
  if run "$PY" -m pip install -q -r "$REQ_FILE"; then
    ok "requirements.txt installed"; INSTALLED+=("requirements.txt")
  else err "requirements.txt failed"; FAILED+=("requirements.txt"); fi
else
  warn "requirements.txt not found — installing packages individually"
  for p in "${PY_PKGS[@]}"; do pip_i "${p%:*}" "${p##*:}"; done
fi

# --- the tree-sitter ABI trap -------------------------------------------
hdr "core: tree-sitter sanity check"
if [[ $DRY_RUN -eq 0 ]]; then
  if "$PY" - <<'EOF' 2>/dev/null
import sys
try:
    import tree_sitter_languages  # noqa
    sys.exit(42)   # present => ABI conflict with tree-sitter >= 0.22
except ImportError:
    pass
try:
    from tree_sitter_language_pack import get_parser
    get_parser("python").parse(b"def f():\n    pass\n")
    sys.exit(0)
except Exception as e:
    print(e, file=sys.stderr); sys.exit(1)
EOF
  then ok "tree-sitter grammars working (language-pack)"
  else
    rc=$?
    if [[ $rc -eq 42 ]]; then
      err "tree-sitter-languages is installed — it is ABI-incompatible with tree-sitter >= 0.22"
      note "fix: $PY -m pip uninstall -y tree-sitter-languages && $PY -m pip install 'tree-sitter-language-pack>=1.20'"
      FAILED+=("tree-sitter-abi")
    else
      err "tree-sitter parser could not be built — the engine will silently fall back to grep"
      FAILED+=("tree-sitter")
    fi
  fi
fi

# grammars are fetched on first use; pre-warm so an air-gapped scan does not fail
if [[ $CHECK_ONLY -eq 0 && $DRY_RUN -eq 0 && "$TIER" != "core" ]]; then
  "$PY" - <<'EOF' 2>/dev/null
from tree_sitter_language_pack import get_parser
langs = ["python","javascript","typescript","tsx","go","java","csharp","ruby",
         "rust","php","kotlin","swift","cpp","c","scala","bash","yaml","hcl"]
okc = 0
for l in langs:
    try: get_parser(l); okc += 1
    except Exception: pass
print(f"  \033[32m✓\033[0m pre-warmed {okc}/{len(langs)} grammars")
EOF
fi

hdr "core: semgrep"
if have semgrep; then ok "semgrep $(note_ver semgrep)"
elif [[ $CHECK_ONLY -eq 1 ]]; then
  if [[ -x "$BIN_DIR/semgrep" ]]; then on_path semgrep
  else err "semgrep missing"; MISSING+=(semgrep); fi
else
  # prefer the venv copy from requirements.txt; fall back to brew/pipx
  if [[ -x "$VENV_DIR/bin/semgrep" ]]; then run ln -sf "$VENV_DIR/bin/semgrep" "$BIN_DIR/semgrep"
  elif [[ "$PKG" == "brew" ]]; then run brew install semgrep
  elif have pipx; then run env PIPX_BIN_DIR="$BIN_DIR" pipx install semgrep
  elif run python3 -m venv "$SEMGREP_VENV" && run "$SEMGREP_VENV/bin/python" -m pip install -q --upgrade semgrep; then
    run ln -sf "$SEMGREP_VENV/bin/semgrep" "$BIN_DIR/semgrep"
  else run python3 -m pip install -q --user semgrep; fi
  if [[ $DRY_RUN -eq 1 ]] || on_path semgrep; then ok "semgrep installed"; INSTALLED+=(semgrep)
  elif [[ ! -x "$BIN_DIR/semgrep" ]]; then err "semgrep failed"; FAILED+=(semgrep); fi
fi

[[ "$TIER" == "core" ]] && summary

# ==========================================================================
# TIER 2 — RECOMMENDED
# ==========================================================================
hdr "recommended: shell tools used by run_shell()"
# these are in _SHELL_WHITELIST in core/code_analysis.py
sys_pkg jq   jq   jq   jq   jq   jq
sys_pkg tree tree tree tree tree tree
sys_pkg file file file file file file
opt_pkg xxd  xxd  vim-common xxd  xxd  -

# yq has no reliable distro package; take the release binary
if have yq; then ok "yq $(note_ver yq)"
elif [[ $CHECK_ONLY -eq 1 ]]; then warn "yq missing (optional)"
elif [[ "$PKG" == "brew" ]]; then run brew install yq && ok "yq installed"
else
  YQ_URL="https://github.com/mikefarah/yq/releases/latest/download/yq_$(echo "$OS" | tr '[:upper:]' '[:lower:]')_${GOARCH}"
  if run curl -fsSL "$YQ_URL" -o "$BIN_DIR/yq" && run chmod +x "$BIN_DIR/yq"; then
    ok "yq installed -> $BIN_DIR/yq"; INSTALLED+=(yq)
  else warn "yq install failed (optional)"; fi
fi

hdr "recommended: codebase-memory-mcp (the code graph backend)"
# core/memory_mcp.py spawns this binary; without it search_graph/trace_path/
# get_architecture all return nothing and the agent degrades to grep.
if have codebase-memory-mcp; then ok "codebase-memory-mcp $(note_ver codebase-memory-mcp)"
elif [[ $CHECK_ONLY -eq 1 ]]; then
  if [[ -x "$BIN_DIR/codebase-memory-mcp" ]]; then on_path codebase-memory-mcp
  else err "codebase-memory-mcp missing"; MISSING+=(codebase-memory-mcp); fi
else
  installed=0
  if [[ "$PKG" == "brew" ]] && run brew install codebase-memory-mcp; then installed=1
  elif have npm  && run npm install -g codebase-memory-mcp; then installed=1
  elif run "$PY" -m pip install -q codebase-memory-mcp; then
    installed=1
    py_scripts="$("$PY" -c 'import sysconfig; print(sysconfig.get_path("scripts"))' 2>/dev/null)"
    if [[ -n "$py_scripts" && -x "$py_scripts/codebase-memory-mcp" ]] && ! have codebase-memory-mcp; then
      run ln -sf "$py_scripts/codebase-memory-mcp" "$BIN_DIR/codebase-memory-mcp"
    fi
  else
    # official one-liner; --skip-config keeps it from rewriting your agent configs
    if run bash -c 'curl -fsSL https://raw.githubusercontent.com/DeusData/codebase-memory-mcp/main/install.sh | bash -s -- --skip-config'; then installed=1; fi
  fi
  if [[ $DRY_RUN -eq 1 ]] || { [[ $installed -eq 1 ]] && on_path codebase-memory-mcp; }; then
    ok "codebase-memory-mcp installed"; INSTALLED+=(codebase-memory-mcp)
  elif [[ $installed -eq 0 || ! -x "$BIN_DIR/codebase-memory-mcp" ]]; then
    err "codebase-memory-mcp failed"; FAILED+=(codebase-memory-mcp)
    note "manual: https://github.com/DeusData/codebase-memory-mcp"; fi
fi

hdr "recommended: ast-grep (structural search / rule prototyping)"
if have ast-grep || have sg; then ok "ast-grep present"
elif [[ $CHECK_ONLY -eq 1 ]]; then warn "ast-grep missing (optional)"
elif [[ "$PKG" == "brew" ]] && run brew install ast-grep; then ok "ast-grep installed"
elif have npm && run npm install -g @ast-grep/cli; then ok "ast-grep installed"
elif have cargo && run cargo install ast-grep --locked; then ok "ast-grep installed"
else warn "ast-grep not installed (needs brew, npm or cargo)"; fi

hdr "recommended: docker (sandbox for PoC validation)"
if have docker; then
  if run docker info; then ok "docker running"
  else warn "docker installed but daemon not reachable"; fi
else
  warn "docker not found — runtime/PoC validation will be unavailable"
  note "https://docs.docker.com/engine/install/"
fi

# ==========================================================================
# TIER 3 — ALL (roadmap tooling)
# ==========================================================================
if [[ "$TIER" == "all" ]]; then

hdr "optional: semantic layer (SCIP / LSP indexers)"
# replaces the grep-based call graph — see language_adapter.py resolve_callers()
if [[ $CHECK_ONLY -eq 0 ]]; then
  pip_i multilspy                                   # generic LSP client, any language server
  have npm   && run npm install -g @sourcegraph/scip-typescript && ok "scip-typescript" || warn "scip-typescript skipped (needs npm)"
  run "$PY" -m pip install -q scip-python && ok "scip-python" || warn "scip-python skipped"
  have go    && run go install golang.org/x/tools/gopls@latest && ok "gopls" || warn "gopls skipped (needs go)"
  have rustup && run rustup component add rust-analyzer && ok "rust-analyzer" || warn "rust-analyzer skipped (needs rustup)"
  cs_bin=""; have coursier && cs_bin=coursier; have cs && cs_bin=cs
  if [[ -n "$cs_bin" ]]; then run "$cs_bin" install scip-java && ok "scip-java" || warn "scip-java failed"; else warn "scip-java skipped (needs coursier)"; fi
else
  if "$PY" -c 'import multilspy' >/dev/null 2>&1; then ok "multilspy"; else warn "multilspy missing"; fi
  for t in scip-typescript gopls rust-analyzer; do have "$t" && ok "$t" || warn "$t missing"; done
fi

hdr "optional: secrets scanning"
if [[ "$PKG" == "brew" ]]; then
  sys_pkg gitleaks - - - - gitleaks
  sys_pkg trufflehog - - - - trufflehog
else
  for t in gitleaks trufflehog; do have "$t" && ok "$t" || warn "$t missing — see github.com/gitleaks/gitleaks"; done
fi

hdr "optional: SCA / dependency + IaC scanning"
for spec in "syft:anchore/syft" "grype:anchore/grype" "osv-scanner:google/osv-scanner" "trivy:aquasecurity/trivy"; do
  t="${spec%%:*}"; repo="${spec##*:}"
  if have "$t"; then ok "$t"
  elif [[ "$PKG" == "brew" && $CHECK_ONLY -eq 0 ]]; then run brew install "$t" && ok "$t installed" || warn "$t skipped"
  else warn "$t missing — https://github.com/$repo/releases"; fi
done
[[ $CHECK_ONLY -eq 0 ]] && pip_i checkov

hdr "optional: benchmark corpora (FP measurement)"
BENCH_DIR="${LLMSAST_BENCH:-$SCRIPT_DIR/benchmarks}"
if [[ $CHECK_ONLY -eq 0 && $DRY_RUN -eq 0 ]]; then
  mkdir -p "$BENCH_DIR"
  clone() { [[ -d "$BENCH_DIR/$2" ]] && { ok "$2 (cached)"; return; }
            run git clone --depth 1 "$1" "$BENCH_DIR/$2" && ok "$2 cloned" || warn "$2 clone failed"; }
  clone https://github.com/OWASP-Benchmark/BenchmarkJava.git       owasp-benchmark-java
  clone https://github.com/juliet-test-suite/juliet-test-suite-c   juliet-c
  clone https://github.com/WebGoat/WebGoat.git                     webgoat
  clone https://github.com/digininja/DVWA.git                      dvwa
  note "for CVE pre/post-patch pairs see: https://github.com/secureIT-project/CVEfixes"
else
  note "would clone OWASP Benchmark, Juliet, WebGoat, DVWA into $BENCH_DIR"
fi

fi  # tier all

# ==========================================================================
summary
