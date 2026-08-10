#!/usr/bin/env bash
# ==========================================================================
# InternShield CSCC — execute.sh
# The single command that runs the tool. This is the "python + bash
# merger": bash handles environment/process orchestration and failure
# capture; on any error, it hands off to the Python AI engine
# (ai_engine.resolve_error) so the user gets a plain-language fix
# instead of a raw traceback.
#
# Usage:
#   ./execute.sh                 -> interactive menu (default)
#   ./execute.sh s3               -> AWS S3 audit only
#   ./execute.sh iam              -> AWS IAM audit only
#   ./execute.sh docker <image>   -> Docker/Trivy scan of <image>
#   ./execute.sh full-audit       -> combined S3 + IAM
#   ./execute.sh doctor           -> environment diagnostics
#   ./execute.sh --help           -> full command list (from Typer)
# ==========================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; }

mkdir -p logs reports

# --------------------------------------------------------------------
# 0. Self-healing: if the venv is missing, run setup.sh automatically
#    instead of just failing. This is what makes execute.sh "durable".
# --------------------------------------------------------------------
if [ ! -d ".venv" ]; then
    warn "No virtual environment found — running setup.sh automatically first..."
    if [ -x "./setup.sh" ]; then
        ./setup.sh
    else
        bash setup.sh
    fi
    echo ""
fi

# --------------------------------------------------------------------
# 1. Activate the virtual environment
# --------------------------------------------------------------------
if [ -f ".venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source ".venv/bin/activate"
elif [ -f ".venv/Scripts/activate" ]; then
    # shellcheck disable=SC1091
    source ".venv/Scripts/activate"
else
    warn "Could not activate .venv — continuing with system Python (may fail)."
fi

# --------------------------------------------------------------------
# 2. Load .env variables into this shell (so AWS/OpenAI/Anthropic keys
#    are visible to boto3/requests inside the Python process too)
# --------------------------------------------------------------------
if [ -f ".env" ]; then
    set -a
    # shellcheck disable=SC1091
    source ".env"
    set +a
fi

# --------------------------------------------------------------------
# 3. Make sure Python can see our merged modules in "python code/"
# --------------------------------------------------------------------
export PYTHONPATH="$SCRIPT_DIR/python code:${PYTHONPATH:-}"

PYTHON_BIN="python"
if ! command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python3"
fi

ERROR_LOG="logs/errors.log"
RUN_STDERR_TMP="$(mktemp)"
trap 'rm -f "$RUN_STDERR_TMP"' EXIT

# --------------------------------------------------------------------
# 4. Run the actual tool, capturing stderr so we can hand a failure to
#    the AI error-resolver, while still streaming everything live to
#    the user's terminal.
# --------------------------------------------------------------------
info "Launching InternShield CSCC..."
echo ""

set +e
"$PYTHON_BIN" "python code/main_cli.py" "$@" 2> >(tee "$RUN_STDERR_TMP" >&2)
EXIT_CODE=$?
set -e 2>/dev/null || true

# --------------------------------------------------------------------
# 5. AI-powered error assistant on non-zero / non-interrupt exit codes
# --------------------------------------------------------------------
if [ "$EXIT_CODE" -ne 0 ] && [ "$EXIT_CODE" -ne 130 ]; then
    echo ""
    error "InternShield exited with status $EXIT_CODE."

    RAW_ERROR="$(tail -n 20 "$RUN_STDERR_TMP" 2>/dev/null)"
    if [ -z "$RAW_ERROR" ] && [ -f "$ERROR_LOG" ]; then
        RAW_ERROR="$(tail -n 20 "$ERROR_LOG" 2>/dev/null)"
    fi
    if [ -z "$RAW_ERROR" ]; then
        RAW_ERROR="Process exited with code $EXIT_CODE and no captured stderr."
    fi

    # main_cli.py's own global handler (run()) already prints an AI
    # explanation for exceptions caught INSIDE Python. This bash-level
    # layer is the backstop for crashes Python couldn't catch itself
    # (e.g. missing interpreter, import errors before logging exists,
    # segfaults, being killed, etc.) — the "bash half" of the merger.
    if command -v sgpt >/dev/null 2>&1; then
        echo -e "${CYAN}[AI] Asking Shell-GPT to explain this failure...${NC}"
        sgpt --no-cache "Explain concisely why this shell command failed and how to fix it: $RAW_ERROR" 2>/dev/null \
            || warn "sgpt call failed too — falling back to the Python offline advisor below."
    fi

    echo -e "${CYAN}[AI] Cross-checking with the built-in resolver...${NC}"
    "$PYTHON_BIN" -c "
import sys
sys.path.insert(0, 'python code')
try:
    from ai_engine import resolve_error
    print(resolve_error('''$RAW_ERROR'''))
except Exception as inner:
    print(f'(Could not run the AI resolver itself: {inner})')
    print('Manual checklist: is .venv activated? did pip install -r requirement.txt succeed?')
    print('Check logs/errors.log and logs/application.log for the full trace.')
"
    echo ""
    warn "Full details were also written to $ERROR_LOG"
fi

exit "$EXIT_CODE"
