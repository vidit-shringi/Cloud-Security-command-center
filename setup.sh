#!/usr/bin/env bash
# ==========================================================================
# InternShield CSCC — setup.sh
# One-time environment bootstrap. Safe to re-run any time (idempotent).
# by Vidit Shringi
# ==========================================================================
#
# What this does, in order:
#   1. Verifies Python 3.9+ is installed
#   2. Creates a local virtual environment (.venv)
#   3. Installs everything in requirement.txt
#   4. Best-effort installs Shell-GPT (non-fatal if it fails / no network)
#   5. Creates .env and config.yaml from their .example templates
#   6. Creates logs/ and reports/ output directories
#   7. Checks for optional external tools (aws cli, docker, trivy) and
#      warns (does not fail) if they're missing
#
# Usage:  ./setup.sh
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
step()  { echo -e "\n${CYAN}==>${NC} $1"; }

FAILED_STEPS=()

echo -e "${GREEN}"
cat << "EOF"
+==============================================================+
|              INTERNSHIELD CSCC — SETUP.SH                    |
|          Cloud Security Command Center — Bootstrapper        |
|                                              ~Vidit Shringi  |
+==============================================================+
EOF
echo -e "${NC}"

# --------------------------------------------------------------------
# 1. Python version check
# --------------------------------------------------------------------
step "Checking for Python 3.9+"

PYTHON_BIN=""
for candidate in python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    error "No python3 interpreter found on PATH."
    echo "    Install Python 3.9+ first: https://www.python.org/downloads/"
    exit 1
fi

PY_VERSION="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
info "Found $PYTHON_BIN (version $PY_VERSION)"

MAJOR="$(echo "$PY_VERSION" | cut -d. -f1)"
MINOR="$(echo "$PY_VERSION" | cut -d. -f2)"
if [ "$MAJOR" -lt 3 ] || { [ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 9 ]; }; then
    error "Python 3.9+ is required, found $PY_VERSION."
    exit 1
fi

# --------------------------------------------------------------------
# 2. Virtual environment
# --------------------------------------------------------------------
step "Setting up virtual environment (.venv)"

if [ -d ".venv" ]; then
    info ".venv already exists — reusing it."
else
    if "$PYTHON_BIN" -m venv .venv; then
        info "Created virtual environment at ./.venv"
    else
        error "Failed to create virtual environment."
        FAILED_STEPS+=("venv creation")
    fi
fi

# shellcheck disable=SC1091
if [ -f ".venv/bin/activate" ]; then
    source ".venv/bin/activate"
elif [ -f ".venv/Scripts/activate" ]; then
    # Git Bash / WSL on Windows
    source ".venv/Scripts/activate"
else
    warn "Could not find venv activate script — continuing with system Python."
fi

# --------------------------------------------------------------------
# 3. Dependencies
# --------------------------------------------------------------------
step "Installing Python dependencies from requirement.txt"

python -m pip install --upgrade pip >/dev/null 2>&1

if python -m pip install -r requirement.txt; then
    info "All Python dependencies installed."
else
    error "pip install failed. Check your internet connection / proxy settings."
    FAILED_STEPS+=("pip install -r requirement.txt")
fi

# --------------------------------------------------------------------
# 4. Optional: Shell-GPT (local AI fallback, non-fatal if it fails)
# --------------------------------------------------------------------
step "Installing Shell-GPT (optional AI fallback)"

if python -m pip install shell-gpt >/dev/null 2>&1; then
    info "Shell-GPT installed. Run 'sgpt --version' to confirm, then configure it with your own key if desired."
else
    warn "Shell-GPT could not be installed (offline, or not critical). This is NOT fatal —"
    warn "InternShield will fall back to OpenAI/Anthropic keys, or the built-in offline advisor."
fi

# --------------------------------------------------------------------
# 5. Config templates -> real config files
# --------------------------------------------------------------------
step "Preparing configuration files"

if [ -f ".env" ]; then
    info ".env already exists — leaving it untouched."
else
    cp ".env.example" ".env"
    info "Created .env from .env.example — edit it to add your API key(s)."
fi

if [ -f "config.yaml" ]; then
    info "config.yaml already exists — leaving it untouched."
else
    cp "config.example.yaml" "config.yaml"
    info "Created config.yaml from config.example.yaml."
fi

# --------------------------------------------------------------------
# 6. Output directories
# --------------------------------------------------------------------
step "Creating output directories"

mkdir -p logs reports
touch logs/.gitkeep reports/.gitkeep
info "logs/ and reports/ are ready."

# --------------------------------------------------------------------
# 7. Optional external tools — warn only, never fail setup
# --------------------------------------------------------------------
step "Checking optional external tools"

if command -v aws >/dev/null 2>&1; then
    info "AWS CLI found ($(aws --version 2>&1 | head -n1))"
else
    warn "AWS CLI not found — needed for S3/IAM scans. Install: https://aws.amazon.com/cli/"
fi

if command -v trivy >/dev/null 2>&1; then
    info "Trivy found ($(trivy --version 2>&1 | head -n1))"
else
    warn "Trivy not found — needed for Docker image scans."
    warn "Install: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
fi

if command -v docker >/dev/null 2>&1; then
    info "Docker found."
else
    warn "Docker not found — you can still run Trivy against remote images without a local daemon."
fi

# --------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------
echo ""
if [ ${#FAILED_STEPS[@]} -eq 0 ]; then
    echo -e "${GREEN}=========================================================${NC}"
    echo -e "${GREEN} Setup complete. InternShield CSCC is ready.${NC}"
    echo -e "${GREEN}=========================================================${NC}"
    echo -e "Next steps:"
    echo -e "  1. (Optional) edit .env        -> add OPENAI_API_KEY / ANTHROPIC_API_KEY"
    echo -e "  2. (Optional) edit config.yaml -> tweak AWS region / AI provider"
    echo -e "  3. Run:  ${CYAN}./execute.sh${NC}"
else
    echo -e "${YELLOW}=========================================================${NC}"
    echo -e "${YELLOW} Setup finished with warnings/failures in:${NC}"
    for f in "${FAILED_STEPS[@]}"; do
        echo -e "   - $f"
    done
    echo -e "${YELLOW} You can still try running ./execute.sh — it will explain${NC}"
    echo -e "${YELLOW} any remaining error in plain language when it happens.${NC}"
    echo -e "${YELLOW}=========================================================${NC}"
fi
