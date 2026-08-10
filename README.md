# 🛡️ InternShield — Cloud Security Command Center (CSCC)

A terminal-based, **read-only** cloud security auditing tool that scans **AWS S3**, **AWS IAM**, and **Docker images** (via Trivy), scores findings with a deterministic risk engine, optionally enriches them with AI-generated remediation advice, and exports clean **JSON/HTML** reports.

```
+==============================================================+
|                       INTERN SHIELD                           |
|              CLOUD SECURITY COMMAND CENTER                    |
+==============================================================+
```

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## ✨ Features

- **AWS S3 Scanner** — public exposure, missing encryption, missing public-access blocks
- **AWS IAM Scanner** — MFA status, stale access keys, privilege-escalation vectors (e.g. `AdministratorAccess`, `iam:PutUserPolicy`)
- **Docker Scanner** — CVEs, misconfigurations, and leaked secrets via [Trivy](https://github.com/aquasecurity/trivy)
- **Deterministic Risk Engine** — severity is calculated by rules first; AI is advisory-only, never authoritative
- **Durable, multi-provider AI layer** — Shell-GPT → OpenAI → Anthropic (Claude) → built-in offline advisor. One missing key or tool never breaks the feature; it just degrades to the next option.
- **Self-healing error handling** — any failure (missing tool, bad config, network issue, uncaught exception) is automatically explained in plain language with a concrete fix, instead of a raw traceback.
- **Reports** — JSON (for SIEM/automation) and a standalone HTML dashboard
- **Interactive CLI** — a guided menu (`questionary` + `rich`) as well as direct Typer subcommands for scripting/CI
- **Strictly read-only** — every scanner only calls read/describe/list APIs. Nothing is ever modified in your AWS account or Docker registry.

## 🏗️ Project Structure

```
InternShield-CSCC/
├── setup.sh                 # One-time environment bootstrap (idempotent)
├── execute.sh                # Bash + Python "merger" — run this to use the tool
├── requirement.txt           # Python dependencies
├── .env.example               # Copy to .env — API keys / AWS overrides
├── config.example.yaml       # Copy to config.yaml — app settings
├── LICENSE
├── .gitignore
└── python code/               # All application logic (5 files max)
    ├── core_engine.py         # Config, exceptions, logger, models, risk engine, validators
    ├── scanners.py            # S3Scanner, IAMScanner, DockerScanner
    ├── ai_engine.py           # ShellGPT / OpenAI / Anthropic providers + offline fallback + error resolver
    ├── reporting.py           # JSON + HTML report generators
    └── main_cli.py            # CLI commands, dashboard, interactive menu, entry point, global error handler
```

Two folders are created automatically on first run and are git-ignored except for a `.gitkeep`:

```
logs/       # application.log, errors.log
reports/    # generated *.json / *.html assessment reports
```

## ✅ Prerequisites

| Requirement | Needed for | Notes |
|---|---|---|
| Python 3.9+ | Everything | `setup.sh` checks this for you |
| AWS CLI configured (`aws configure`) or valid `~/.aws/credentials` | `s3`, `iam` audits | A read-only policy is enough (e.g. `SecurityAudit` managed policy) |
| [Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) on `PATH` | `docker` audits | Optional — only needed for image scans |
| An OpenAI **or** Anthropic (Claude) API key, **or** [Shell-GPT](https://github.com/TheR1D/shell_gpt) | AI-enriched remediation & error explanations | Optional — the tool still runs without any of these, using the built-in offline advisor |

## 🚀 Quickstart

```bash
git clone <your-fork-url> InternShield-CSCC
cd InternShield-CSCC

chmod +x setup.sh execute.sh
./setup.sh          # creates .venv, installs deps, copies .env/config templates

# (optional) add your key(s)
nano .env            # set OPENAI_API_KEY and/or ANTHROPIC_API_KEY

./execute.sh          # launches the interactive menu
```

### Direct subcommands (for scripting / CI)

```bash
./execute.sh s3                     # AWS S3 audit only
./execute.sh iam                    # AWS IAM audit only
./execute.sh docker nginx:1.19.6     # Docker/Trivy scan of an image
./execute.sh full-audit              # Combined S3 + IAM
./execute.sh doctor                   # Environment diagnostics + AI-explained fixes
```

## 🤖 How the AI layer stays "durable" on a free tier

`config.yaml`'s `ai.default_provider: auto` (the default) tries, in order:

1. **Shell-GPT** (`sgpt`) — if installed and configured, used first, no code-level key needed
2. **OpenAI** — if `OPENAI_API_KEY` is set (uses `gpt-4o-mini` by default — cheap on tokens)
3. **Anthropic / Claude** — if `ANTHROPIC_API_KEY` is set (uses `claude-3-5-haiku` by default — also cheap)
4. **Offline advisor** — a zero-cost, zero-network, rule-based fallback that always works

`ai.max_findings_sent_to_ai` in `config.yaml` caps how many findings get sent per run, so a limited-token free-tier key isn't exhausted in a single scan.

**No key is ever hardcoded in this repo.** Put your own in `.env` (already git-ignored).

## 🩺 Self-healing errors

Whenever anything fails — a missing tool, bad AWS permissions, a malformed `config.yaml`, or any uncaught Python exception — `execute.sh` and the global handler in `main_cli.py` both call into `ai_engine.resolve_error()`, which tries the same shellgpt → OpenAI → Claude → offline chain to turn the raw error into a plain-language explanation with a concrete next step, instead of leaving you with a bare traceback.

Run `./execute.sh doctor` any time you want a full health check.

## 🔒 Security model

- All scanners are **read-only**: they only call `list*`, `describe*`, `get*` AWS/Trivy APIs.
- Secrets (API keys, AWS credentials) live only in `.env`, which is git-ignored.
- Docker image names are validated before being passed to `subprocess` (no `shell=True`, no injection surface).
- Hardcoded secrets found inside scanned Docker images are never printed in full — only their category/location.

## 📄 License

MIT — see [LICENSE](LICENSE).
