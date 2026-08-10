"""
InternShield CSCC — CLI & Entry Point
========================================
File 5 of 5.

Merges cli/commands.py + cli/dashboard.py + cli/menu.py + cli/__init__.py
+ main.py into one file. This is the script `execute.sh` actually runs.

On top of the original logic, this file adds a GLOBAL ERROR HANDLER:
any uncaught exception anywhere in a run is caught here, logged to
logs/errors.log, and handed to `ai_engine.resolve_error()` so the user
gets a plain-language explanation + fix instead of a raw traceback —
this is the "sgpt will point out the msg" requirement from the brief.
"""

from __future__ import annotations

import sys
import traceback
from typing import List, Optional

import typer

from core_engine import log, settings
from scanners import S3Scanner, IAMScanner, DockerScanner
from ai_engine import AIProviderFactory, get_configured_provider, resolve_error
from reporting import ReportEngine

try:
    import questionary
except ImportError:
    questionary = None

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.align import Align
    _RICH = True
except ImportError:
    _RICH = False


# ======================================================================
# DASHBOARD (console output)
# ======================================================================

if _RICH:
    console = Console()
else:
    console = None


def _print(msg: str = ""):
    """Prints plain text, stripping rich markup, if rich isn't installed."""
    if _RICH:
        console.print(msg)
    else:
        import re
        print(re.sub(r"\[/?[a-zA-Z0-9_ ]+\]", "", msg))


def print_banner():
    banner = """
+==============================================================+
|                                                              |
|                       INTERN SHIELD                          |
|              CLOUD SECURITY COMMAND CENTER                   |
|                                                              |
+==============================================================+
    """
    if _RICH:
        console.print(Text(banner, style="bold bright_green", justify="center"))
        console.print(Align.center('[italic]"Cloud Security. Intelligence. Visibility."[/italic]\n'))
    else:
        print(banner)
        print('"Cloud Security. Intelligence. Visibility."\n')


def print_status_dashboard(aws_ok: bool, docker_ok: bool, ai_provider: Optional[str]):
    aws_badge = "READY" if aws_ok else "UNAVAILABLE"
    docker_badge = "READY" if docker_ok else "UNAVAILABLE"
    ai_badge = f"READY ({ai_provider})" if ai_provider else "DISABLED"

    if _RICH:
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="bold")
        table.add_row("● AWS Identity & APIs", f"[green]{aws_badge}[/green]" if aws_ok else f"[red]{aws_badge}[/red]")
        table.add_row("● Docker & Trivy", f"[green]{docker_badge}[/green]" if docker_ok else f"[yellow]{docker_badge}[/yellow]")
        table.add_row("● AI Engine", f"[green]{ai_badge}[/green]" if ai_provider else f"[yellow]{ai_badge}[/yellow]")
        panel = Panel(table, title="[bold white]SYSTEM STATUS[/bold white]", border_style="bright_green", expand=False)
        console.print(Align.center(panel))
        console.print("\n")
    else:
        print("SYSTEM STATUS")
        print(f"  AWS Identity & APIs : {aws_badge}")
        print(f"  Docker & Trivy      : {docker_badge}")
        print(f"  AI Engine           : {ai_badge}\n")


def print_assessment_summary(summary, report_paths: dict):
    html_path = report_paths.get("html", "N/A")
    if _RICH:
        table = Table(title="ASSESSMENT SUMMARY", border_style="cyan")
        table.add_column("Metric", style="white")
        table.add_column("Value", justify="right")
        table.add_row("Total Findings", str(summary.total_findings))
        table.add_row("[red]Critical[/red]", str(summary.critical_count))
        table.add_row("[yellow]High[/yellow]", str(summary.high_count))
        table.add_row("[blue]Medium[/blue]", str(summary.medium_count))
        table.add_row("[green]Low[/green]", str(summary.low_count))
        table.add_row("Report Path", f"[u]{html_path}[/u]")
        console.print("\n")
        console.print(Align.center(table))
    else:
        print("\nASSESSMENT SUMMARY")
        print(f"  Total Findings : {summary.total_findings}")
        print(f"  Critical       : {summary.critical_count}")
        print(f"  High           : {summary.high_count}")
        print(f"  Medium         : {summary.medium_count}")
        print(f"  Low            : {summary.low_count}")
        print(f"  Report Path    : {html_path}")


def print_ai_error_help(error_msg: str):
    """Prints the AI's plain-language explanation of a failure."""
    explanation = resolve_error(error_msg)
    if _RICH:
        console.print(Panel(explanation, title="[bold red]AI Error Assistant[/bold red]", border_style="red"))
    else:
        print("\n--- AI ERROR ASSISTANT -----------------------------")
        print(explanation)
        print("-----------------------------------------------------\n")


# ======================================================================
# COMMANDS / ORCHESTRATION
# ======================================================================

def initialize_ai():
    """Helper to initialize the AI provider gracefully (never raises)."""
    try:
        return get_configured_provider()
    except Exception as e:
        log.warning(f"AI Provider failed to initialize: {e}. Running without AI.")
        return None


def execute_audit(scanners: List[str], target_env: str, image_name: Optional[str] = None):
    """Core orchestration function for running any combination of scanners."""
    from core_engine import RiskEngine

    risk_engine = RiskEngine()
    ai_provider = initialize_ai()
    tools_used = []

    if "s3" in scanners:
        try:
            s3_scanner = S3Scanner(region_name=settings.aws.default_region)
            for f in s3_scanner.run_scan():
                risk_engine.add_finding(f)
            tools_used.append("AWS_S3_API")
        except Exception as e:
            log.error(f"S3 Scan failed: {e}")
            print_ai_error_help(str(e))

    if "iam" in scanners:
        try:
            iam_scanner = IAMScanner(region_name=settings.aws.default_region)
            for f in iam_scanner.run_scan():
                risk_engine.add_finding(f)
            tools_used.append("AWS_IAM_API")
        except Exception as e:
            log.error(f"IAM Scan failed: {e}")
            print_ai_error_help(str(e))

    if "docker" in scanners and image_name:
        try:
            docker_scanner = DockerScanner()
            for f in docker_scanner.run_scan(image_name):
                risk_engine.add_finding(f)
            tools_used.append("Trivy")
        except Exception as e:
            log.error(f"Docker Scan failed: {e}")
            print_ai_error_help(str(e))

    # AI Analysis — capped by max_findings_sent_to_ai to protect
    # free/limited-token API keys from being exhausted in one run.
    if ai_provider and risk_engine.findings:
        log.info("Sending High/Critical findings to AI for analysis...")
        budget = settings.ai.max_findings_sent_to_ai
        sent = 0
        for finding in risk_engine.findings:
            if sent >= budget:
                log.warning(f"AI analysis budget ({budget} findings) reached — remaining findings skipped to save tokens.")
                break
            if finding.severity.value in ["CRITICAL", "HIGH"]:
                try:
                    finding.ai_analysis = ai_provider.analyze_finding(finding)
                    sent += 1
                except Exception as e:
                    log.warning(f"AI analysis failed for {finding.finding_id}: {e}")

    summary = risk_engine.generate_summary(target_env, tools_used)
    report_paths = ReportEngine.generate_all(summary, settings.reporting.output_dir)
    print_assessment_summary(summary, report_paths)


# ======================================================================
# INTERACTIVE MENU
# ======================================================================

def interactive_menu():
    """Displays the main interactive menu."""
    if questionary is None:
        _print("[yellow]The 'questionary' package isn't installed — falling back to plain-text menu.[/yellow]")
        return _plain_menu()

    while True:
        print_banner()
        choice = questionary.select(
            "Select an Assessment Module:",
            choices=[
                "1. AWS S3 Security Audit",
                "2. AWS IAM Security Review",
                "3. Docker Image Security Scan",
                "4. Run Combined Security Assessment (AWS S3 + IAM)",
                "5. Exit",
            ],
            style=questionary.Style([
                ("qmark", "fg:green bold"),
                ("question", "bold"),
                ("answer", "fg:cyan bold"),
                ("pointer", "fg:green bold"),
                ("highlighted", "fg:green bold"),
            ]),
        ).ask()

        if not choice or "Exit" in choice:
            print("\n[+] Exiting InternShield. Stay Secure!\n")
            sys.exit(0)
        elif "S3" in choice and "Combined" not in choice:
            execute_audit(scanners=["s3"], target_env="AWS S3 Only")
        elif "IAM" in choice and "Combined" not in choice:
            execute_audit(scanners=["iam"], target_env="AWS IAM Only")
        elif "Docker" in choice:
            image_name = questionary.text("Enter Docker Image name to scan (e.g., nginx:1.19.6):").ask()
            if image_name:
                execute_audit(scanners=["docker"], target_env="Local Container", image_name=image_name)
        elif "Combined" in choice:
            execute_audit(scanners=["s3", "iam"], target_env="AWS Combined Audit")

        questionary.press_any_key_to_continue("Press any key to return to the main menu...").ask()


def _plain_menu():
    """No-dependency fallback menu (used if questionary isn't installed)."""
    while True:
        print_banner()
        print("1. AWS S3 Security Audit")
        print("2. AWS IAM Security Review")
        print("3. Docker Image Security Scan")
        print("4. Run Combined Security Assessment (AWS S3 + IAM)")
        print("5. Exit")
        choice = input("\nSelect an option [1-5]: ").strip()

        if choice == "5" or choice == "":
            print("\n[+] Exiting InternShield. Stay Secure!\n")
            sys.exit(0)
        elif choice == "1":
            execute_audit(scanners=["s3"], target_env="AWS S3 Only")
        elif choice == "2":
            execute_audit(scanners=["iam"], target_env="AWS IAM Only")
        elif choice == "3":
            image_name = input("Enter Docker Image name to scan (e.g., nginx:1.19.6): ").strip()
            if image_name:
                execute_audit(scanners=["docker"], target_env="Local Container", image_name=image_name)
        elif choice == "4":
            execute_audit(scanners=["s3", "iam"], target_env="AWS Combined Audit")
        else:
            print("Invalid choice, try again.")

        input("\nPress Enter to return to the main menu...")


# ======================================================================
# TYPER APP / MAIN ENTRY POINT
# ======================================================================

app = typer.Typer(
    help="InternShield Cloud Security Command Center",
    add_completion=False,
    no_args_is_help=False,
)


def check_system_health():
    """Performs a background health check of the underlying tools."""
    import subprocess

    aws_ok = False
    try:
        res = subprocess.run(["aws", "sts", "get-caller-identity"], capture_output=True, timeout=5)
        aws_ok = res.returncode == 0
    except FileNotFoundError:
        pass

    docker_ok = False
    try:
        res = subprocess.run(["trivy", "--version"], capture_output=True, timeout=5)
        docker_ok = res.returncode == 0
    except FileNotFoundError:
        pass

    ai_status = None
    if settings.ai.default_provider.lower() != "disabled":
        provider = initialize_ai()
        if provider:
            ai_status = provider.name

    return aws_ok, docker_ok, ai_status


@app.command()
def interactive():
    """Launch the Interactive Command Center (Default)."""
    aws_ok, docker_ok, ai_status = check_system_health()
    print_status_dashboard(aws_ok, docker_ok, ai_status)
    try:
        interactive_menu()
    except KeyboardInterrupt:
        print("\n[+] Assessment aborted by user. Stay Secure!\n")
        sys.exit(0)


@app.command()
def s3():
    """Run an isolated AWS S3 Security Audit."""
    execute_audit(scanners=["s3"], target_env="AWS S3")


@app.command()
def iam():
    """Run an isolated AWS IAM Security Review."""
    execute_audit(scanners=["iam"], target_env="AWS IAM")


@app.command()
def docker(image: str = typer.Argument(..., help="Docker image name to scan (e.g., nginx:latest)")):
    """Run a local Docker Container Vulnerability Scan."""
    execute_audit(scanners=["docker"], target_env="Local Container", image_name=image)


@app.command()
def full_audit():
    """Run a combined security assessment across AWS S3 and IAM."""
    execute_audit(scanners=["s3", "iam"], target_env="AWS Combined Environment")


@app.command()
def doctor():
    """Diagnose the environment: checks Python deps, AWS, Docker/Trivy,
    and every configured AI provider — and asks the AI to explain any
    problem it finds. Run this first if anything seems broken."""
    _print("[bold]Running InternShield diagnostics...[/bold]\n")
    aws_ok, docker_ok, ai_status = check_system_health()
    print_status_dashboard(aws_ok, docker_ok, ai_status)

    problems = []
    if not aws_ok:
        problems.append("AWS CLI not found or not authenticated (`aws sts get-caller-identity` failed).")
    if not docker_ok:
        problems.append("Trivy not found or not on PATH (Docker scans will fail).")
    if not ai_status:
        problems.append("No AI provider is currently reachable (shellgpt/openai/anthropic all unavailable).")

    if not problems:
        _print("[green]Everything looks good. You're ready to run a full audit.[/green]")
        return

    for p in problems:
        _print(f"[yellow]! {p}[/yellow]")
        print_ai_error_help(p)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """InternShield CSCC - Defensive Posture Management."""
    if ctx.invoked_subcommand is None:
        interactive()


def run():
    """True entry point — wraps `app()` in a global error handler so
    ANY uncaught exception gets logged and explained by the AI layer
    instead of dumping a raw Python traceback on the user."""
    try:
        app()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("\n[+] Interrupted by user. Stay Secure!\n")
        sys.exit(130)
    except Exception as e:
        tb = traceback.format_exc()
        log.error(f"UNHANDLED EXCEPTION:\n{tb}")
        print("\n" + "=" * 60)
        print(" InternShield hit an unexpected error.")
        print("=" * 60)
        print_ai_error_help(f"{type(e).__name__}: {e}")
        print("Full traceback was written to logs/errors.log")
        sys.exit(1)


if __name__ == "__main__":
    run()
