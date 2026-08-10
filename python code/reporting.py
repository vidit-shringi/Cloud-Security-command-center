"""
InternShield CSCC — Reporting
===============================
File 4 of 5.

Merges json_report.py + html_report.py + reporting/__init__.py into
one file. No templating engine dependency (no Jinja2) — the HTML is
built with plain string formatting to keep the tool lightweight.
"""

from __future__ import annotations

import os
import json
from pathlib import Path

from core_engine import AssessmentSummary, log


# ======================================================================
# JSON REPORT
# ======================================================================

def generate_json_report(summary: AssessmentSummary, output_dir: str) -> str:
    """Saves the assessment summary as a beautifully formatted JSON file."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"{summary.assessment_id.lower()}.json"
    filepath = os.path.join(output_dir, filename)

    try:
        json_data = summary.model_dump_json(indent=4)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(json_data)
        log.info(f"JSON Report successfully generated: [green]{filepath}[/green]")
        return filepath
    except Exception as e:
        log.error(f"Failed to write JSON report: {e}")
        return ""


# ======================================================================
# HTML REPORT
# ======================================================================

def generate_html_report(summary: AssessmentSummary, output_dir: str) -> str:
    """Generates a professional, standalone, dependency-free HTML dashboard."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"{summary.assessment_id.lower()}.html"
    filepath = os.path.join(output_dir, filename)

    findings_html = ""
    for f in summary.findings:
        badge_color = "#3b82f6"
        if f.severity.value == "CRITICAL":
            badge_color = "#ef4444"
        elif f.severity.value == "HIGH":
            badge_color = "#f97316"
        elif f.severity.value == "MEDIUM":
            badge_color = "#eab308"
        elif f.severity.value == "LOW":
            badge_color = "#22c55e"

        ai_section = ""
        if f.ai_analysis:
            ai_section = f"""
            <div style="margin-top: 15px; padding: 10px; background-color: #f0fdf4; border-left: 4px solid #22c55e; border-radius: 4px;">
                <h4 style="margin: 0 0 10px 0; color: #166534;">🤖 AI Analysis &amp; Remediation</h4>
                <pre style="white-space: pre-wrap; margin: 0; font-family: monospace; font-size: 13px; color: #14532d;">{f.ai_analysis}</pre>
            </div>
            """

        findings_html += f"""
        <div style="border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 20px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e5e7eb; padding-bottom: 10px; margin-bottom: 15px;">
                <h3 style="margin: 0; color: #111827;">{f.title}</h3>
                <span style="background-color: {badge_color}; color: white; padding: 4px 12px; border-radius: 9999px; font-weight: bold; font-size: 12px;">{f.severity.value}</span>
            </div>
            <p><strong>Finding ID:</strong> {f.finding_id} | <strong>Category:</strong> {f.category} | <strong>Source:</strong> {f.source_tool}</p>
            <p><strong>Target Resource:</strong> <code>{f.resource}</code></p>
            <h4 style="margin-bottom: 5px;">Impact</h4>
            <p style="margin-top: 0; color: #4b5563;">{f.impact}</p>
            <h4 style="margin-bottom: 5px;">Recommendation</h4>
            <p style="margin-top: 0; color: #4b5563;">{f.recommendation}</p>
            {ai_section}
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>InternShield Security Report - {summary.assessment_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #374151; line-height: 1.6; max-width: 1200px; margin: 0 auto; padding: 20px; background-color: #f9fafb; }}
        .header {{ background-color: #111827; color: #10b981; padding: 30px; border-radius: 8px; text-align: center; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; font-size: 2.5em; letter-spacing: -0.025em; }}
        .header p {{ color: #9ca3af; margin-top: 10px; font-size: 1.1em; }}
        .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .card h2 {{ margin: 0; font-size: 2em; }}
        .card p {{ margin: 5px 0 0 0; color: #6b7280; font-weight: bold; text-transform: uppercase; font-size: 0.85em; }}
        .c-crit {{ color: #ef4444; }} .c-high {{ color: #f97316; }} .c-med {{ color: #eab308; }} .c-low {{ color: #22c55e; }}
        .content-box {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    </style>
</head>
<body>
    <div class="header">
        <h1>INTERN SHIELD</h1>
        <p>Cloud Security Command Center - Executive Report</p>
    </div>

    <div class="summary-cards">
        <div class="card"><h2 class="c-crit">{summary.critical_count}</h2><p>Critical</p></div>
        <div class="card"><h2 class="c-high">{summary.high_count}</h2><p>High</p></div>
        <div class="card"><h2 class="c-med">{summary.medium_count}</h2><p>Medium</p></div>
        <div class="card"><h2 class="c-low">{summary.low_count}</h2><p>Low</p></div>
        <div class="card"><h2>{summary.total_findings}</h2><p>Total Findings</p></div>
    </div>

    <div class="content-box">
        <h2>Assessment Details</h2>
        <p><strong>Assessment ID:</strong> {summary.assessment_id}<br>
        <strong>Target Environment:</strong> {summary.target_environment}<br>
        <strong>Timestamp:</strong> {summary.start_time}<br>
        <strong>Tools Executed:</strong> {", ".join(summary.tools_used)}</p>

        <hr style="border: 0; border-top: 1px solid #e5e7eb; margin: 30px 0;">

        <h2>Detailed Findings</h2>
        {findings_html}
    </div>

    <div style="text-align: center; margin-top: 30px; color: #6b7280; font-size: 0.9em;">
        Generated by InternShield CSCC
    </div>
</body>
</html>
"""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        log.info(f"HTML Report successfully generated: [green]{filepath}[/green]")
        return filepath
    except Exception as e:
        log.error(f"Failed to write HTML report: {e}")
        return ""


# ======================================================================
# REPORT ENGINE (orchestrator)
# ======================================================================

class ReportEngine:
    @staticmethod
    def generate_all(summary: AssessmentSummary, output_dir: str) -> dict:
        """Generates all configured report formats."""
        json_path = generate_json_report(summary, output_dir)
        html_path = generate_html_report(summary, output_dir)
        return {"json": json_path, "html": html_path}
