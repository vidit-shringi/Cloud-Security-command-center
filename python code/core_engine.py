"""
InternShield CSCC — Core Engine
================================
File 1 of 5.

This single file merges what used to be five separate modules
(config, exceptions, logger, models, risk_engine, validators) so the
whole project can ship as a maximum of 5 Python files under
`python code/`, per the requested repo layout.

Contains:
    - Custom exception hierarchy
    - Pydantic data models (Finding, AssessmentSummary, Severity)
    - Structured logger (console + file, via `rich`)
    - Configuration manager (.env + config.yaml)
    - Deterministic Risk Engine

Every other file in `python code/` imports from this file, never the
other way around — this keeps the dependency graph a clean one-way
tree and avoids circular imports.
"""

from __future__ import annotations

import os
import re
import sys
import uuid
import logging
from pathlib import Path
from enum import Enum
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

try:
    import yaml
except ImportError:
    yaml = None

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

try:
    from pydantic import BaseModel, Field
except ImportError:
    print(
        "[FATAL] Missing dependency 'pydantic'. Run: pip install -r requirement.txt",
        file=sys.stderr,
    )
    raise

try:
    from rich.logging import RichHandler
except ImportError:
    RichHandler = None


# ======================================================================
# 1. EXCEPTIONS
# ======================================================================

class InternShieldBaseError(Exception):
    """Base exception for all InternShield errors."""
    pass


class ConfigurationError(InternShieldBaseError):
    """Raised when there is an issue with config.yaml or .env."""
    pass


class AWSAccessError(InternShieldBaseError):
    """Raised when AWS credentials or permissions are insufficient."""
    pass


class ToolMissingError(InternShieldBaseError):
    """Raised when an external CLI tool (like Trivy or AWS CLI) is missing."""
    pass


class AIProviderError(InternShieldBaseError):
    """Raised when an AI Provider fails to respond or authenticate."""
    pass


class AssessmentError(InternShieldBaseError):
    """Raised when a specific security module fails its execution."""
    pass


# ======================================================================
# 2. DATA MODELS
# ======================================================================

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    """Centralized model for all security findings."""
    finding_id: str = Field(..., description="Unique ID for the finding (e.g., S3-001)")
    title: str = Field(..., description="Short, descriptive title")
    category: str = Field(..., description="Security category (e.g., IAM, Storage, Container)")
    resource: str = Field(..., description="The affected resource ARN, ID, or Image Name")
    severity: Severity = Field(..., description="Deterministic severity level")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence score of the finding")
    evidence: str = Field(..., description="Raw output or configuration snippet proving the finding")
    impact: str = Field(..., description="Potential security impact if exploited")
    recommendation: str = Field(..., description="Actionable remediation steps")
    source_tool: str = Field(..., description="Tool that generated the finding (e.g., AWS API, Trivy)")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Optional field for AI's augmented analysis
    ai_analysis: Optional[str] = Field(None, description="AI-generated context or custom remediation")


class AssessmentSummary(BaseModel):
    """Summary of a completed security assessment."""
    assessment_id: str
    target_environment: str
    start_time: str
    end_time: str
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    findings: List[Finding] = []
    tools_used: List[str] = []


# ======================================================================
# 3. VALIDATORS
# ======================================================================

def validate_aws_region(region: str) -> bool:
    """Validates if a string matches standard AWS region formats."""
    pattern = r"^[a-z]{2}-[a-z]+-\d+$"
    return bool(re.match(pattern, region))


def validate_docker_image_name(image_name: str) -> bool:
    """Validates Docker image names to prevent shell injection."""
    pattern = r"^([a-zA-Z0-9_\-\./]+)(:[a-zA-Z0-9_\-\.]+)?$"
    if not re.match(pattern, image_name):
        raise InternShieldBaseError(f"Invalid Docker image format: {image_name}")
    return True


def validate_non_empty(value: str, field_name: str = "value") -> bool:
    """Generic guard against blank/whitespace-only user input."""
    if not value or not value.strip():
        raise InternShieldBaseError(f"{field_name} cannot be empty.")
    return True


# ======================================================================
# 4. CONFIGURATION MANAGER
# ======================================================================

if load_dotenv is not None:
    # Load environment variables from .env (API Keys, etc.) as early as possible.
    load_dotenv()


class AppConfig(BaseModel):
    name: str = "InternShield CSCC"
    version: str = "2.0"
    log_level: str = "INFO"


class AWSConfig(BaseModel):
    default_region: str = "us-east-1"
    max_retries: int = 3


class AIConfig(BaseModel):
    # Supported: shellgpt, openai, anthropic, auto, disabled
    # "auto" tries every configured provider in order until one works —
    # this is what makes the AI layer durable even on a free/limited tier.
    default_provider: str = "auto"
    require_human_confirmation: bool = True
    openai_model: str = "gpt-4o-mini"
    anthropic_model: str = "claude-3-5-haiku-20241022"
    max_findings_sent_to_ai: int = 15  # token-budget guard for free-tier keys


class ReportingConfig(BaseModel):
    output_dir: str = "reports"
    default_formats: List[str] = ["json", "html"]


class ConfigManager:
    """Loads settings from config.yaml + environment variables (.env)."""

    def __init__(self):
        self.app = AppConfig()
        self.aws = AWSConfig()
        self.ai = AIConfig()
        self.reporting = ReportingConfig()
        self._load_yaml()

    def _load_yaml(self):
        config_path = Path("config.yaml")
        if not config_path.exists():
            # Fallback to defaults if no config.yaml exists yet.
            return

        if yaml is None:
            raise ConfigurationError(
                "PyYAML is not installed but config.yaml was found. "
                "Run: pip install -r requirement.txt"
            )

        try:
            with open(config_path, "r") as f:
                data = yaml.safe_load(f) or {}

            if "app" in data:
                self.app = AppConfig(**data["app"])
            if "aws" in data:
                self.aws = AWSConfig(**data["aws"])
            if "ai" in data:
                self.ai = AIConfig(**data["ai"])
            if "reporting" in data:
                self.reporting = ReportingConfig(**data["reporting"])
        except Exception as e:
            raise ConfigurationError(f"Failed to parse config.yaml: {str(e)}")

    def get_ai_api_key(self, provider_name: str) -> str:
        """Securely fetch API keys from the environment (never hardcoded)."""
        key_map = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "claude": "ANTHROPIC_API_KEY",
            "gemini": "GEMINI_API_KEY",
        }
        env_var = key_map.get(provider_name.lower())
        if not env_var:
            return ""
        return os.getenv(env_var, "")

    def has_any_ai_key(self) -> bool:
        return bool(self.get_ai_api_key("openai") or self.get_ai_api_key("anthropic"))


# Global configuration instance — importable everywhere as `settings`.
settings = ConfigManager()


# ======================================================================
# 5. STRUCTURED LOGGER
# ======================================================================

def setup_logger(name: str) -> logging.Logger:
    """Configures and returns a secure, structured logger."""
    logger = logging.getLogger(name)

    if logger.hasHandlers():
        return logger

    log_level_str = settings.app.log_level.upper()
    log_level = getattr(logging, log_level_str, logging.INFO)
    logger.setLevel(log_level)

    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    # 1. Console handler — rich if available, plain otherwise (durability:
    #    the tool must still run in minimal environments / CI containers).
    if RichHandler is not None:
        console_handler = RichHandler(rich_tracebacks=True, markup=True)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
    else:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    console_handler.setLevel(log_level)

    # 2. File handler — full audit trail.
    file_handler = logging.FileHandler(log_dir / "application.log", encoding="utf-8")
    file_format = logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
    file_handler.setFormatter(file_format)
    file_handler.setLevel(logging.DEBUG)

    # 3. Dedicated error file — this is what execute.sh reads when it
    #    hands off a failure to the AI error-resolver.
    error_handler = logging.FileHandler(log_dir / "errors.log", encoding="utf-8")
    error_handler.setFormatter(file_format)
    error_handler.setLevel(logging.ERROR)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.addHandler(error_handler)
    logger.propagate = False

    return logger


# Global application logger — importable everywhere as `log`.
log = setup_logger("InternShield")


# ======================================================================
# 6. RISK ENGINE
# ======================================================================

class RiskEngine:
    """Calculates risk scores and aggregates findings deterministically.
    AI is layered on top of this later — it never overrides these
    severities, it only adds advisory context.
    """

    def __init__(self):
        self.findings: List[Finding] = []
        self._start_time = datetime.now(timezone.utc).isoformat()

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        log.debug(f"Finding recorded: {finding.finding_id} - [{finding.severity.value}] on {finding.resource}")

    def generate_summary(self, target_environment: str, tools_used: List[str]) -> AssessmentSummary:
        log.info("Calculating risk and generating assessment summary...")

        summary = AssessmentSummary(
            assessment_id=f"IS-AUDIT-{uuid.uuid4().hex[:8].upper()}",
            target_environment=target_environment,
            start_time=self._start_time,
            end_time=datetime.now(timezone.utc).isoformat(),
            tools_used=tools_used,
            findings=self.findings,
            total_findings=len(self.findings),
            critical_count=sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
            high_count=sum(1 for f in self.findings if f.severity == Severity.HIGH),
            medium_count=sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
            low_count=sum(1 for f in self.findings if f.severity == Severity.LOW),
            info_count=sum(1 for f in self.findings if f.severity == Severity.INFO),
        )
        return summary
