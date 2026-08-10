"""
InternShield CSCC — Scanners
=============================
File 2 of 5.

Merges the three security scanners (AWS S3, AWS IAM, Docker/Trivy) into
one file. Every scanner is strictly READ-ONLY: nothing here ever
mutates cloud resources or containers, it only lists/describes/reads.

Classes:
    S3Scanner       — public exposure, ACLs, bucket policy, encryption
    IAMScanner      — MFA, stale keys, privilege-escalation vectors
    DockerScanner   — CVEs, misconfig, secrets via Trivy
"""

from __future__ import annotations

import json
import uuid
import subprocess
from datetime import datetime, timezone
from typing import List

from core_engine import (
    Finding,
    Severity,
    log,
    ToolMissingError,
    AWSAccessError,
    validate_docker_image_name,
)

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    boto3 = None
    ClientError = Exception
    NoCredentialsError = Exception


# ======================================================================
# AWS S3 SCANNER
# ======================================================================

class S3Scanner:
    """Audits S3 buckets for public exposure, missing encryption, and
    missing public access blocks. Strictly Read-Only."""

    def __init__(self, region_name: str = "us-east-1"):
        if boto3 is None:
            raise ToolMissingError("boto3 is not installed. Run: pip install -r requirement.txt")
        self.region_name = region_name
        self.findings: List[Finding] = []
        try:
            self.s3_client = boto3.client("s3", region_name=self.region_name)
        except NoCredentialsError:
            raise AWSAccessError(
                "AWS credentials not found. Please configure ~/.aws/credentials or environment variables."
            )

    def run_scan(self) -> List[Finding]:
        log.info("Starting AWS S3 Security Assessment...")
        try:
            response = self.s3_client.list_buckets()
            buckets = response.get("Buckets", [])
        except ClientError as e:
            log.error(f"Failed to list S3 buckets. Ensure identity has 's3:ListAllMyBuckets' permission. Error: {e}")
            return self.findings

        if not buckets:
            log.info("No S3 buckets found in this account.")
            return self.findings

        for bucket in buckets:
            bucket_name = bucket["Name"]
            log.info(f"Auditing S3 Bucket: [cyan]{bucket_name}[/cyan]")
            self._check_public_access_block(bucket_name)
            self._check_acls(bucket_name)
            self._check_bucket_policy(bucket_name)
            self._check_encryption(bucket_name)

        log.info(f"S3 Assessment complete. Generated {len(self.findings)} findings.")
        return self.findings

    def _generate_finding_id(self) -> str:
        return f"S3-{uuid.uuid4().hex[:6].upper()}"

    def _check_public_access_block(self, bucket_name: str):
        try:
            bpa = self.s3_client.get_public_access_block(Bucket=bucket_name)
            config = bpa.get("PublicAccessBlockConfiguration", {})
            if not all([
                config.get("BlockPublicAcls"), config.get("IgnorePublicAcls"),
                config.get("BlockPublicPolicy"), config.get("RestrictPublicBuckets"),
            ]):
                self.findings.append(Finding(
                    finding_id=self._generate_finding_id(),
                    title="S3 Block Public Access (BPA) Not Fully Enabled",
                    category="Storage Security",
                    resource=f"arn:aws:s3:::{bucket_name}",
                    severity=Severity.HIGH,
                    evidence=json.dumps(config),
                    impact="Bucket may be accidentally exposed to the public via ACLs or Bucket Policies.",
                    recommendation="Enable all 4 settings of S3 Block Public Access at the bucket or account level.",
                    source_tool="AWS_API_S3",
                ))
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoSuchPublicAccessBlockConfiguration":
                self.findings.append(Finding(
                    finding_id=self._generate_finding_id(),
                    title="S3 Block Public Access (BPA) Missing",
                    category="Storage Security",
                    resource=f"arn:aws:s3:::{bucket_name}",
                    severity=Severity.HIGH,
                    evidence="NoSuchPublicAccessBlockConfiguration",
                    impact="Bucket has no BPA configuration, making it highly vulnerable to accidental public exposure.",
                    recommendation="Enable S3 Block Public Access for this bucket.",
                    source_tool="AWS_API_S3",
                ))
            elif error_code == "AccessDenied":
                log.debug(f"Access Denied getting BPA for {bucket_name}")
            else:
                log.warning(f"Unexpected error getting BPA for {bucket_name}: {e}")

    def _check_acls(self, bucket_name: str):
        try:
            acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                uri = grant.get("Grantee", {}).get("URI", "")
                if "http://acs.amazonaws.com/groups/global/AllUsers" in uri:
                    self.findings.append(Finding(
                        finding_id=self._generate_finding_id(),
                        title="S3 Bucket Publicly Accessible via ACL",
                        category="Storage Security",
                        resource=f"arn:aws:s3:::{bucket_name}",
                        severity=Severity.CRITICAL,
                        evidence=json.dumps(grant),
                        impact="Anyone on the internet can access or modify objects in this bucket based on the granted permission.",
                        recommendation="Remove the 'AllUsers' grant from the Bucket ACL and rely on IAM or Bucket Policies.",
                        source_tool="AWS_API_S3",
                    ))
                elif "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" in uri:
                    self.findings.append(Finding(
                        finding_id=self._generate_finding_id(),
                        title="S3 Bucket Accessible to Any AWS User via ACL",
                        category="Storage Security",
                        resource=f"arn:aws:s3:::{bucket_name}",
                        severity=Severity.HIGH,
                        evidence=json.dumps(grant),
                        impact="Any authenticated AWS user (even outside your organization) can access this bucket.",
                        recommendation="Remove the 'AuthenticatedUsers' grant from the Bucket ACL.",
                        source_tool="AWS_API_S3",
                    ))
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                log.warning(f"Error reading ACL for {bucket_name}: {e}")

    def _check_bucket_policy(self, bucket_name: str):
        try:
            policy_response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_response.get("Policy", "{}"))
            statements = policy.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for statement in statements:
                effect = statement.get("Effect")
                principal = statement.get("Principal", {})
                if effect == "Allow" and (principal == "*" or principal.get("AWS") == "*"):
                    if not statement.get("Condition", {}):
                        self.findings.append(Finding(
                            finding_id=self._generate_finding_id(),
                            title="S3 Bucket Policy Allows Unrestricted Public Access",
                            category="Storage Security",
                            resource=f"arn:aws:s3:::{bucket_name}",
                            severity=Severity.CRITICAL,
                            evidence=json.dumps(statement),
                            impact="The bucket policy explicitly grants permissions to the entire internet without conditions.",
                            recommendation="Restrict the 'Principal' to specific AWS IAM ARNs, or add strong 'Condition' keys (like IP restrictions or specific VPC endpoints).",
                            source_tool="AWS_API_S3",
                        ))
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code != "NoSuchBucketPolicy" and error_code != "AccessDenied":
                log.warning(f"Error reading Bucket Policy for {bucket_name}: {e}")

    def _check_encryption(self, bucket_name: str):
        try:
            self.s3_client.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                self.findings.append(Finding(
                    finding_id=self._generate_finding_id(),
                    title="S3 Bucket Missing Default Server-Side Encryption",
                    category="Storage Security",
                    resource=f"arn:aws:s3:::{bucket_name}",
                    severity=Severity.MEDIUM,
                    evidence="ServerSideEncryptionConfigurationNotFoundError",
                    impact="Data at rest is not encrypted automatically, which may violate compliance standards (e.g., PCI-DSS, HIPAA).",
                    recommendation="Enable default Server-Side Encryption (SSE-S3 or SSE-KMS) on the bucket.",
                    source_tool="AWS_API_S3",
                ))
            elif error_code != "AccessDenied":
                log.warning(f"Error reading Encryption Config for {bucket_name}: {e}")


# ======================================================================
# AWS IAM SCANNER
# ======================================================================

class IAMScanner:
    """Audits IAM Users, Policies, MFA status, and Access Keys.
    Detects Privilege Escalation vectors. Strictly Read-Only."""

    def __init__(self, region_name: str = "us-east-1"):
        if boto3 is None:
            raise ToolMissingError("boto3 is not installed. Run: pip install -r requirement.txt")
        self.region_name = region_name
        self.findings: List[Finding] = []
        try:
            self.iam_client = boto3.client("iam", region_name=self.region_name)
        except NoCredentialsError:
            raise AWSAccessError(
                "AWS credentials not found. Please configure ~/.aws/credentials or environment variables."
            )

    def run_scan(self) -> List[Finding]:
        log.info("Starting AWS IAM Security Assessment...")
        try:
            paginator = self.iam_client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    arn = user["Arn"]
                    log.info(f"Auditing IAM User: [cyan]{username}[/cyan]")
                    self._check_mfa_and_keys(username, arn)
                    self._check_attached_policies(username, arn)
                    self._check_inline_policies(username, arn)
        except ClientError as e:
            log.error(f"Failed to list IAM users. Ensure identity has 'iam:ListUsers' permission. Error: {e}")
            return self.findings

        log.info(f"IAM Assessment complete. Generated {len(self.findings)} findings.")
        return self.findings

    def _generate_finding_id(self) -> str:
        return f"IAM-{uuid.uuid4().hex[:6].upper()}"

    def _check_mfa_and_keys(self, username: str, arn: str):
        try:
            has_console_access = False
            try:
                self.iam_client.get_login_profile(UserName=username)
                has_console_access = True
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchEntity":
                    pass

            if has_console_access:
                mfa = self.iam_client.list_mfa_devices(UserName=username)
                if not mfa.get("MFADevices"):
                    self.findings.append(Finding(
                        finding_id=self._generate_finding_id(),
                        title="IAM User with Console Access Lacks MFA",
                        category="Identity & Access Management",
                        resource=arn,
                        severity=Severity.HIGH,
                        evidence="MFADevices array is empty.",
                        impact="User credentials can be easily compromised via phishing or credential stuffing.",
                        recommendation="Enforce Multi-Factor Authentication (MFA) for this user.",
                        source_tool="AWS_API_IAM",
                    ))

            keys = self.iam_client.list_access_keys(UserName=username)
            for key in keys.get("AccessKeyMetadata", []):
                create_date = key.get("CreateDate")
                status = key.get("Status")
                if create_date and status == "Active":
                    days_old = (datetime.now(timezone.utc) - create_date).days
                    if days_old > 90:
                        self.findings.append(Finding(
                            finding_id=self._generate_finding_id(),
                            title="Stale IAM Access Key (> 90 Days)",
                            category="Identity & Access Management",
                            resource=f"{arn}/key/{key.get('AccessKeyId')}",
                            severity=Severity.MEDIUM,
                            evidence=f"Access Key {key.get('AccessKeyId')} is {days_old} days old.",
                            impact="Long-lived access keys heavily increase the likelihood of credential leakage.",
                            recommendation="Rotate this access key immediately and delete the old key.",
                            source_tool="AWS_API_IAM",
                        ))
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                log.warning(f"Error reading MFA/Keys for {username}: {e}")

    def _check_attached_policies(self, username: str, arn: str):
        try:
            attached = self.iam_client.list_attached_user_policies(UserName=username)
            for policy in attached.get("AttachedPolicies", []):
                policy_name = policy.get("PolicyName")
                if policy_name in ["AdministratorAccess", "IAMFullAccess"]:
                    self.findings.append(Finding(
                        finding_id=self._generate_finding_id(),
                        title=f"Excessive Privileges: '{policy_name}' Attached Directly to User",
                        category="Identity & Access Management",
                        resource=arn,
                        severity=Severity.CRITICAL,
                        evidence=json.dumps(policy),
                        impact="User has unrestricted access to the AWS environment. If compromised, the entire account is at risk.",
                        recommendation="Remove this policy and implement Least Privilege. Assign granular permissions via IAM Roles.",
                        source_tool="AWS_API_IAM",
                    ))
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                log.warning(f"Error reading attached policies for {username}: {e}")

    def _check_inline_policies(self, username: str, arn: str):
        try:
            inlines = self.iam_client.list_user_policies(UserName=username)
            for policy_name in inlines.get("PolicyNames", []):
                policy_doc_resp = self.iam_client.get_user_policy(UserName=username, PolicyName=policy_name)
                doc = policy_doc_resp.get("PolicyDocument", {})
                doc_str = json.dumps(doc).replace(" ", "")

                dangerous_actions = [
                    "iam:AttachUserPolicy",
                    "iam:PutUserPolicy",
                    "iam:CreateAccessKey",
                    "iam:UpdateLoginProfile",
                    "iam:PassRole",
                    "*:*",
                ]
                found_risks = [action for action in dangerous_actions if action in doc_str]

                if found_risks:
                    self.findings.append(Finding(
                        finding_id=self._generate_finding_id(),
                        title=f"Privilege Escalation Risk in Inline Policy: {policy_name}",
                        category="Identity & Access Management",
                        resource=f"{arn}/inline-policy/{policy_name}",
                        severity=Severity.HIGH,
                        evidence=f"Dangerous actions found: {found_risks}. Document snippet: {json.dumps(doc)[:200]}...",
                        impact="User can potentially escalate their own privileges, create backdoor access, or assume higher-privileged roles.",
                        recommendation=f"Review the inline policy '{policy_name}' and strictly limit IAM modification permissions.",
                        source_tool="AWS_API_IAM",
                    ))
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                log.warning(f"Error reading inline policies for {username}: {e}")


# ======================================================================
# DOCKER / TRIVY SCANNER
# ======================================================================

class DockerScanner:
    """Uses Trivy to scan images for Vulnerabilities (CVEs),
    Misconfigurations, and Secrets. Strictly Read-Only, secure subprocess
    calls only (never shell=True)."""

    def __init__(self):
        self.findings: List[Finding] = []
        self._verify_trivy()

    def _verify_trivy(self):
        try:
            subprocess.run(["trivy", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise ToolMissingError(
                "Trivy is not installed or not in PATH. Please install Trivy to scan Docker images: "
                "https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
            )

    def _generate_finding_id(self) -> str:
        return f"DOC-{uuid.uuid4().hex[:6].upper()}"

    def _map_severity(self, trivy_sev: str) -> Severity:
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "UNKNOWN": Severity.INFO,
        }
        return mapping.get(trivy_sev.upper(), Severity.INFO)

    def run_scan(self, image_name: str) -> List[Finding]:
        log.info(f"Starting Docker Security Scan for image: [cyan]{image_name}[/cyan]")
        validate_docker_image_name(image_name)

        cmd = [
            "trivy", "image",
            "--format", "json",
            "--no-progress",
            "--scanners", "vuln,secret,misconfig",
            image_name,
        ]

        try:
            log.debug(f"Executing subprocess: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode != 0 and not result.stdout.strip():
                log.error(f"Trivy execution failed for {image_name}. Error: {result.stderr}")
                return self.findings

            data = json.loads(result.stdout)
            self._parse_trivy_results(image_name, data.get("Results", []))

        except subprocess.TimeoutExpired:
            log.error(f"Trivy scan timed out for {image_name} after 5 minutes.")
        except json.JSONDecodeError:
            log.error(f"Failed to parse Trivy JSON output for {image_name}. Output may be malformed.")
        except Exception as e:
            log.error(f"An unexpected error occurred during Docker scan: {str(e)}")

        log.info(f"Docker Assessment complete. Generated {len(self.findings)} findings.")
        return self.findings

    def _parse_trivy_results(self, image_name: str, results: list):
        for result in results:
            target = result.get("Target", image_name)

            for vuln in result.get("Vulnerabilities", []):
                title = f"{vuln.get('VulnerabilityID')} in {vuln.get('PkgName')}"
                impact = vuln.get("Title") or vuln.get("Description", "No description available.")
                self.findings.append(Finding(
                    finding_id=self._generate_finding_id(),
                    title=title[:100],
                    category="Container Vulnerability",
                    resource=f"{image_name} -> {target}",
                    severity=self._map_severity(vuln.get("Severity", "UNKNOWN")),
                    evidence=f"Installed: {vuln.get('InstalledVersion')} | Fixed: {vuln.get('FixedVersion', 'N/A')}",
                    impact=impact[:250] + "..." if len(impact) > 250 else impact,
                    recommendation=f"Upgrade package '{vuln.get('PkgName')}' to version {vuln.get('FixedVersion', 'latest')}.",
                    source_tool="Trivy",
                ))

            for misconf in result.get("Misconfigurations", []):
                self.findings.append(Finding(
                    finding_id=self._generate_finding_id(),
                    title=misconf.get("Title", "Container Misconfiguration"),
                    category="Container Misconfiguration",
                    resource=f"{image_name} -> {target}",
                    severity=self._map_severity(misconf.get("Severity", "UNKNOWN")),
                    evidence=misconf.get("Message", "N/A"),
                    impact=misconf.get("Description", "N/A")[:250],
                    recommendation=misconf.get("Resolution", "Review Dockerfile or Container configuration."),
                    source_tool="Trivy",
                ))

            for secret in result.get("Secrets", []):
                rule_id = secret.get("RuleID", "Exposed Secret")
                self.findings.append(Finding(
                    finding_id=self._generate_finding_id(),
                    title=f"Hardcoded Secret Detected: {secret.get('Title', rule_id)}",
                    category="Container Secret",
                    resource=f"{image_name} -> {target}",
                    severity=self._map_severity(secret.get("Severity", "CRITICAL")),
                    evidence=f"Category: {secret.get('Category')} | Match found at line {secret.get('StartLine', 'unknown')}",
                    impact="Hardcoded secrets in Docker images can lead to lateral movement and full infrastructure compromise.",
                    recommendation="Remove the secret from the image build history. Rotate the compromised credential immediately. Use a secrets manager.",
                    source_tool="Trivy",
                ))
