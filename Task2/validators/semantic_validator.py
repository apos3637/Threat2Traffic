"""Semantic validator (V_Φ) using terraform plan and custom rules."""

import asyncio
import tempfile
import shutil
import re
import json
import time
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from Task2.models import (
    ValidationResult,
    ValidationIssue,
    ValidationTier,
    ValidationSeverity,
)

if TYPE_CHECKING:
    from Task2.providers.base_provider import IaCProvider


class SemanticValidator:
    """Semantic validator using terraform plan and custom rules.

    This implements the V_Φ tier of validation, checking that the
    generated configuration is semantically valid and will work
    when applied.
    """

    def __init__(self, terraform_path: str = "terraform"):
        self.terraform_path = terraform_path

        # Known deprecated resource attributes by provider
        self._deprecated_attrs = {
            "tencentcloud": {
                "tencentcloud_instance": ["security_groups"],  # Use orderly_security_groups
            },
            "libvirt": {
                "libvirt_domain": ["cmdline"],  # Deprecated in newer versions
            },
            "aws": {
                "aws_instance": ["security_groups"],  # Use vpc_security_group_ids
            },
        }

    async def validate(
        self,
        hcl_code: str,
        provider: Optional["IaCProvider"] = None,
        timeout: float = 180.0,
    ) -> ValidationResult:
        """Validate Terraform configuration semantically.

        Args:
            hcl_code: The Terraform HCL code to validate
            provider: Optional provider for provider-specific checks
            timeout: Maximum time to wait for validation

        Returns:
            ValidationResult with any semantic issues
        """
        start_time = time.time()
        issues = []

        # First run custom static checks
        static_issues = self._run_static_checks(hcl_code, provider)
        issues.extend(static_issues)

        # Create temporary directory for Terraform files
        temp_dir = tempfile.mkdtemp(prefix="tf_plan_")

        try:
            # Write main.tf
            main_tf = Path(temp_dir) / "main.tf"
            main_tf.write_text(hcl_code)

            # Run terraform init
            init_result = await self._run_command(
                [self.terraform_path, "init", "-backend=false", "-input=false"],
                cwd=temp_dir,
                timeout=timeout / 3,
            )

            if init_result["returncode"] != 0:
                issues.append(ValidationIssue(
                    tier=ValidationTier.SEMANTIC,
                    severity=ValidationSeverity.ERROR,
                    message=f"terraform init failed: {init_result['stderr'][:500]}",
                ))
            else:
                # Run terraform plan (dry-run)
                plan_result = await self._run_command(
                    [self.terraform_path, "plan", "-input=false", "-no-color"],
                    cwd=temp_dir,
                    timeout=timeout * 2 / 3,
                )

                # Parse plan output
                plan_issues = self._parse_plan_output(
                    plan_result["stdout"],
                    plan_result["stderr"],
                    plan_result["returncode"],
                )
                issues.extend(plan_issues)

        except asyncio.TimeoutError:
            issues.append(ValidationIssue(
                tier=ValidationTier.SEMANTIC,
                severity=ValidationSeverity.ERROR,
                message=f"Validation timed out after {timeout}s",
            ))
        except Exception as e:
            issues.append(ValidationIssue(
                tier=ValidationTier.SEMANTIC,
                severity=ValidationSeverity.ERROR,
                message=f"Validation failed: {str(e)}",
            ))
        finally:
            # Clean up temp directory
            shutil.rmtree(temp_dir, ignore_errors=True)

        duration = time.time() - start_time
        has_errors = any(i.severity == ValidationSeverity.ERROR for i in issues)

        return ValidationResult(
            valid=not has_errors,
            tier=ValidationTier.SEMANTIC,
            issues=issues,
            duration_seconds=duration,
        )

    async def _run_command(
        self,
        cmd: list,
        cwd: str,
        timeout: float,
    ) -> dict:
        """Run a command asynchronously."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            return {
                "returncode": proc.returncode,
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
            }
        except asyncio.TimeoutError:
            proc.kill()
            raise

    def _run_static_checks(
        self,
        hcl_code: str,
        provider: Optional["IaCProvider"],
    ) -> list[ValidationIssue]:
        """Run static semantic checks on HCL code."""
        issues = []

        # Check for deprecated attributes
        if provider:
            provider_name = provider.provider_name
            deprecated = self._deprecated_attrs.get(provider_name, {})

            for resource_type, attrs in deprecated.items():
                for attr in attrs:
                    if f'"{attr}"' in hcl_code or f"{attr} " in hcl_code or f"{attr}=" in hcl_code:
                        issues.append(ValidationIssue(
                            tier=ValidationTier.SEMANTIC,
                            severity=ValidationSeverity.WARNING,
                            message=f"Deprecated attribute '{attr}' used in {resource_type}",
                            resource=resource_type,
                            suggestion=f"Consider updating to the non-deprecated alternative",
                        ))

        # Check for hardcoded secrets (basic pattern matching)
        secret_patterns = [
            (r'secret_key\s*=\s*"[^"]{20,}"', "Hardcoded secret_key detected"),
            (r'password\s*=\s*"[^"]+"', "Hardcoded password detected"),
            (r'api_key\s*=\s*"[^"]{10,}"', "Hardcoded api_key detected"),
        ]

        for pattern, message in secret_patterns:
            if re.search(pattern, hcl_code, re.IGNORECASE):
                issues.append(ValidationIssue(
                    tier=ValidationTier.SEMANTIC,
                    severity=ValidationSeverity.WARNING,
                    message=message,
                    suggestion="Use environment variables or a secrets manager",
                ))

        # Check for missing required blocks
        if "provider " not in hcl_code:
            issues.append(ValidationIssue(
                tier=ValidationTier.SEMANTIC,
                severity=ValidationSeverity.ERROR,
                message="No provider block found",
            ))

        # Check for resource references
        resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"'
        resources = re.findall(resource_pattern, hcl_code)
        resource_names = {f"{t}.{n}" for t, n in resources}

        # Check for dangling references
        ref_pattern = r'\b(\w+\.\w+)\.(\w+)\b'
        for match in re.finditer(ref_pattern, hcl_code):
            ref = match.group(1)
            if ref not in resource_names and not ref.startswith(("var.", "local.", "data.", "module.")):
                # Could be a valid reference to a resource defined elsewhere
                pass  # Skip for now to avoid false positives

        return issues

    def _parse_plan_output(
        self,
        stdout: str,
        stderr: str,
        returncode: int,
    ) -> list[ValidationIssue]:
        """Parse terraform plan output."""
        issues = []
        combined = stdout + stderr

        # Check for specific error patterns
        error_patterns = [
            (r"Error: (.+?)(?:\n\n|\Z)", ValidationSeverity.ERROR),
            (r"Warning: (.+?)(?:\n\n|\Z)", ValidationSeverity.WARNING),
            (r"InvalidImageId\.NotFound", ValidationSeverity.ERROR, "Image ID not found - check image_id value"),
            (r"InvalidInstanceType", ValidationSeverity.ERROR, "Invalid instance type - check instance_type value"),
            (r"InvalidVpcId", ValidationSeverity.ERROR, "Invalid VPC ID reference"),
            (r"InvalidSubnetId", ValidationSeverity.ERROR, "Invalid Subnet ID reference"),
            (r"InvalidSecurityGroupId", ValidationSeverity.ERROR, "Invalid Security Group ID reference"),
            (r"UnauthorizedAccess", ValidationSeverity.ERROR, "Insufficient permissions - check credentials"),
            (r"RequestLimitExceeded", ValidationSeverity.WARNING, "API rate limit exceeded"),
        ]

        for pattern_tuple in error_patterns:
            if len(pattern_tuple) == 2:
                pattern, severity = pattern_tuple
                message = None
            else:
                pattern, severity, message = pattern_tuple

            matches = re.finditer(pattern, combined, re.DOTALL | re.IGNORECASE)
            for match in matches:
                msg = message if message else match.group(1).strip()[:500] if match.lastindex else match.group(0)
                issues.append(ValidationIssue(
                    tier=ValidationTier.SEMANTIC,
                    severity=severity,
                    message=msg,
                ))

        # If plan failed but no specific errors found
        if returncode != 0 and not any(i.severity == ValidationSeverity.ERROR for i in issues):
            issues.append(ValidationIssue(
                tier=ValidationTier.SEMANTIC,
                severity=ValidationSeverity.ERROR,
                message=f"terraform plan failed (exit code {returncode})",
            ))

        return issues

    @staticmethod
    def is_available() -> bool:
        """Check if terraform is available on the system."""
        import subprocess
        try:
            result = subprocess.run(
                ["terraform", "version"],
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
