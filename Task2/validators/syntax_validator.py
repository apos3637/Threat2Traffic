"""Syntax validator (V_Γ) using terraform validate."""

import asyncio
import tempfile
import shutil
import re
import time
from pathlib import Path
from typing import Optional

from Task2.models import (
    ValidationResult,
    ValidationIssue,
    ValidationTier,
    ValidationSeverity,
)


class SyntaxValidator:
    """Syntax validator using terraform validate.

    This implements the V_Γ tier of validation, checking that the
    generated HCL code is syntactically valid.
    """

    def __init__(self, terraform_path: str = "terraform"):
        self.terraform_path = terraform_path

    async def validate(
        self,
        hcl_code: str,
        timeout: float = 120.0,
    ) -> ValidationResult:
        """Validate Terraform HCL syntax.

        Args:
            hcl_code: The Terraform HCL code to validate
            timeout: Maximum time to wait for validation

        Returns:
            ValidationResult with any syntax errors
        """
        start_time = time.time()
        issues = []

        # Create temporary directory for Terraform files
        temp_dir = tempfile.mkdtemp(prefix="tf_validate_")

        try:
            # Write main.tf
            main_tf = Path(temp_dir) / "main.tf"
            main_tf.write_text(hcl_code)

            # Run terraform init (provider-only, no backend)
            init_result = await self._run_command(
                [self.terraform_path, "init", "-backend=false", "-input=false"],
                cwd=temp_dir,
                timeout=timeout,
            )

            if init_result["returncode"] != 0:
                # Parse init errors
                init_issues = self._parse_init_errors(init_result["stderr"])
                if init_issues:
                    issues.extend(init_issues)
                else:
                    issues.append(ValidationIssue(
                        tier=ValidationTier.SYNTAX,
                        severity=ValidationSeverity.ERROR,
                        message=f"terraform init failed: {init_result['stderr'][:500]}",
                    ))

            # Run terraform validate
            validate_result = await self._run_command(
                [self.terraform_path, "validate", "-json"],
                cwd=temp_dir,
                timeout=timeout / 2,
            )

            # Parse validate output
            validate_issues = self._parse_validate_output(
                validate_result["stdout"],
                validate_result["stderr"],
                validate_result["returncode"],
            )
            issues.extend(validate_issues)

        except asyncio.TimeoutError:
            issues.append(ValidationIssue(
                tier=ValidationTier.SYNTAX,
                severity=ValidationSeverity.ERROR,
                message=f"Validation timed out after {timeout}s",
            ))
        except Exception as e:
            issues.append(ValidationIssue(
                tier=ValidationTier.SYNTAX,
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
            tier=ValidationTier.SYNTAX,
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

    def _parse_init_errors(self, stderr: str) -> list[ValidationIssue]:
        """Parse terraform init error output."""
        issues = []

        # Common init error patterns
        patterns = [
            (r"Error: (.+)", ValidationSeverity.ERROR),
            (r"Warning: (.+)", ValidationSeverity.WARNING),
            (r"provider .+ not found", ValidationSeverity.ERROR),
        ]

        for pattern, severity in patterns:
            matches = re.finditer(pattern, stderr, re.IGNORECASE)
            for match in matches:
                issues.append(ValidationIssue(
                    tier=ValidationTier.SYNTAX,
                    severity=severity,
                    message=match.group(1) if match.lastindex else match.group(0),
                ))

        return issues

    def _parse_validate_output(
        self,
        stdout: str,
        stderr: str,
        returncode: int,
    ) -> list[ValidationIssue]:
        """Parse terraform validate -json output."""
        issues = []

        # Try to parse JSON output
        try:
            import json
            data = json.loads(stdout)

            if not data.get("valid", True):
                for diag in data.get("diagnostics", []):
                    severity = (
                        ValidationSeverity.ERROR
                        if diag.get("severity") == "error"
                        else ValidationSeverity.WARNING
                    )

                    # Extract location info
                    range_info = diag.get("range", {})
                    filename = range_info.get("filename")
                    start = range_info.get("start", {})
                    line = start.get("line")
                    column = start.get("column")

                    issues.append(ValidationIssue(
                        tier=ValidationTier.SYNTAX,
                        severity=severity,
                        message=diag.get("summary", "") + (
                            f": {diag.get('detail', '')}" if diag.get("detail") else ""
                        ),
                        file=filename,
                        line=line,
                        column=column,
                    ))

            return issues

        except (json.JSONDecodeError, KeyError):
            pass

        # Fall back to text parsing
        if returncode != 0:
            # Parse text errors
            error_pattern = r"Error: (.+?)(?:\n\n|\Z)"
            for match in re.finditer(error_pattern, stderr + stdout, re.DOTALL):
                issues.append(ValidationIssue(
                    tier=ValidationTier.SYNTAX,
                    severity=ValidationSeverity.ERROR,
                    message=match.group(1).strip()[:500],
                ))

            if not issues:
                issues.append(ValidationIssue(
                    tier=ValidationTier.SYNTAX,
                    severity=ValidationSeverity.ERROR,
                    message=f"terraform validate failed (exit code {returncode})",
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
