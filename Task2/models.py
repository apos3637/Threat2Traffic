"""Data models for Stage II: Invariant-Guided Synthesis."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum
from datetime import datetime
from pathlib import Path
import json


class ValidationTier(str, Enum):
    """Validation tier identifier."""
    SYNTAX = "syntax"      # V_Γ: terraform validate
    SEMANTIC = "semantic"  # V_Φ: terraform plan + custom rules


class ValidationSeverity(str, Enum):
    """Severity level of validation issues."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class GeneratedScript:
    """Generated installation script with metadata."""
    content: str
    script_type: str  # "bash", "powershell", "batch"
    filename: str     # e.g., "user_data.ps1"
    description: Optional[str] = None

    @classmethod
    def bash(cls, content: str, description: str = "") -> "GeneratedScript":
        """Create a bash script."""
        return cls(content, "bash", "user_data.sh", description)

    @classmethod
    def powershell(cls, content: str, description: str = "") -> "GeneratedScript":
        """Create a PowerShell script."""
        return cls(content, "powershell", "user_data.ps1", description)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "script_type": self.script_type,
            "filename": self.filename,
            "description": self.description,
        }


@dataclass
class ValidationIssue:
    """A single validation issue."""
    tier: ValidationTier
    severity: ValidationSeverity
    message: str
    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    resource: Optional[str] = None
    suggestion: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tier": self.tier.value,
            "severity": self.severity.value,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "resource": self.resource,
            "suggestion": self.suggestion,
        }


@dataclass
class ValidationResult:
    """Result of a validation pass."""
    valid: bool
    tier: ValidationTier
    issues: List[ValidationIssue] = field(default_factory=list)
    raw_output: Optional[str] = None
    duration_seconds: float = 0.0

    @property
    def errors(self) -> List[ValidationIssue]:
        """Get only error-level issues."""
        return [i for i in self.issues if i.severity == ValidationSeverity.ERROR]

    @property
    def warnings(self) -> List[ValidationIssue]:
        """Get only warning-level issues."""
        return [i for i in self.issues if i.severity == ValidationSeverity.WARNING]

    @property
    def feedback(self) -> str:
        """Format issues as feedback string for refinement."""
        if not self.issues:
            return "No issues found."

        lines = []
        for issue in self.issues:
            location = ""
            if issue.file:
                location = f" at {issue.file}"
                if issue.line:
                    location += f":{issue.line}"

            lines.append(f"[{issue.severity.value.upper()}]{location}: {issue.message}")
            if issue.suggestion:
                lines.append(f"  Suggestion: {issue.suggestion}")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "tier": self.tier.value,
            "issues": [i.to_dict() for i in self.issues],
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class SynthesisResult:
    """Result of the synthesis process."""
    success: bool
    terraform_code: Optional[str] = None
    iterations: int = 0
    provider_used: str = ""
    validation_history: List[ValidationResult] = field(default_factory=list)
    error_message: Optional[str] = None
    user_data_script: Optional[GeneratedScript] = None
    created_at: datetime = field(default_factory=datetime.now)
    duration_seconds: float = 0.0

    @classmethod
    def failure(cls, message: str, **kwargs) -> "SynthesisResult":
        """Create a failure result."""
        return cls(success=False, error_message=message, **kwargs)

    @classmethod
    def from_success(
        cls,
        terraform_code: str,
        iterations: int,
        provider: str,
        validation_history: List[ValidationResult],
        user_data_script: Optional[GeneratedScript] = None,
        duration: float = 0.0,
    ) -> "SynthesisResult":
        """Create a success result."""
        return cls(
            success=True,
            terraform_code=terraform_code,
            iterations=iterations,
            provider_used=provider,
            validation_history=validation_history,
            user_data_script=user_data_script,
            duration_seconds=duration,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "terraform_code": self.terraform_code,
            "iterations": self.iterations,
            "provider_used": self.provider_used,
            "validation_history": [v.to_dict() for v in self.validation_history],
            "error_message": self.error_message,
            "user_data_script": self.user_data_script.to_dict() if self.user_data_script else None,
            "created_at": self.created_at.isoformat(),
            "duration_seconds": self.duration_seconds,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, output_dir: Path) -> None:
        """Save Terraform configuration and metadata to files."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save main.tf
        if self.terraform_code:
            main_tf = output_dir / "main.tf"
            main_tf.write_text(self.terraform_code)

        # Save user_data script if present
        if self.user_data_script:
            script_file = output_dir / self.user_data_script.filename
            script_file.write_text(self.user_data_script.content)

        # Save synthesis metadata
        metadata_file = output_dir / "synthesis_result.json"
        metadata_file.write_text(self.to_json())


@dataclass
class ProviderCapabilities:
    """Provider capability description."""
    supported_os: List[str]
    supported_architectures: List[str]
    max_vcpu: int
    max_memory_gb: int
    supports_nested_virt: bool
    supports_gpu: bool
    supports_custom_images: bool = False
    supports_user_data: bool = True
    supported_regions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "supported_os": self.supported_os,
            "supported_architectures": self.supported_architectures,
            "max_vcpu": self.max_vcpu,
            "max_memory_gb": self.max_memory_gb,
            "supports_nested_virt": self.supports_nested_virt,
            "supports_gpu": self.supports_gpu,
            "supports_custom_images": self.supports_custom_images,
            "supports_user_data": self.supports_user_data,
            "supported_regions": self.supported_regions,
        }
