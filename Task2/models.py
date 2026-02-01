"""Data models for Stage II tools: Constraint Acquisition and Validation."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


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
        """Format issues as feedback string."""
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
