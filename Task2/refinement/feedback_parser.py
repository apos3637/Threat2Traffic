"""Parser for validation feedback to extract actionable error information."""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class ErrorCategory(str, Enum):
    """Categories of Terraform errors."""
    SYNTAX = "syntax"              # HCL syntax errors
    RESOURCE_REF = "resource_ref"  # Invalid resource references
    IMAGE_NOT_FOUND = "image"      # Image ID not found
    INSTANCE_TYPE = "instance"     # Invalid instance type
    NETWORK = "network"            # VPC/subnet/security group issues
    PERMISSION = "permission"      # Access/permission denied
    PROVIDER = "provider"          # Provider configuration issues
    ATTRIBUTE = "attribute"        # Invalid/deprecated attributes
    UNKNOWN = "unknown"


@dataclass
class ParsedError:
    """Parsed and categorized error."""
    category: ErrorCategory
    message: str
    resource_type: Optional[str] = None
    resource_name: Optional[str] = None
    attribute: Optional[str] = None
    line: Optional[int] = None
    suggestion: Optional[str] = None
    raw_text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "message": self.message,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "attribute": self.attribute,
            "line": self.line,
            "suggestion": self.suggestion,
        }


@dataclass
class ParsedFeedback:
    """Parsed validation feedback."""
    errors: List[ParsedError] = field(default_factory=list)
    warnings: List[ParsedError] = field(default_factory=list)
    summary: str = ""

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0

    @property
    def primary_error(self) -> Optional[ParsedError]:
        """Get the most important error to fix first."""
        if not self.errors:
            return None

        # Priority order for fixing
        priority = [
            ErrorCategory.SYNTAX,
            ErrorCategory.PROVIDER,
            ErrorCategory.RESOURCE_REF,
            ErrorCategory.ATTRIBUTE,
            ErrorCategory.IMAGE_NOT_FOUND,
            ErrorCategory.INSTANCE_TYPE,
            ErrorCategory.NETWORK,
            ErrorCategory.PERMISSION,
            ErrorCategory.UNKNOWN,
        ]

        for cat in priority:
            for err in self.errors:
                if err.category == cat:
                    return err

        return self.errors[0]

    def format_for_llm(self) -> str:
        """Format feedback for LLM refinement prompt."""
        lines = []

        if self.errors:
            lines.append("ERRORS TO FIX:")
            for i, err in enumerate(self.errors, 1):
                lines.append(f"{i}. [{err.category.value}] {err.message}")
                if err.resource_type:
                    lines.append(f"   Resource: {err.resource_type}")
                if err.resource_name:
                    lines.append(f"   Name: {err.resource_name}")
                if err.attribute:
                    lines.append(f"   Attribute: {err.attribute}")
                if err.line:
                    lines.append(f"   Line: {err.line}")
                if err.suggestion:
                    lines.append(f"   Suggestion: {err.suggestion}")

        if self.warnings:
            lines.append("\nWARNINGS:")
            for warn in self.warnings:
                lines.append(f"- {warn.message}")

        return "\n".join(lines)


class FeedbackParser:
    """Parse validation feedback into structured error information."""

    def __init__(self):
        # Patterns for categorizing errors
        self._patterns = [
            # Syntax errors
            (r"Invalid block definition|Argument or block definition required|Invalid expression",
             ErrorCategory.SYNTAX),
            (r"Invalid reference|Reference to undeclared",
             ErrorCategory.RESOURCE_REF),

            # Image errors
            (r"InvalidImageId|image.+not found|no matching image",
             ErrorCategory.IMAGE_NOT_FOUND),

            # Instance type errors
            (r"InvalidInstanceType|instance.+type.+invalid|unsupported instance",
             ErrorCategory.INSTANCE_TYPE),

            # Network errors
            (r"InvalidVpc|InvalidSubnet|InvalidSecurityGroup|network.+not found",
             ErrorCategory.NETWORK),

            # Permission errors
            (r"UnauthorizedAccess|Access.+Denied|insufficient.+permission|credentials",
             ErrorCategory.PERMISSION),

            # Provider errors
            (r"provider.+not found|failed to instantiate provider|provider configuration",
             ErrorCategory.PROVIDER),

            # Attribute errors
            (r"Invalid attribute|deprecated|unsupported argument|unknown attribute",
             ErrorCategory.ATTRIBUTE),
        ]

    def parse(self, feedback: str) -> ParsedFeedback:
        """Parse raw feedback string into structured format.

        Args:
            feedback: Raw feedback string from validation

        Returns:
            ParsedFeedback with categorized errors and warnings
        """
        result = ParsedFeedback()

        # Split into lines and process
        lines = feedback.split("\n")
        current_error = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Check for error/warning markers
            is_error = line.startswith("[ERROR]") or "Error:" in line
            is_warning = line.startswith("[WARNING]") or "Warning:" in line

            if is_error or is_warning:
                # Save previous error if exists
                if current_error:
                    if current_error.category == ErrorCategory.UNKNOWN:
                        result.warnings.append(current_error)
                    else:
                        result.errors.append(current_error)

                # Create new error
                message = re.sub(r"^\[ERROR\]|\[WARNING\]|Error:|Warning:", "", line).strip()
                category = self._categorize(message)

                current_error = ParsedError(
                    category=category,
                    message=message,
                    raw_text=line,
                )

                # Extract resource information
                self._extract_resource_info(message, current_error)

            elif current_error and line.startswith("Suggestion:"):
                current_error.suggestion = line.replace("Suggestion:", "").strip()

            elif current_error and "line" in line.lower():
                # Try to extract line number
                match = re.search(r"line\s*:?\s*(\d+)", line, re.IGNORECASE)
                if match:
                    current_error.line = int(match.group(1))

        # Don't forget last error
        if current_error:
            if current_error.category == ErrorCategory.UNKNOWN:
                result.warnings.append(current_error)
            else:
                result.errors.append(current_error)

        # Generate summary
        result.summary = self._generate_summary(result)

        return result

    def _categorize(self, message: str) -> ErrorCategory:
        """Categorize an error message."""
        message_lower = message.lower()

        for pattern, category in self._patterns:
            if re.search(pattern, message_lower, re.IGNORECASE):
                return category

        return ErrorCategory.UNKNOWN

    def _extract_resource_info(self, message: str, error: ParsedError) -> None:
        """Extract resource type and name from error message."""
        # Pattern: resource_type.resource_name
        match = re.search(r"(\w+)\.(\w+)", message)
        if match:
            error.resource_type = match.group(1)
            error.resource_name = match.group(2)

        # Pattern: "attribute_name"
        attr_match = re.search(r'"(\w+)"', message)
        if attr_match:
            error.attribute = attr_match.group(1)

    def _generate_summary(self, feedback: ParsedFeedback) -> str:
        """Generate a summary of the feedback."""
        if not feedback.has_errors:
            return "No errors found"

        categories = {}
        for err in feedback.errors:
            cat = err.category.value
            categories[cat] = categories.get(cat, 0) + 1

        parts = [f"{count} {cat}" for cat, count in categories.items()]
        return f"Found {len(feedback.errors)} errors: " + ", ".join(parts)
