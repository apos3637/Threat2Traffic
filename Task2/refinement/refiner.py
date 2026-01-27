"""LLM-based code refiner for iterative error correction."""

from typing import Optional, List, TYPE_CHECKING
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from Task1.utils.llm_client import LLMClient
from Task2.config import get_config, LLMConfig
from .feedback_parser import FeedbackParser, ParsedFeedback

if TYPE_CHECKING:
    from Task2.schema.compiler import LocalSchema


# Legacy prompts (without schema context) - kept for backward compatibility
REFINEMENT_PROMPT = """You are an expert Terraform developer. Fix the following Terraform HCL code based on the validation errors.

CURRENT CODE:
```hcl
{current_code}
```

VALIDATION ERRORS:
{errors}

INSTRUCTIONS:
1. Fix ALL the errors listed above
2. Preserve the overall structure and intent of the code
3. Do not add new resources or features unless necessary to fix the errors
4. If an image ID is invalid, use a placeholder comment indicating it needs to be updated
5. Ensure all resource references are valid
6. Use proper HCL syntax

Output ONLY the corrected Terraform code, starting with terraform {{ or resource.
Do not include any explanations or markdown formatting."""


TARGETED_FIX_PROMPT = """You are an expert Terraform developer. Fix a specific error in this code.

CURRENT CODE:
```hcl
{current_code}
```

ERROR TO FIX:
Category: {error_category}
Message: {error_message}
{resource_info}
{suggestion}

Fix ONLY this specific error. Output the complete corrected code.
Do not include explanations or markdown formatting."""


# Schema-aware prompts
REFINEMENT_PROMPT_WITH_SCHEMA = """You are an expert Terraform developer. Fix the Terraform code using the schema constraints below.

{schema_context}

CURRENT CODE:
```hcl
{current_code}
```

VALIDATION ERRORS:
{errors}

INSTRUCTIONS:
1. Use ONLY valid values from the schema above
2. If image_id is invalid, select a valid one from the valid images list
3. If instance_type is invalid, select a valid one from the valid instance types list
4. Ensure all resource references are correct
5. Fix ALL errors while preserving the original intent

Output ONLY the corrected Terraform code.
Do not include explanations or markdown formatting."""


TARGETED_FIX_PROMPT_WITH_SCHEMA = """You are an expert Terraform developer. Fix a specific error using schema constraints.

{schema_context}

CURRENT CODE:
```hcl
{current_code}
```

ERROR TO FIX:
Category: {error_category}
Message: {error_message}
{resource_info}
{suggestion}

Use ONLY valid values from the schema above to fix this error.
Output the complete corrected code without explanations or markdown."""


class LLMRefiner:
    """LLM-based Terraform code refiner."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        if llm_client:
            self.llm_client = llm_client
        else:
            config = get_config()
            llm_config = LLMConfig(
                api_key=config.llm.api_key,
                base_url=config.llm.base_url,
                model=config.llm.model,
                temperature=0.2,  # Low temperature for precise fixes
            )
            from Task1.utils.llm_client import LLMClient
            self.llm_client = LLMClient(llm_config)

        self.feedback_parser = FeedbackParser()
        self._history: List[str] = []  # Track refinement history

    async def refine(
        self,
        current_code: str,
        feedback: str,
        local_schema: Optional["LocalSchema"] = None,
        max_code_length: int = 50000,
    ) -> str:
        """Refine Terraform code based on validation feedback.

        Args:
            current_code: The current Terraform HCL code
            feedback: Raw validation feedback string
            local_schema: Optional compiled schema constraints for context
            max_code_length: Maximum code length to process

        Returns:
            Refined Terraform code
        """
        # Parse feedback into structured format
        parsed = self.feedback_parser.parse(feedback)

        # Truncate code if too long
        if len(current_code) > max_code_length:
            current_code = current_code[:max_code_length] + "\n# ... truncated ..."

        # Store in history
        self._history.append(current_code)

        # Choose refinement strategy based on errors
        if len(parsed.errors) == 1:
            # Single error - use targeted fix
            return await self._targeted_fix(current_code, parsed.errors[0], local_schema)
        else:
            # Multiple errors - use general refinement
            return await self._general_refinement(current_code, parsed, local_schema)

    async def _general_refinement(
        self,
        current_code: str,
        parsed: ParsedFeedback,
        local_schema: Optional["LocalSchema"] = None,
    ) -> str:
        """Apply general refinement for multiple errors."""
        # Use schema-aware prompt if schema is available
        if local_schema:
            schema_context = local_schema.format_for_refinement()
            prompt = REFINEMENT_PROMPT_WITH_SCHEMA.format(
                schema_context=schema_context,
                current_code=current_code,
                errors=parsed.format_for_llm(),
            )
        else:
            prompt = REFINEMENT_PROMPT.format(
                current_code=current_code,
                errors=parsed.format_for_llm(),
            )

        messages = [{"role": "user", "content": prompt}]

        try:
            response = await self.llm_client.chat(messages, temperature=0.2)
            refined_code = response.content.strip()

            # Clean up any markdown formatting
            refined_code = self._clean_code(refined_code)

            # Validate the refinement didn't break things
            if self._is_valid_hcl(refined_code):
                return refined_code
            else:
                # Fall back to current code with minor fixes
                return self._apply_simple_fixes(current_code, parsed)

        except Exception as e:
            # On LLM failure, try simple fixes
            return self._apply_simple_fixes(current_code, parsed)

    async def _targeted_fix(
        self,
        current_code: str,
        error: "ParsedError",
        local_schema: Optional["LocalSchema"] = None,
    ) -> str:
        """Apply targeted fix for a single error."""
        resource_info = ""
        if error.resource_type:
            resource_info = f"Resource: {error.resource_type}"
            if error.resource_name:
                resource_info += f".{error.resource_name}"
        if error.attribute:
            resource_info += f"\nAttribute: {error.attribute}"

        suggestion = ""
        if error.suggestion:
            suggestion = f"Suggestion: {error.suggestion}"

        # Use schema-aware prompt if schema is available
        if local_schema:
            schema_context = local_schema.format_for_refinement()
            prompt = TARGETED_FIX_PROMPT_WITH_SCHEMA.format(
                schema_context=schema_context,
                current_code=current_code,
                error_category=error.category.value,
                error_message=error.message,
                resource_info=resource_info,
                suggestion=suggestion,
            )
        else:
            prompt = TARGETED_FIX_PROMPT.format(
                current_code=current_code,
                error_category=error.category.value,
                error_message=error.message,
                resource_info=resource_info,
                suggestion=suggestion,
            )

        messages = [{"role": "user", "content": prompt}]

        try:
            response = await self.llm_client.chat(messages, temperature=0.1)
            refined_code = response.content.strip()

            # Clean up
            refined_code = self._clean_code(refined_code)

            if self._is_valid_hcl(refined_code):
                return refined_code
            else:
                return current_code

        except Exception:
            return current_code

    def _clean_code(self, code: str) -> str:
        """Remove markdown formatting and clean up code."""
        # Remove code block markers
        if code.startswith("```"):
            lines = code.split("\n")
            lines = lines[1:]  # Remove first line
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            code = "\n".join(lines)

        # Remove any remaining backticks at start
        code = code.lstrip("`").rstrip("`")

        return code.strip()

    def _is_valid_hcl(self, code: str) -> bool:
        """Basic check if code looks like valid HCL."""
        if not code:
            return False

        # Check for basic HCL structure
        has_terraform = "terraform {" in code or "terraform{" in code
        has_resource = "resource " in code
        has_provider = "provider " in code

        # Must have at least provider or terraform block
        if not (has_terraform or has_provider):
            return False

        # Check balanced braces
        open_braces = code.count("{")
        close_braces = code.count("}")

        return open_braces == close_braces

    def _apply_simple_fixes(
        self,
        code: str,
        parsed: ParsedFeedback,
    ) -> str:
        """Apply simple regex-based fixes as fallback."""
        fixed = code

        for error in parsed.errors:
            # Handle deprecated security_groups -> orderly_security_groups
            if "security_groups" in error.message and "deprecated" in error.message.lower():
                fixed = fixed.replace("security_groups =", "orderly_security_groups =")

            # Handle missing quotes
            if "Invalid expression" in error.message:
                # Try to add missing quotes around string values
                pass  # Complex to do reliably

        return fixed

    def get_history(self) -> List[str]:
        """Get refinement history."""
        return self._history.copy()

    def clear_history(self) -> None:
        """Clear refinement history."""
        self._history.clear()

    async def close(self):
        """Close the LLM client."""
        if self.llm_client:
            await self.llm_client.close()
