"""Schema-aware prompt templates for Terraform generation and refinement.

These templates incorporate platform schema constraints to guide LLM generation.
"""

# Template for schema context section
SCHEMA_CONTEXT_TEMPLATE = """
## Platform Schema Constraints

### Provider: {provider}

### Valid Image Options:
{valid_images}

### Valid Instance Types:
{valid_instance_types}

### Resource Attribute Constraints:
{attribute_constraints}

### Required Resources:
{required_resources}
"""


# Generation prompt with schema context
GENERATION_PROMPT_WITH_SCHEMA = """Generate Terraform HCL code for the following specification.

{schema_context}

## Environment Specification:
- OS: {os_family} {os_version}
- Architecture: {architecture}
- Min Memory: {min_memory}
- Min Disk: {min_disk}
- Dependencies: {dependencies}
- Network: {network_requirements}

## Instructions:
1. Use ONLY values from the valid options listed above
2. If an image_id is needed, select from the valid images list
3. If an instance_type is needed, select from the valid instance types list
4. Reference resources correctly using Terraform resource references
5. Follow HCL syntax strictly
6. Include all required attributes for each resource
7. Use the specified provider region

Output ONLY valid Terraform HCL code, starting with terraform {{ or provider block.
Do not include any explanations or markdown formatting.
"""


# Refinement prompt with schema context
REFINEMENT_PROMPT_WITH_SCHEMA = """Fix the Terraform code using the schema constraints below.

{schema_context}

## Current Code:
```hcl
{current_code}
```

## Validation Errors:
{errors}

## Fix Instructions:
1. Use ONLY valid values from the schema above
2. If image_id is invalid, select a valid one from valid_images
3. If instance_type is invalid, select a valid one from valid_instance_types
4. If availability_zone is invalid, use the provider's region
5. Ensure all resource references are correct
6. Fix ALL errors while preserving the original intent

Output ONLY the corrected Terraform code.
Do not include explanations or markdown formatting.
"""


# Targeted fix prompt with schema context
TARGETED_FIX_PROMPT_WITH_SCHEMA = """Fix a specific error in this Terraform code using the schema constraints.

{schema_context}

## Current Code:
```hcl
{current_code}
```

## Error to Fix:
Category: {error_category}
Message: {error_message}
{resource_info}
{suggestion}

Fix ONLY this specific error using valid values from the schema above.
Output the complete corrected code without explanations or markdown.
"""


def format_dependencies_for_prompt(dependencies: list) -> str:
    """Format software dependencies for prompt.

    Args:
        dependencies: List of SoftwareDependency objects

    Returns:
        Formatted string for prompt
    """
    if not dependencies:
        return "None specified"

    formatted = []
    for dep in dependencies[:5]:  # Limit to 5 for prompt size
        name = getattr(dep, 'name', str(dep))
        version = getattr(dep, 'version_constraint', None)
        if version:
            formatted.append(f"{name} ({version})")
        else:
            formatted.append(name)

    result = ", ".join(formatted)
    if len(dependencies) > 5:
        result += f" ... and {len(dependencies) - 5} more"
    return result


def format_network_for_prompt(network) -> str:
    """Format network constraints for prompt.

    Args:
        network: NetworkConstraint object

    Returns:
        Formatted string for prompt
    """
    parts = []

    if network.requires_internet:
        parts.append("Internet access required")
    else:
        parts.append("No internet required")

    if network.ports:
        parts.append(f"Ports: {network.ports[:5]}")

    if network.protocols:
        protos = [p.value if hasattr(p, 'value') else str(p) for p in network.protocols]
        parts.append(f"Protocols: {protos[:3]}")

    return "; ".join(parts) if parts else "Default network"


def build_generation_prompt(
    spec,
    schema_context: str,
) -> str:
    """Build complete generation prompt with schema context.

    Args:
        spec: EnvironmentSpecification
        schema_context: Pre-formatted schema context from LocalSchema

    Returns:
        Complete prompt string
    """
    os_family = spec.os_requirements.family.value if hasattr(spec.os_requirements.family, 'value') else str(spec.os_requirements.family)
    os_version = spec.os_requirements.min_version or "latest"
    architecture = spec.os_requirements.architecture.value if hasattr(spec.os_requirements.architecture, 'value') else str(spec.os_requirements.architecture)

    min_memory = f"{spec.hardware_profile.min_memory_mb}MB" if spec.hardware_profile.min_memory_mb else "Default"
    min_disk = f"{spec.hardware_profile.min_disk_mb}MB" if spec.hardware_profile.min_disk_mb else "Default"

    return GENERATION_PROMPT_WITH_SCHEMA.format(
        schema_context=schema_context,
        os_family=os_family,
        os_version=os_version,
        architecture=architecture,
        min_memory=min_memory,
        min_disk=min_disk,
        dependencies=format_dependencies_for_prompt(spec.software_dependencies),
        network_requirements=format_network_for_prompt(spec.network_constraints),
    )


def build_refinement_prompt(
    current_code: str,
    errors: str,
    schema_context: str,
) -> str:
    """Build refinement prompt with schema context.

    Args:
        current_code: Current Terraform HCL code
        errors: Formatted error messages
        schema_context: Pre-formatted schema context from LocalSchema

    Returns:
        Complete prompt string
    """
    return REFINEMENT_PROMPT_WITH_SCHEMA.format(
        schema_context=schema_context,
        current_code=current_code,
        errors=errors,
    )


def build_targeted_fix_prompt(
    current_code: str,
    error_category: str,
    error_message: str,
    schema_context: str,
    resource_info: str = "",
    suggestion: str = "",
) -> str:
    """Build targeted fix prompt with schema context.

    Args:
        current_code: Current Terraform HCL code
        error_category: Error category
        error_message: Error message
        schema_context: Pre-formatted schema context from LocalSchema
        resource_info: Optional resource context
        suggestion: Optional fix suggestion

    Returns:
        Complete prompt string
    """
    return TARGETED_FIX_PROMPT_WITH_SCHEMA.format(
        schema_context=schema_context,
        current_code=current_code,
        error_category=error_category,
        error_message=error_message,
        resource_info=resource_info,
        suggestion=suggestion,
    )
