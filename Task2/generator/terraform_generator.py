"""Terraform HCL code generator."""

from typing import Optional, TYPE_CHECKING
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from Task1.spec_extractor.models import EnvironmentSpecification
from Task2.providers.base_provider import IaCProvider
from Task2.models import GeneratedScript
from Task2.schema.registry import SchemaRegistry
from Task2.schema.compiler import ConstraintCompiler, LocalSchema
from .script_generator import ScriptGenerator


class TerraformGenerator:
    """Generate Terraform HCL code from environment specifications."""

    def __init__(
        self,
        script_generator: Optional[ScriptGenerator] = None,
        constraint_compiler: Optional[ConstraintCompiler] = None,
    ):
        self.script_generator = script_generator
        self.constraint_compiler = constraint_compiler or ConstraintCompiler(SchemaRegistry())

    async def generate(
        self,
        spec: EnvironmentSpecification,
        provider: IaCProvider,
        local_schema: Optional[LocalSchema] = None,
    ) -> tuple[str, Optional[GeneratedScript], Optional[LocalSchema]]:
        """Generate complete Terraform configuration.

        Args:
            spec: Environment specification from Stage I
            provider: Provider implementation to use
            local_schema: Pre-compiled schema constraints (optional)

        Returns:
            Tuple of (terraform_code, GeneratedScript or None, LocalSchema or None)
        """
        # Compile schema constraints if not provided
        if local_schema is None:
            local_schema = self.constraint_compiler.compile(spec, provider.provider_name)

        # Generate user_data script if script generator is available
        user_data: Optional[GeneratedScript] = None
        if self.script_generator and spec.software_dependencies:
            user_data = await self.script_generator.generate_user_data(
                os_family=spec.os_requirements.family.value.lower(),
                dependencies=spec.software_dependencies,
            )

        # Collect all Terraform blocks
        blocks = []

        # 1. Provider block
        blocks.append(provider.generate_provider_block())

        # 2. Data sources (for dynamic image/instance lookup)
        data_sources = provider.generate_data_sources(spec)
        if data_sources:
            blocks.append(data_sources)

        # 3. Network resources
        blocks.append(provider.generate_network_resources(spec.network_constraints))

        # 4. Instance resource (pass content string to provider)
        user_data_content = user_data.content if user_data else ""
        blocks.append(provider.generate_instance_resource(spec, user_data_content))

        # 5. Outputs
        outputs = provider.generate_outputs()
        if outputs:
            blocks.append(outputs)

        # Combine all blocks with newlines
        terraform_code = "\n".join(blocks)

        return terraform_code, user_data, local_schema

    def generate_sync(
        self,
        spec: EnvironmentSpecification,
        provider: IaCProvider,
        user_data: str = "",
        local_schema: Optional[LocalSchema] = None,
    ) -> tuple[str, Optional[LocalSchema]]:
        """Synchronous version of generate for simple use cases.

        Args:
            spec: Environment specification
            provider: Provider implementation
            user_data: Pre-generated user_data script
            local_schema: Pre-compiled schema constraints (optional)

        Returns:
            Tuple of (Terraform HCL code, LocalSchema or None)
        """
        # Compile schema constraints if not provided
        if local_schema is None:
            local_schema = self.constraint_compiler.compile(spec, provider.provider_name)

        blocks = []

        # 1. Provider block
        blocks.append(provider.generate_provider_block())

        # 2. Data sources (for dynamic image/instance lookup)
        data_sources = provider.generate_data_sources(spec)
        if data_sources:
            blocks.append(data_sources)

        # 3. Network resources
        blocks.append(provider.generate_network_resources(spec.network_constraints))

        # 4. Instance resource
        blocks.append(provider.generate_instance_resource(spec, user_data))

        # 5. Outputs
        outputs = provider.generate_outputs()
        if outputs:
            blocks.append(outputs)

        return "\n".join(blocks), local_schema

    @staticmethod
    def format_hcl(code: str) -> str:
        """Basic HCL formatting (normalize whitespace).

        For production, consider using 'terraform fmt' via subprocess.
        """
        lines = code.split("\n")
        formatted_lines = []
        prev_empty = False

        for line in lines:
            is_empty = not line.strip()

            # Collapse multiple empty lines
            if is_empty and prev_empty:
                continue

            formatted_lines.append(line.rstrip())
            prev_empty = is_empty

        return "\n".join(formatted_lines)
