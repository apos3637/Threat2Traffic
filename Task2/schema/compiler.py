"""Constraint Compiler for Invariant-Guided Synthesis.

Implements the paper's formula: Phi_plat^local = Union_{r in Resources(G)} Schema(r)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from Task1.spec_extractor.models import EnvironmentSpecification
from Task2.schema.registry import SchemaRegistry, ImageMapping, InstanceTypeMapping


@dataclass
class LocalSchema:
    """Compiled local schema - paper's Phi_plat^local.

    Contains all platform-specific constraints for a synthesis task,
    including valid values and attribute constraints.
    """
    provider: str
    required_resources: List[str]

    # Resource schemas (attribute requirements)
    resource_schemas: Dict[str, dict] = field(default_factory=dict)

    # Valid value lists for prompt generation
    valid_images: List[ImageMapping] = field(default_factory=list)
    valid_instance_types: List[InstanceTypeMapping] = field(default_factory=list)
    valid_regions: List[str] = field(default_factory=list)

    # Attribute constraints for validation
    attribute_constraints: Dict[str, dict] = field(default_factory=dict)

    def format_for_prompt(self) -> str:
        """Format schema as context for LLM generation prompt.

        Returns:
            Formatted string with valid values and constraints
        """
        lines = [
            "## Platform Schema Constraints",
            f"### Provider: {self.provider}",
            "",
        ]

        # Valid images section
        if self.valid_images:
            lines.append("### Valid Image Options:")
            for img in self.valid_images[:10]:  # Limit to 10 for prompt size
                lines.append(f"- {img.os_version}: `{img.image_id}` ({img.architecture})")
            if len(self.valid_images) > 10:
                lines.append(f"  ... and {len(self.valid_images) - 10} more")
            lines.append("")

        # Valid instance types section
        if self.valid_instance_types:
            lines.append("### Valid Instance Types:")
            for itype in self.valid_instance_types:
                lines.append(
                    f"- {itype.name}: `{itype.type_id}` ({itype.vcpu} vCPU, {itype.memory_gb}GB RAM)"
                )
            lines.append("")

        # Valid regions section
        if self.valid_regions:
            lines.append("### Valid Regions:")
            lines.append(f"- {', '.join(self.valid_regions[:5])}")
            if len(self.valid_regions) > 5:
                lines.append(f"  ... and {len(self.valid_regions) - 5} more")
            lines.append("")

        # Required resources
        if self.required_resources:
            lines.append("### Required Resources:")
            for res in self.required_resources:
                lines.append(f"- {res}")
            lines.append("")

        # Key attribute constraints
        if self.attribute_constraints:
            lines.append("### Attribute Constraints:")
            for resource, constraints in self.attribute_constraints.items():
                if constraints:
                    lines.append(f"**{resource}**:")
                    for attr, constraint in constraints.items():
                        if "valid_values" in constraint:
                            lines.append(f"  - {attr}: {constraint['valid_values']}")
                        elif "valid_prefixes" in constraint:
                            lines.append(f"  - {attr}: prefixes {constraint['valid_prefixes']}")
                        elif "pattern" in constraint:
                            lines.append(f"  - {attr}: pattern `{constraint['pattern']}`")
            lines.append("")

        return "\n".join(lines)

    def format_for_refinement(self) -> str:
        """Format schema as context for LLM refinement prompt.

        Returns:
            Focused context with valid values for fixing errors
        """
        lines = [
            "## Valid Values Reference",
            "",
        ]

        # Images - include all for refinement
        if self.valid_images:
            lines.append("### Valid Images (use these exact IDs):")
            for img in self.valid_images:
                lines.append(f"- `{img.image_id}` = {img.os_version} ({img.architecture})")
            lines.append("")

        # Instance types
        if self.valid_instance_types:
            lines.append("### Valid Instance Types (use these exact IDs):")
            for itype in self.valid_instance_types:
                lines.append(
                    f"- `{itype.type_id}` = {itype.vcpu} vCPU, {itype.memory_gb}GB RAM"
                )
            lines.append("")

        # Regions
        if self.valid_regions:
            lines.append("### Valid Regions:")
            lines.append(f"Valid: {', '.join(self.valid_regions)}")
            lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "provider": self.provider,
            "required_resources": self.required_resources,
            "resource_schemas": self.resource_schemas,
            "valid_images": [
                {
                    "os_version": img.os_version,
                    "image_id": img.image_id,
                    "architecture": img.architecture,
                }
                for img in self.valid_images
            ],
            "valid_instance_types": [
                {
                    "name": it.name,
                    "type_id": it.type_id,
                    "vcpu": it.vcpu,
                    "memory_gb": it.memory_gb,
                }
                for it in self.valid_instance_types
            ],
            "valid_regions": self.valid_regions,
            "attribute_constraints": self.attribute_constraints,
        }


class ConstraintCompiler:
    """Compiles platform constraints from registry for synthesis.

    Implements: Phi_plat^local = Union_{r in Resources(G)} Schema(r)
    """

    # Resource type mappings for inference
    RESOURCE_MAPPINGS = {
        "tencentcloud": {
            "compute_instance": "tencentcloud_instance",
            "vpc": "tencentcloud_vpc",
            "subnet": "tencentcloud_subnet",
            "security_group": "tencentcloud_security_group",
            "security_group_rule": "tencentcloud_security_group_rule",
        },
        "aws": {
            "compute_instance": "aws_instance",
            "vpc": "aws_vpc",
            "subnet": "aws_subnet",
            "security_group": "aws_security_group",
            "internet_gateway": "aws_internet_gateway",
        },
        "libvirt": {
            "compute_instance": "libvirt_domain",
            "volume": "libvirt_volume",
            "cloudinit": "libvirt_cloudinit_disk",
            "network": "libvirt_network",
        },
    }

    def __init__(self, registry: Optional[SchemaRegistry] = None):
        """Initialize compiler with schema registry.

        Args:
            registry: SchemaRegistry instance, creates new if None
        """
        self.registry = registry or SchemaRegistry()

    def infer_required_resources(
        self,
        spec: EnvironmentSpecification,
        provider_name: str,
    ) -> List[str]:
        """Infer required Terraform resources from specification.

        Args:
            spec: Environment specification from Stage I
            provider_name: Target provider name

        Returns:
            List of provider-specific resource type names
        """
        # Get provider-specific resource mappings
        mappings = self.RESOURCE_MAPPINGS.get(provider_name, {})

        # Always need compute instance
        resources = []
        if "compute_instance" in mappings:
            resources.append(mappings["compute_instance"])

        # Check network requirements
        if spec.network_constraints.requires_internet:
            if "vpc" in mappings:
                resources.append(mappings["vpc"])
            if "subnet" in mappings:
                resources.append(mappings["subnet"])
            if "security_group" in mappings:
                resources.append(mappings["security_group"])
            if "internet_gateway" in mappings:
                resources.append(mappings["internet_gateway"])

        # Check for security group rules (for port requirements)
        if spec.network_constraints.ports:
            if "security_group_rule" in mappings:
                resources.append(mappings["security_group_rule"])

        # Check storage requirements
        if spec.hardware_profile.min_disk_mb and spec.hardware_profile.min_disk_mb > 50000:
            if "volume" in mappings:
                resources.append(mappings["volume"])

        # Libvirt-specific: always need cloudinit for user_data
        if provider_name == "libvirt":
            if "cloudinit" in mappings:
                resources.append(mappings["cloudinit"])
            if "volume" in mappings and mappings["volume"] not in resources:
                resources.append(mappings["volume"])

        return resources

    def _filter_images_for_spec(
        self,
        images: List[ImageMapping],
        spec: EnvironmentSpecification,
    ) -> List[ImageMapping]:
        """Filter images based on OS requirements.

        Args:
            images: All available images
            spec: Environment specification

        Returns:
            Filtered list of compatible images
        """
        os_family = spec.os_requirements.family.value.lower()
        architecture = spec.os_requirements.architecture.value.lower()

        filtered = []
        for img in images:
            # Filter by OS family
            if os_family == "windows" and "windows" not in img.os_version.lower():
                continue
            if os_family == "linux" and "windows" in img.os_version.lower():
                continue

            # Filter by architecture if specified
            if architecture != "unknown":
                img_arch = img.architecture.lower()
                if architecture == "x64" and img_arch not in ["x86_64", "amd64", "x64"]:
                    continue
                if architecture == "arm64" and img_arch not in ["arm64", "aarch64"]:
                    continue

            filtered.append(img)

        # If no matches, return all images (better than nothing)
        return filtered if filtered else images

    def _filter_instance_types_for_spec(
        self,
        instance_types: List[InstanceTypeMapping],
        spec: EnvironmentSpecification,
    ) -> List[InstanceTypeMapping]:
        """Filter instance types based on hardware requirements.

        Args:
            instance_types: All available instance types
            spec: Environment specification

        Returns:
            Filtered list of compatible instance types
        """
        min_memory_gb = (spec.hardware_profile.min_memory_mb or 0) / 1024

        filtered = []
        for itype in instance_types:
            # Check memory requirement
            if itype.memory_gb >= min_memory_gb:
                filtered.append(itype)

        # Sort by memory (ascending) to prefer smaller instances
        filtered.sort(key=lambda x: (x.memory_gb, x.vcpu))

        # If no matches, return all instance types
        return filtered if filtered else instance_types

    def compile(
        self,
        spec: EnvironmentSpecification,
        provider_name: str,
    ) -> LocalSchema:
        """Compile constraints for synthesis.

        Implements: Phi_plat^local = Union_{r in Resources(G)} Schema(r)

        Args:
            spec: Environment specification from Stage I
            provider_name: Target provider name

        Returns:
            LocalSchema containing all relevant constraints
        """
        # Step 1: Infer required resources
        required_resources = self.infer_required_resources(spec, provider_name)

        # Step 2: Collect resource schemas
        resource_schemas = {}
        for resource_type in required_resources:
            schema = self.registry.get_resource_schema(provider_name, resource_type)
            if schema:
                resource_schemas[resource_type] = {
                    "required_attributes": schema.required_attributes,
                    "optional_attributes": schema.optional_attributes,
                    "constraints": schema.constraints,
                }

        # Step 3: Get valid images (filtered for spec)
        all_images = self.registry.list_images(provider_name)
        valid_images = self._filter_images_for_spec(all_images, spec)

        # Step 4: Get valid instance types (filtered for spec)
        all_instance_types = self.registry.list_instance_types(provider_name)
        valid_instance_types = self._filter_instance_types_for_spec(all_instance_types, spec)

        # Step 5: Get valid regions
        valid_regions = self.registry.list_regions(provider_name)

        # Step 6: Collect attribute constraints for required resources
        attribute_constraints = {}
        for resource_type in required_resources:
            constraints = self.registry.get_attribute_constraints(provider_name, resource_type)
            if constraints:
                attribute_constraints[resource_type] = constraints

        return LocalSchema(
            provider=provider_name,
            required_resources=required_resources,
            resource_schemas=resource_schemas,
            valid_images=valid_images,
            valid_instance_types=valid_instance_types,
            valid_regions=valid_regions,
            attribute_constraints=attribute_constraints,
        )
