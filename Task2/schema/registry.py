"""Schema registry for managing provider image and instance type mappings."""

from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
import yaml


@dataclass
class ImageMapping:
    """Image mapping entry."""
    os_version: str
    image_id: str
    architecture: str = "x86_64"
    description: Optional[str] = None


@dataclass
class InstanceTypeMapping:
    """Instance type mapping entry."""
    name: str
    type_id: str
    vcpu: int
    memory_gb: int
    description: Optional[str] = None


@dataclass
class ResourceSchema:
    """Schema for a specific resource type."""
    resource_type: str
    required_attributes: List[str] = field(default_factory=list)
    optional_attributes: List[str] = field(default_factory=list)
    constraints: Dict[str, dict] = field(default_factory=dict)


@dataclass
class ProviderSchema:
    """Schema for a specific provider."""
    provider: str
    region: str
    last_updated: str
    images: Dict[str, List[ImageMapping]] = field(default_factory=dict)
    instance_types: Dict[str, InstanceTypeMapping] = field(default_factory=dict)
    resources: Dict[str, ResourceSchema] = field(default_factory=dict)
    supported_regions: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProviderSchema":
        """Create ProviderSchema from dictionary."""
        images = {}
        for os_family, image_list in data.get("images", {}).items():
            images[os_family] = [
                ImageMapping(
                    os_version=img.get("os_version", ""),
                    image_id=img.get("image_id", ""),
                    architecture=img.get("architecture", "x86_64"),
                    description=img.get("description"),
                )
                for img in image_list
            ]

        instance_types = {}
        for size, type_data in data.get("instance_types", {}).items():
            if isinstance(type_data, dict):
                instance_types[size] = InstanceTypeMapping(
                    name=size,
                    type_id=type_data.get("type", ""),
                    vcpu=type_data.get("vcpu", 2),
                    memory_gb=type_data.get("memory_gb", 4),
                    description=type_data.get("description"),
                )
            else:
                # Simple string format
                instance_types[size] = InstanceTypeMapping(
                    name=size,
                    type_id=str(type_data),
                    vcpu=2,
                    memory_gb=4,
                )

        # Parse resource schemas
        resources = {}
        for res_type, res_data in data.get("resources", {}).items():
            if isinstance(res_data, dict):
                resources[res_type] = ResourceSchema(
                    resource_type=res_type,
                    required_attributes=res_data.get("required_attributes", []),
                    optional_attributes=res_data.get("optional_attributes", []),
                    constraints=res_data.get("constraints", {}),
                )

        # Parse supported regions
        supported_regions = data.get("supported_regions", [data.get("region", "")])

        return cls(
            provider=data.get("provider", ""),
            region=data.get("region", ""),
            last_updated=data.get("last_updated", ""),
            images=images,
            instance_types=instance_types,
            resources=resources,
            supported_regions=supported_regions,
        )


class SchemaRegistry:
    """Central registry for provider schemas."""

    def __init__(self, mappings_dir: Optional[Path] = None):
        self.mappings_dir = mappings_dir or (Path(__file__).parent / "mappings")
        self._schemas: Dict[str, ProviderSchema] = {}
        self._load_schemas()

    def _load_schemas(self) -> None:
        """Load all schema files from mappings directory."""
        if not self.mappings_dir.exists():
            return

        for yaml_file in self.mappings_dir.glob("*.yaml"):
            try:
                with open(yaml_file, "r") as f:
                    data = yaml.safe_load(f)
                    if data and "provider" in data:
                        schema = ProviderSchema.from_dict(data)
                        self._schemas[schema.provider] = schema
            except Exception as e:
                print(f"Warning: Failed to load schema {yaml_file}: {e}")

    def get_schema(self, provider: str) -> Optional[ProviderSchema]:
        """Get schema for a provider."""
        return self._schemas.get(provider)

    def get_image_id(
        self,
        provider: str,
        os_family: str,
        os_version: Optional[str] = None,
    ) -> Optional[str]:
        """Get image ID for a provider and OS specification.

        Args:
            provider: Provider name (e.g., "tencentcloud")
            os_family: OS family (e.g., "windows", "linux")
            os_version: Specific OS version to match

        Returns:
            Image ID or None if not found
        """
        schema = self.get_schema(provider)
        if not schema:
            return None

        images = schema.images.get(os_family.lower(), [])
        if not images:
            return None

        # Try to find exact version match
        if os_version:
            for img in images:
                if os_version.lower() in img.os_version.lower():
                    return img.image_id

        # Return first available image for the OS family
        return images[0].image_id if images else None

    def get_instance_type(
        self,
        provider: str,
        size: str = "medium",
    ) -> Optional[str]:
        """Get instance type for a provider and size.

        Args:
            provider: Provider name
            size: Size category (small, medium, large, xlarge)

        Returns:
            Instance type ID or None if not found
        """
        schema = self.get_schema(provider)
        if not schema:
            return None

        type_mapping = schema.instance_types.get(size)
        return type_mapping.type_id if type_mapping else None

    def list_providers(self) -> List[str]:
        """List all registered providers."""
        return list(self._schemas.keys())

    def list_images(self, provider: str, os_family: Optional[str] = None) -> List[ImageMapping]:
        """List all images for a provider."""
        schema = self.get_schema(provider)
        if not schema:
            return []

        if os_family:
            return schema.images.get(os_family.lower(), [])

        all_images = []
        for images in schema.images.values():
            all_images.extend(images)
        return all_images

    def get_resource_schema(
        self,
        provider: str,
        resource_type: str,
    ) -> Optional[ResourceSchema]:
        """Get schema constraints for a specific resource type.

        Args:
            provider: Provider name (e.g., "tencentcloud")
            resource_type: Resource type (e.g., "tencentcloud_instance")

        Returns:
            ResourceSchema or None if not found
        """
        schema = self.get_schema(provider)
        if not schema:
            return None
        return schema.resources.get(resource_type)

    def get_attribute_constraints(
        self,
        provider: str,
        resource_type: str,
    ) -> Dict[str, dict]:
        """Get attribute constraints for a resource type.

        Args:
            provider: Provider name
            resource_type: Resource type

        Returns:
            Dictionary of attribute name -> constraint dict
        """
        resource_schema = self.get_resource_schema(provider, resource_type)
        if not resource_schema:
            return {}
        return resource_schema.constraints

    def get_valid_values(
        self,
        provider: str,
        field: str,
    ) -> List[Any]:
        """Get valid values for a field (images, instance_types, regions).

        Args:
            provider: Provider name
            field: Field name (e.g., "images", "instance_types", "regions")

        Returns:
            List of valid values
        """
        schema = self.get_schema(provider)
        if not schema:
            return []

        if field == "images":
            return self.list_images(provider)
        elif field == "instance_types":
            return list(schema.instance_types.values())
        elif field == "regions":
            return schema.supported_regions
        else:
            return []

    def list_available_resources(self, provider: str) -> List[str]:
        """List resource types supported by a provider.

        Args:
            provider: Provider name

        Returns:
            List of resource type names
        """
        schema = self.get_schema(provider)
        if not schema:
            return []
        return list(schema.resources.keys())

    def list_regions(self, provider: str) -> List[str]:
        """List regions supported by a provider.

        Args:
            provider: Provider name

        Returns:
            List of region names
        """
        schema = self.get_schema(provider)
        if not schema:
            return [schema.region] if schema else []
        return schema.supported_regions if schema.supported_regions else [schema.region]

    def list_instance_types(self, provider: str) -> List[InstanceTypeMapping]:
        """List all instance types for a provider.

        Args:
            provider: Provider name

        Returns:
            List of InstanceTypeMapping objects
        """
        schema = self.get_schema(provider)
        if not schema:
            return []
        return list(schema.instance_types.values())
