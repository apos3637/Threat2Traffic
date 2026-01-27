"""Abstract base class for IaC providers."""

from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING
import sys
from pathlib import Path

# Add parent directory to path for Task1 imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from Task1.spec_extractor.models import (
    EnvironmentSpecification,
    OSRequirement,
    HardwareProfile,
    NetworkConstraint,
)
from Task2.models import ProviderCapabilities


class IaCProvider(ABC):
    """Abstract Provider interface for Terraform generation."""

    provider_name: str = "base"

    @abstractmethod
    def get_capabilities(self) -> ProviderCapabilities:
        """Get provider capabilities."""
        pass

    @abstractmethod
    def check_availability(self, spec: EnvironmentSpecification) -> bool:
        """Check if this provider can satisfy the environment specification.

        Args:
            spec: The environment specification from Stage I

        Returns:
            True if the provider can satisfy all requirements
        """
        pass

    @abstractmethod
    def get_image_id(self, os_req: OSRequirement) -> Optional[str]:
        """Map OS requirement to provider-specific image ID.

        Args:
            os_req: OS requirement from specification

        Returns:
            Image ID string or None if no matching image found
        """
        pass

    @abstractmethod
    def get_instance_type(self, hardware: HardwareProfile) -> str:
        """Map hardware profile to provider-specific instance type.

        Args:
            hardware: Hardware requirements

        Returns:
            Instance type identifier
        """
        pass

    @abstractmethod
    def generate_provider_block(self) -> str:
        """Generate the Terraform provider configuration block.

        Returns:
            HCL string for the provider block
        """
        pass

    @abstractmethod
    def generate_network_resources(self, network: NetworkConstraint) -> str:
        """Generate network resources (VPC, subnet, security group).

        Args:
            network: Network constraints from specification

        Returns:
            HCL string for network resources
        """
        pass

    @abstractmethod
    def generate_instance_resource(
        self,
        spec: EnvironmentSpecification,
        user_data: str,
    ) -> str:
        """Generate compute instance resource.

        Args:
            spec: Full environment specification
            user_data: Cloud-init or user_data script content

        Returns:
            HCL string for the instance resource
        """
        pass

    def generate_data_sources(self, spec: EnvironmentSpecification) -> str:
        """Generate data source blocks for dynamic resource lookup.

        Override this method to add data sources for dynamic image/instance lookup.

        Args:
            spec: Environment specification

        Returns:
            HCL string for data source blocks (empty by default)
        """
        return ""

    def generate_outputs(self) -> str:
        """Generate Terraform output blocks.

        Returns:
            HCL string for outputs
        """
        return ""

    def validate_spec(self, spec: EnvironmentSpecification) -> list[str]:
        """Validate specification against provider capabilities.

        Args:
            spec: Environment specification

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        caps = self.get_capabilities()

        # Check OS support
        os_family = spec.os_requirements.family.value.lower()
        if os_family not in [os.lower() for os in caps.supported_os]:
            errors.append(f"OS family '{os_family}' not supported by {self.provider_name}")

        # Check architecture support
        arch = spec.os_requirements.architecture.value.lower()
        if arch != "unknown" and arch not in [a.lower() for a in caps.supported_architectures]:
            errors.append(f"Architecture '{arch}' not supported by {self.provider_name}")

        # Check GPU requirement
        if spec.hardware_profile.requires_gpu and not caps.supports_gpu:
            errors.append(f"GPU not supported by {self.provider_name}")

        # Check memory limits
        if spec.hardware_profile.min_memory_mb:
            min_memory_gb = spec.hardware_profile.min_memory_mb / 1024
            if min_memory_gb > caps.max_memory_gb:
                errors.append(
                    f"Memory requirement ({min_memory_gb}GB) exceeds {self.provider_name} max ({caps.max_memory_gb}GB)"
                )

        return errors
