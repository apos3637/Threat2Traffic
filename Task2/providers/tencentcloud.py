"""Tencent Cloud provider implementation with Data Source for dynamic image lookup."""

from typing import Optional, Tuple
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from Task1.spec_extractor.models import (
    EnvironmentSpecification,
    OSRequirement,
    HardwareProfile,
    NetworkConstraint,
    OSFamily,
    Architecture,
)
from Task2.models import ProviderCapabilities
from Task2.config import get_config
from .base_provider import IaCProvider


class TencentCloudProvider(IaCProvider):
    """Tencent Cloud provider implementation using Data Source for images."""

    provider_name = "tencentcloud"

    def __init__(self):
        self.config = get_config().tencentcloud
        self._instance_types = self._load_instance_types()
        # Image name patterns for data source queries
        self._image_patterns = {
            "windows": {
                "Windows Server 2022": "Windows Server 2022",
                "Windows Server 2019": "Windows Server 2019",
                "Windows Server 2016": "Windows Server 2016",
                "Windows 10": "Windows 10",
                "Windows 11": "Windows 11",
                "default": "Windows Server 2022",
            },
            "linux": {
                "Ubuntu 22.04": "Ubuntu Server 22.04",
                "Ubuntu 20.04": "Ubuntu Server 20.04",
                "Ubuntu 18.04": "Ubuntu Server 18.04",
                "CentOS 7": "CentOS 7",
                "CentOS 8": "CentOS 8",
                "Debian 11": "Debian 11",
                "Debian 10": "Debian 10",
                "default": "Ubuntu Server 22.04",
            },
        }

    def _load_instance_types(self) -> dict:
        """Load instance type mapping."""
        return {
            "small": "S5.MEDIUM4",    # 2 vCPU, 4GB RAM
            "medium": "S5.LARGE8",    # 4 vCPU, 8GB RAM
            "large": "S5.2XLARGE16",  # 8 vCPU, 16GB RAM
            "xlarge": "S5.4XLARGE32", # 16 vCPU, 32GB RAM
        }

    def get_capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            supported_os=["windows", "linux"],
            supported_architectures=["x64", "x86_64"],
            max_vcpu=128,
            max_memory_gb=512,
            supports_nested_virt=False,
            supports_gpu=True,
            supports_custom_images=True,
            supports_user_data=True,
            supported_regions=[
                "ap-guangzhou", "ap-shanghai", "ap-beijing",
                "ap-chengdu", "ap-hongkong", "ap-singapore",
            ],
        )

    def check_availability(self, spec: EnvironmentSpecification) -> bool:
        """Check if TencentCloud can satisfy the specification."""
        errors = self.validate_spec(spec)
        if errors:
            return False

        # With data source, we can handle any supported OS family
        os_family = spec.os_requirements.family.value.lower()
        return os_family in self._image_patterns

    def get_image_id(self, os_req: OSRequirement) -> Optional[str]:
        """Return a reference to the data source (not a hardcoded ID)."""
        # This now returns a Terraform reference to the data source
        return "data.tencentcloud_images.os_image.images[0].image_id"

    def get_image_filter(self, os_req: OSRequirement) -> Tuple[str, str]:
        """Get image filter pattern for data source query.

        Returns:
            Tuple of (os_name_pattern, image_type)
        """
        os_family = os_req.family.value.lower()

        if os_family not in self._image_patterns:
            # Fallback to Ubuntu
            return ("Ubuntu Server 22.04", "PUBLIC_IMAGE")

        family_patterns = self._image_patterns[os_family]

        # Try to find specific version match
        for version in os_req.specific_versions:
            for pattern_name, pattern in family_patterns.items():
                if version.lower() in pattern_name.lower():
                    return (pattern, "PUBLIC_IMAGE")

        # Try min_version match
        if os_req.min_version:
            for pattern_name, pattern in family_patterns.items():
                if os_req.min_version.lower() in pattern_name.lower():
                    return (pattern, "PUBLIC_IMAGE")

        # Return default for OS family
        return (family_patterns.get("default", "Ubuntu Server 22.04"), "PUBLIC_IMAGE")

    def get_instance_type(self, hardware: HardwareProfile) -> str:
        """Map hardware profile to TencentCloud instance type."""
        min_memory_gb = (hardware.min_memory_mb or 2048) / 1024

        if min_memory_gb <= 4:
            return self._instance_types["small"]
        elif min_memory_gb <= 8:
            return self._instance_types["medium"]
        elif min_memory_gb <= 16:
            return self._instance_types["large"]
        else:
            return self._instance_types["xlarge"]

    def generate_provider_block(self) -> str:
        """Generate TencentCloud provider block."""
        return f'''terraform {{
  required_providers {{
    tencentcloud = {{
      source  = "tencentcloudstack/tencentcloud"
      version = ">= 1.81.0"
    }}
  }}
}}

provider "tencentcloud" {{
  region = "{self.config.region}"
  # secret_id and secret_key should be set via environment variables:
  # TENCENTCLOUD_SECRET_ID and TENCENTCLOUD_SECRET_KEY
}}
'''

    def generate_data_sources(self, spec: EnvironmentSpecification) -> str:
        """Generate data source blocks for dynamic image and instance type lookup."""
        os_name, image_type = self.get_image_filter(spec.os_requirements)
        min_cpu, min_memory = self._get_min_resources(spec.hardware_profile)

        return f'''# Data Source: Query availability zones
data "tencentcloud_availability_zones_by_product" "zones" {{
  product = "cvm"
}}

# Data Source: Query latest OS image dynamically
data "tencentcloud_images" "os_image" {{
  image_type       = ["{image_type}"]
  image_name_regex = "^{os_name}.*64.*"
  os_name          = "{os_name}"

  # Filter for latest stable image
  filter {{
    name   = "image-state"
    values = ["NORMAL"]
  }}
}}

# Data Source: Query available instance types that meet requirements
data "tencentcloud_instance_types" "available" {{
  availability_zone = data.tencentcloud_availability_zones_by_product.zones.zones[0].name

  cpu_core_count   = {min_cpu}
  memory_size      = {min_memory}
  exclude_sold_out = true

  filter {{
    name   = "instance-charge-type"
    values = ["POSTPAID_BY_HOUR"]  # Pay-as-you-go
  }}
}}

# Local: Select the smallest instance type that meets requirements
locals {{
  # Sort by memory (ascending) and pick first available
  selected_instance_type = try(
    data.tencentcloud_instance_types.available.instance_types[0].instance_type,
    "{self._get_fallback_instance_type(spec.hardware_profile)}"  # Fallback
  )

  selected_zone = try(
    data.tencentcloud_availability_zones_by_product.zones.zones[0].name,
    "{self.config.region}-3"  # Fallback
  )
}}
'''

    def _get_min_resources(self, hardware: HardwareProfile) -> Tuple[int, int]:
        """Calculate minimum vCPU and memory from hardware profile.

        Returns:
            Tuple of (min_cpu, min_memory_gb)
        """
        min_memory_gb = (hardware.min_memory_mb or 2048) / 1024

        # Round up to nearest standard size
        if min_memory_gb <= 4:
            return (2, 4)
        elif min_memory_gb <= 8:
            return (4, 8)
        elif min_memory_gb <= 16:
            return (8, 16)
        else:
            return (16, 32)

    def _get_fallback_instance_type(self, hardware: HardwareProfile) -> str:
        """Get fallback instance type if data source fails."""
        min_memory_gb = (hardware.min_memory_mb or 2048) / 1024

        if min_memory_gb <= 4:
            return self._instance_types["small"]
        elif min_memory_gb <= 8:
            return self._instance_types["medium"]
        elif min_memory_gb <= 16:
            return self._instance_types["large"]
        else:
            return self._instance_types["xlarge"]

    def generate_network_resources(self, network: NetworkConstraint) -> str:
        """Generate TencentCloud network resources."""
        ingress_rules = []
        egress_rules = []

        # Default egress: allow all outbound
        egress_rules.append('''  egress {
    action      = "ACCEPT"
    cidr_block  = "0.0.0.0/0"
    protocol    = "ALL"
    port        = "ALL"
    description = "Allow all outbound traffic"
  }''')

        # Add ingress rules for specified ports
        if network.ports:
            for port in network.ports:
                ingress_rules.append(f'''  ingress {{
    action      = "ACCEPT"
    cidr_block  = "0.0.0.0/0"
    protocol    = "TCP"
    port        = "{port}"
    description = "Allow inbound TCP port {port}"
  }}''')

        # Always allow SSH/RDP for management
        ingress_rules.append('''  ingress {
    action      = "ACCEPT"
    cidr_block  = "0.0.0.0/0"
    protocol    = "TCP"
    port        = "22"
    description = "Allow SSH"
  }''')

        ingress_rules.append('''  ingress {
    action      = "ACCEPT"
    cidr_block  = "0.0.0.0/0"
    protocol    = "TCP"
    port        = "3389"
    description = "Allow RDP"
  }''')

        ingress_str = "\n\n".join(ingress_rules)
        egress_str = "\n\n".join(egress_rules)

        return f'''# VPC
resource "tencentcloud_vpc" "malware_analysis_vpc" {{
  name       = "malware-analysis-vpc"
  cidr_block = "10.0.0.0/16"
  tags = {{
    Purpose = "malware-analysis"
  }}
}}

# Subnet
resource "tencentcloud_subnet" "malware_analysis_subnet" {{
  name              = "malware-analysis-subnet"
  vpc_id            = tencentcloud_vpc.malware_analysis_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = local.selected_zone
  tags = {{
    Purpose = "malware-analysis"
  }}
}}

# Security Group
resource "tencentcloud_security_group" "malware_analysis_sg" {{
  name        = "malware-analysis-sg"
  description = "Security group for malware analysis environment"
}}

# Security Group Rules
resource "tencentcloud_security_group_lite_rule" "malware_analysis_rules" {{
  security_group_id = tencentcloud_security_group.malware_analysis_sg.id

{ingress_str}

{egress_str}
}}
'''

    def generate_instance_resource(
        self,
        spec: EnvironmentSpecification,
        user_data: str,
    ) -> str:
        """Generate TencentCloud CVM instance resource using data sources."""
        # Determine disk size
        disk_size = 50  # Default 50GB
        if spec.hardware_profile.min_disk_mb:
            disk_size = max(50, spec.hardware_profile.min_disk_mb // 1024)

        # Base64 encode user_data if provided
        user_data_block = ""
        if user_data:
            user_data_block = f'''
  user_data = base64encode(<<-EOF
{user_data}
EOF
  )'''

        # Use data source references for image_id and instance_type
        return f'''# CVM Instance - using dynamically queried image and instance type
resource "tencentcloud_instance" "malware_analysis_vm" {{
  instance_name     = "malware-analysis-vm"
  availability_zone = local.selected_zone

  # Dynamic lookups via data source
  image_id      = data.tencentcloud_images.os_image.images[0].image_id
  instance_type = local.selected_instance_type

  system_disk_type = "CLOUD_PREMIUM"
  system_disk_size = {disk_size}

  vpc_id                     = tencentcloud_vpc.malware_analysis_vpc.id
  subnet_id                  = tencentcloud_subnet.malware_analysis_subnet.id
  allocate_public_ip         = true
  internet_max_bandwidth_out = 10

  orderly_security_groups = [tencentcloud_security_group.malware_analysis_sg.id]
{user_data_block}

  tags = {{
    Purpose      = "malware-analysis"
    SampleHash   = "{spec.sample_hash[:16]}"
    ManagedBy    = "terraform"
    ImageSource  = "dynamic"
    InstanceType = "dynamic"
  }}

  # Lifecycle: ignore changes to avoid unnecessary recreation
  lifecycle {{
    ignore_changes = [image_id, instance_type]
  }}
}}
'''

    def generate_outputs(self) -> str:
        """Generate output blocks."""
        return '''# Outputs
output "instance_id" {
  description = "The ID of the CVM instance"
  value       = tencentcloud_instance.malware_analysis_vm.id
}

output "public_ip" {
  description = "The public IP address of the instance"
  value       = tencentcloud_instance.malware_analysis_vm.public_ip
}

output "private_ip" {
  description = "The private IP address of the instance"
  value       = tencentcloud_instance.malware_analysis_vm.private_ip
}

output "vpc_id" {
  description = "The ID of the VPC"
  value       = tencentcloud_vpc.malware_analysis_vpc.id
}

output "availability_zone" {
  description = "The availability zone used"
  value       = local.selected_zone
}

output "image_used" {
  description = "The image ID that was used (queried dynamically)"
  value       = data.tencentcloud_images.os_image.images[0].image_id
}

output "image_name" {
  description = "The name of the image used"
  value       = data.tencentcloud_images.os_image.images[0].image_name
}

output "instance_type_used" {
  description = "The instance type that was selected (queried dynamically)"
  value       = local.selected_instance_type
}

output "available_instance_types" {
  description = "All instance types that matched the requirements"
  value       = data.tencentcloud_instance_types.available.instance_types[*].instance_type
}
'''
