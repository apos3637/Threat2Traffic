"""QEMU/KVM provider implementation (via libvirt Terraform provider)."""

from typing import Optional
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from Task1.spec_extractor.models import (
    EnvironmentSpecification,
    OSRequirement,
    HardwareProfile,
    NetworkConstraint,
    OSFamily,
)
from Task2.models import ProviderCapabilities
from Task2.config import get_config
from .base_provider import IaCProvider


class QemuProvider(IaCProvider):
    """QEMU/KVM provider implementation for local virtualization."""

    provider_name = "qemu"

    def __init__(self):
        self.config = get_config().qemu
        self._image_mapping = self._load_image_mapping()

    def _load_image_mapping(self) -> dict:
        """Load image mapping - uses cloud image URLs for libvirt."""
        return {
            "windows": {
                # Windows requires manual image preparation
                "Windows Server 2022": "/var/lib/libvirt/images/windows-server-2022.qcow2",
                "Windows Server 2019": "/var/lib/libvirt/images/windows-server-2019.qcow2",
                "Windows 10": "/var/lib/libvirt/images/windows-10.qcow2",
                "default": "/var/lib/libvirt/images/windows-server-2022.qcow2",
            },
            "linux": {
                # Cloud images can be downloaded automatically
                "Ubuntu 22.04": "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img",
                "Ubuntu 20.04": "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img",
                "CentOS 7": "https://cloud.centos.org/centos/7/images/CentOS-7-x86_64-GenericCloud.qcow2",
                "Debian 11": "https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-generic-amd64.qcow2",
                "default": "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img",
            },
        }

    def get_capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            supported_os=["windows", "linux"],
            supported_architectures=["x64", "x86_64", "x86"],
            max_vcpu=64,  # Depends on host
            max_memory_gb=256,  # Depends on host
            supports_nested_virt=True,
            supports_gpu=False,  # GPU passthrough requires special setup
            supports_custom_images=True,
            supports_user_data=True,  # Via cloud-init
            supported_regions=["local"],
        )

    def check_availability(self, spec: EnvironmentSpecification) -> bool:
        """Check if libvirt can satisfy the specification."""
        errors = self.validate_spec(spec)
        if errors:
            return False

        # Check if we have a matching image
        image_source = self.get_image_id(spec.os_requirements)
        return image_source is not None

    def get_image_id(self, os_req: OSRequirement) -> Optional[str]:
        """Map OS requirement to libvirt image source (URL or path)."""
        os_family = os_req.family.value.lower()

        if os_family not in self._image_mapping:
            return None

        family_images = self._image_mapping[os_family]

        # Try to find specific version match
        for version in os_req.specific_versions:
            for image_name, image_source in family_images.items():
                if version.lower() in image_name.lower():
                    return image_source

        # Try min_version match
        if os_req.min_version:
            for image_name, image_source in family_images.items():
                if os_req.min_version.lower() in image_name.lower():
                    return image_source

        # Return default for OS family
        return family_images.get("default")

    def get_instance_type(self, hardware: HardwareProfile) -> str:
        """Map hardware profile to libvirt resource spec.

        For libvirt, we return a string encoding vCPU and memory.
        """
        min_memory_mb = hardware.min_memory_mb or 2048
        vcpus = 2

        if min_memory_mb > 8192:
            vcpus = 4
        if min_memory_mb > 16384:
            vcpus = 8

        return f"{vcpus}vcpu_{min_memory_mb}mb"

    def generate_provider_block(self) -> str:
        """Generate libvirt provider block."""
        return f'''terraform {{
  required_providers {{
    libvirt = {{
      source  = "dmacvicar/libvirt"
      version = ">= 0.7.0"
    }}
  }}
}}

provider "libvirt" {{
  uri = "{self.config.uri}"
}}
'''

    def generate_network_resources(self, network: NetworkConstraint) -> str:
        """Generate libvirt network resources."""
        # For libvirt, we typically use NAT network for internet access
        # or isolated network for controlled environment

        network_mode = "nat"
        if not network.requires_internet:
            network_mode = "none"

        return f'''# Network
resource "libvirt_network" "malware_analysis_network" {{
  name      = "malware-analysis-net"
  mode      = "{network_mode}"
  domain    = "malware.local"
  addresses = ["10.10.10.0/24"]

  dhcp {{
    enabled = true
  }}

  dns {{
    enabled = true
  }}
}}
'''

    def generate_instance_resource(
        self,
        spec: EnvironmentSpecification,
        user_data: str,
    ) -> str:
        """Generate libvirt domain (VM) resource."""
        image_source = self.get_image_id(spec.os_requirements)

        # Parse instance type for resources
        instance_spec = self.get_instance_type(spec.hardware_profile)
        parts = instance_spec.split("_")
        vcpus = int(parts[0].replace("vcpu", ""))
        memory_mb = int(parts[1].replace("mb", ""))

        # Determine disk size
        disk_size_bytes = 50 * 1024 * 1024 * 1024  # 50GB default
        if spec.hardware_profile.min_disk_mb:
            disk_size_bytes = max(
                disk_size_bytes,
                spec.hardware_profile.min_disk_mb * 1024 * 1024
            )

        # Check if Windows (requires different setup)
        is_windows = spec.os_requirements.family == OSFamily.WINDOWS

        # Cloud-init for Linux
        cloudinit_block = ""
        if not is_windows and user_data:
            cloudinit_block = f'''
# Cloud-init for Linux
resource "libvirt_cloudinit_disk" "malware_analysis_cloudinit" {{
  name      = "malware-analysis-cloudinit.iso"
  pool      = "{self.config.storage_pool}"
  user_data = <<-EOF
#cloud-config
{user_data}
EOF
}}
'''

        cloudinit_ref = ""
        if not is_windows and user_data:
            cloudinit_ref = "  cloudinit = libvirt_cloudinit_disk.malware_analysis_cloudinit.id"

        # Determine if source is URL or local path
        if image_source.startswith("http"):
            volume_source = f'  source = "{image_source}"'
        else:
            volume_source = f'  source = "{image_source}"'

        return f'''# Base volume from cloud image
resource "libvirt_volume" "malware_analysis_base" {{
  name   = "malware-analysis-base.qcow2"
  pool   = "{self.config.storage_pool}"
{volume_source}
  format = "qcow2"
}}

# Main disk volume (clone of base)
resource "libvirt_volume" "malware_analysis_disk" {{
  name           = "malware-analysis-disk.qcow2"
  pool           = "{self.config.storage_pool}"
  base_volume_id = libvirt_volume.malware_analysis_base.id
  size           = {disk_size_bytes}
}}
{cloudinit_block}
# VM Domain
resource "libvirt_domain" "malware_analysis_vm" {{
  name   = "malware-analysis-vm"
  memory = {memory_mb}
  vcpu   = {vcpus}

  cpu {{
    mode = "host-passthrough"
  }}

  disk {{
    volume_id = libvirt_volume.malware_analysis_disk.id
  }}

  network_interface {{
    network_id     = libvirt_network.malware_analysis_network.id
    wait_for_lease = true
  }}

  console {{
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }}

  graphics {{
    type        = "spice"
    listen_type = "address"
    autoport    = true
  }}
{cloudinit_ref}

  # Malware analysis metadata
  metadata = <<-EOF
    <malware-analysis>
      <sample-hash>{spec.sample_hash}</sample-hash>
      <managed-by>terraform</managed-by>
    </malware-analysis>
  EOF
}}
'''

    def generate_outputs(self) -> str:
        """Generate output blocks."""
        return '''# Outputs
output "vm_id" {
  description = "The ID of the libvirt domain"
  value       = libvirt_domain.malware_analysis_vm.id
}

output "vm_name" {
  description = "The name of the VM"
  value       = libvirt_domain.malware_analysis_vm.name
}

output "network_addresses" {
  description = "The network addresses of the VM"
  value       = libvirt_domain.malware_analysis_vm.network_interface[*].addresses
}

output "volume_id" {
  description = "The ID of the main disk volume"
  value       = libvirt_volume.malware_analysis_disk.id
}
'''
