"""Extract EnvironmentSpecification from Evidence Graph conclusions."""

from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass

from ..evidence_graph.models import (
    EvidenceNode,
    NodeType,
    ConstraintCategory,
)
from ..evidence_graph.graph import EvidenceGraph
from .models import (
    OSFamily,
    Architecture,
    NetworkProtocol,
    ThreatCategory,
    OSRequirement,
    SoftwareDependency,
    NetworkConstraint,
    NetworkEndpoint,
    HardwareProfile,
    MITREMapping,
    ThreatProfile,
    AttackChainStep,
    EnvironmentSpecification,
)
from ..utils.logger import get_logger

logger = get_logger("specification_extractor")


class SpecificationExtractor:
    """Extract structured EnvironmentSpecification from Evidence Graph.

    Processes conclusion nodes (accepted hypotheses from grounded extension)
    and serializes them into the output specification format.
    """

    def extract(
        self,
        graph: EvidenceGraph,
        sample_hash: str,
        deliberation_rounds: int = 0,
        conflicts_resolved: int = 0,
    ) -> EnvironmentSpecification:
        """Extract complete environment specification from graph.

        Args:
            graph: Evidence Graph with conclusions
            sample_hash: SHA256 hash of the analyzed sample
            deliberation_rounds: Number of deliberation rounds completed
            conflicts_resolved: Number of conflicts resolved

        Returns:
            Complete EnvironmentSpecification
        """
        conclusions = graph.get_conclusions()
        hypotheses = graph.get_hypotheses()

        logger.info(f"Extracting specification from {len(conclusions)} conclusions")

        # Extract by category
        os_req = self._extract_os_requirements(conclusions)
        software_deps = self._extract_software_dependencies(conclusions)
        network_constraints = self._extract_network_constraints(conclusions)
        hardware_profile = self._extract_hardware_profile(conclusions)

        # Calculate overall confidence for each component
        self._calculate_confidences(
            conclusions, os_req, software_deps, network_constraints, hardware_profile
        )

        spec = EnvironmentSpecification(
            sample_hash=sample_hash,
            os_requirements=os_req,
            software_dependencies=software_deps,
            network_constraints=network_constraints,
            hardware_profile=hardware_profile,
            grounded_extension_size=len(conclusions),
            deliberation_rounds=deliberation_rounds,
            total_hypotheses=len(hypotheses),
            conflicts_resolved=conflicts_resolved,
        )

        return spec

    def _extract_os_requirements(
        self,
        conclusions: List[EvidenceNode],
    ) -> OSRequirement:
        """Extract OS requirements from conclusions."""
        os_family = OSFamily.UNKNOWN
        architecture = Architecture.UNKNOWN
        min_version = None
        language = None
        required_features = []
        specific_versions = []

        for node in conclusions:
            content_lower = node.content.lower()

            # OS Family detection
            if node.category == ConstraintCategory.OS_VERSION:
                if "windows" in content_lower:
                    os_family = OSFamily.WINDOWS
                    # Extract specific version
                    for version in ["11", "10", "8.1", "8", "7", "server 2022", "server 2019", "server 2016"]:
                        if version in content_lower:
                            specific_versions.append(f"Windows {version}")
                elif "linux" in content_lower:
                    os_family = OSFamily.LINUX
                    for distro in ["ubuntu", "debian", "centos", "rhel", "fedora"]:
                        if distro in content_lower:
                            specific_versions.append(distro.capitalize())
                elif "macos" in content_lower or "mac os" in content_lower:
                    os_family = OSFamily.MACOS
                elif "android" in content_lower:
                    os_family = OSFamily.ANDROID

            # Architecture detection
            if node.category == ConstraintCategory.OS_ARCHITECTURE:
                if "x64" in content_lower or "64-bit" in content_lower or "amd64" in content_lower:
                    architecture = Architecture.X64
                elif "x86" in content_lower or "32-bit" in content_lower:
                    architecture = Architecture.X86
                elif "arm64" in content_lower or "aarch64" in content_lower:
                    architecture = Architecture.ARM64
                elif "arm" in content_lower:
                    architecture = Architecture.ARM

            # Language detection
            if node.category == ConstraintCategory.OS_LANGUAGE:
                if "english" in content_lower or "en-" in content_lower:
                    language = "en-US"
                elif "chinese" in content_lower or "zh-" in content_lower:
                    language = "zh-CN"
                elif "russian" in content_lower or "ru-" in content_lower:
                    language = "ru-RU"

            # Feature detection
            if "powershell" in content_lower:
                required_features.append("powershell")
            if "wmi" in content_lower:
                required_features.append("wmi")
            if "dotnet" in content_lower or ".net" in content_lower:
                required_features.append(".NET Framework")

        return OSRequirement(
            family=os_family,
            min_version=min_version,
            specific_versions=list(set(specific_versions)),
            architecture=architecture,
            language=language,
            required_features=list(set(required_features)),
        )

    def _extract_software_dependencies(
        self,
        conclusions: List[EvidenceNode],
    ) -> List[SoftwareDependency]:
        """Extract software dependencies from conclusions."""
        dependencies = []
        seen_names = set()

        for node in conclusions:
            if node.category not in (
                ConstraintCategory.SOFTWARE_DEPENDENCY,
                ConstraintCategory.RUNTIME_DEPENDENCY,
            ):
                continue

            content_lower = node.content.lower()

            # Common runtime dependencies
            runtime_patterns = [
                (".net", "runtime", ".NET Framework"),
                ("python", "runtime", "Python"),
                ("java", "runtime", "Java Runtime"),
                ("node", "runtime", "Node.js"),
                ("powershell", "runtime", "PowerShell"),
                ("visual c++", "runtime", "Visual C++ Runtime"),
                ("vcredist", "runtime", "Visual C++ Redistributable"),
            ]

            for pattern, dep_type, name in runtime_patterns:
                if pattern in content_lower and name not in seen_names:
                    seen_names.add(name)
                    dependencies.append(SoftwareDependency(
                        name=name,
                        type=dep_type,
                        purpose=node.content,
                        confidence=node.confidence,
                    ))

            # Generic extraction if no pattern matched
            if node.category == ConstraintCategory.SOFTWARE_DEPENDENCY:
                # Try to extract the dependency name from content
                dep_name = self._extract_name_from_content(node.content)
                if dep_name and dep_name not in seen_names:
                    seen_names.add(dep_name)
                    dependencies.append(SoftwareDependency(
                        name=dep_name,
                        type="software",
                        purpose=node.content,
                        confidence=node.confidence,
                    ))

        return dependencies

    def _extract_network_constraints(
        self,
        conclusions: List[EvidenceNode],
    ) -> NetworkConstraint:
        """Extract network constraints from conclusions."""
        constraint = NetworkConstraint()
        protocols = set()
        ports = set()
        domains = set()
        ips = set()
        endpoints = []

        for node in conclusions:
            content_lower = node.content.lower()

            if node.category == ConstraintCategory.NETWORK_PROTOCOL:
                if "http" in content_lower:
                    protocols.add(NetworkProtocol.HTTPS if "https" in content_lower else NetworkProtocol.HTTP)
                if "dns" in content_lower:
                    protocols.add(NetworkProtocol.DNS)
                if "smtp" in content_lower:
                    protocols.add(NetworkProtocol.SMTP)
                if "ftp" in content_lower:
                    protocols.add(NetworkProtocol.FTP)
                if "irc" in content_lower:
                    protocols.add(NetworkProtocol.IRC)
                if "tor" in content_lower:
                    protocols.add(NetworkProtocol.TOR)
                    constraint.uses_tor = True

            elif node.category == ConstraintCategory.NETWORK_PORT:
                # Extract port numbers
                import re
                port_matches = re.findall(r'\b(\d{1,5})\b', node.content)
                for port in port_matches:
                    port_num = int(port)
                    if 1 <= port_num <= 65535:
                        ports.add(port_num)

            elif node.category == ConstraintCategory.NETWORK_DOMAIN:
                # Extract domains
                import re
                domain_pattern = r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}'
                domain_matches = re.findall(domain_pattern, node.content)
                domains.update(domain_matches)

                for domain in domain_matches:
                    endpoints.append(NetworkEndpoint(
                        type="domain",
                        value=domain,
                        purpose="c2" if "c2" in content_lower or "command" in content_lower else None,
                    ))

            elif node.category == ConstraintCategory.NETWORK_IP:
                # Extract IP addresses
                import re
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                ip_matches = re.findall(ip_pattern, node.content)
                ips.update(ip_matches)

                for ip in ip_matches:
                    endpoints.append(NetworkEndpoint(
                        type="ip",
                        value=ip,
                        purpose="c2" if "c2" in content_lower or "command" in content_lower else None,
                    ))

        constraint.protocols = list(protocols)
        constraint.ports = sorted(ports)
        constraint.domains = list(domains)
        constraint.ip_addresses = list(ips)
        constraint.endpoints = endpoints
        constraint.requires_internet = len(domains) > 0 or len(ips) > 0

        return constraint

    def _extract_hardware_profile(
        self,
        conclusions: List[EvidenceNode],
    ) -> HardwareProfile:
        """Extract hardware profile from conclusions."""
        profile = HardwareProfile()

        for node in conclusions:
            content_lower = node.content.lower()

            if node.category == ConstraintCategory.HARDWARE_MEMORY:
                import re
                mem_match = re.search(r'(\d+)\s*(mb|gb)', content_lower)
                if mem_match:
                    amount = int(mem_match.group(1))
                    unit = mem_match.group(2)
                    profile.min_memory_mb = amount * 1024 if unit == "gb" else amount

            elif node.category == ConstraintCategory.HARDWARE_DISK:
                import re
                disk_match = re.search(r'(\d+)\s*(mb|gb)', content_lower)
                if disk_match:
                    amount = int(disk_match.group(1))
                    unit = disk_match.group(2)
                    profile.min_disk_mb = amount * 1024 if unit == "gb" else amount

            elif node.category == ConstraintCategory.ANTI_ANALYSIS:
                if "vm" in content_lower or "virtual" in content_lower:
                    profile.vm_detection = True
                if "sandbox" in content_lower:
                    profile.sandbox_detection = True

        return profile

    def _calculate_confidences(
        self,
        conclusions: List[EvidenceNode],
        os_req: OSRequirement,
        software_deps: List[SoftwareDependency],
        network: NetworkConstraint,
        hardware: HardwareProfile,
    ) -> None:
        """Calculate aggregate confidence scores for each component."""
        os_conclusions = [
            c for c in conclusions
            if c.category in (ConstraintCategory.OS_VERSION, ConstraintCategory.OS_ARCHITECTURE, ConstraintCategory.OS_LANGUAGE)
        ]
        if os_conclusions:
            os_req.confidence = sum(c.confidence for c in os_conclusions) / len(os_conclusions)

        network_conclusions = [
            c for c in conclusions
            if c.category in (
                ConstraintCategory.NETWORK_PROTOCOL,
                ConstraintCategory.NETWORK_PORT,
                ConstraintCategory.NETWORK_DOMAIN,
                ConstraintCategory.NETWORK_IP,
            )
        ]
        if network_conclusions:
            network.confidence = sum(c.confidence for c in network_conclusions) / len(network_conclusions)

        hardware_conclusions = [
            c for c in conclusions
            if c.category in (
                ConstraintCategory.HARDWARE_CPU,
                ConstraintCategory.HARDWARE_MEMORY,
                ConstraintCategory.HARDWARE_DISK,
                ConstraintCategory.ANTI_ANALYSIS,
            )
        ]
        if hardware_conclusions:
            hardware.confidence = sum(c.confidence for c in hardware_conclusions) / len(hardware_conclusions)

    def _extract_name_from_content(self, content: str) -> Optional[str]:
        """Try to extract a dependency name from content text."""
        # Simple heuristic: look for quoted strings or known patterns
        import re

        # Look for quoted names
        quoted = re.search(r'"([^"]+)"', content)
        if quoted:
            return quoted.group(1)

        quoted = re.search(r"'([^']+)'", content)
        if quoted:
            return quoted.group(1)

        # Look for "requires X" pattern
        requires = re.search(r'requires?\s+(\w+)', content, re.IGNORECASE)
        if requires:
            return requires.group(1)

        return None
