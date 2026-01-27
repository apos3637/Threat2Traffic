"""Output data models for Environment Specification."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum
from datetime import datetime
import json


class OSFamily(str, Enum):
    """Operating system family."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"


class Architecture(str, Enum):
    """CPU architecture."""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


class NetworkProtocol(str, Enum):
    """Network protocol types."""
    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"
    UDP = "udp"
    DNS = "dns"
    SMTP = "smtp"
    FTP = "ftp"
    IRC = "irc"
    TOR = "tor"
    CUSTOM = "custom"


class ThreatCategory(str, Enum):
    """Malware threat categories."""
    RANSOMWARE = "ransomware"
    TROJAN = "trojan"
    BACKDOOR = "backdoor"
    WORM = "worm"
    DROPPER = "dropper"
    DOWNLOADER = "downloader"
    SPYWARE = "spyware"
    ADWARE = "adware"
    ROOTKIT = "rootkit"
    BOTNET = "botnet"
    RAT = "rat"
    CRYPTOMINER = "cryptominer"
    INFOSTEALER = "infostealer"
    KEYLOGGER = "keylogger"
    UNKNOWN = "unknown"


@dataclass
class OSRequirement:
    """Operating system requirements."""
    family: OSFamily
    min_version: Optional[str] = None
    max_version: Optional[str] = None
    specific_versions: List[str] = field(default_factory=list)
    architecture: Architecture = Architecture.UNKNOWN
    language: Optional[str] = None  # e.g., "en-US", "zh-CN"
    required_features: List[str] = field(default_factory=list)  # e.g., ["powershell", "wmi"]
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "family": self.family.value,
            "min_version": self.min_version,
            "max_version": self.max_version,
            "specific_versions": self.specific_versions,
            "architecture": self.architecture.value,
            "language": self.language,
            "required_features": self.required_features,
            "confidence": self.confidence,
        }


@dataclass
class SoftwareDependency:
    """Software dependency requirement."""
    name: str
    type: str  # e.g., "runtime", "library", "application"
    version_constraint: Optional[str] = None  # e.g., ">=3.0", "~2.7"
    required: bool = True
    purpose: Optional[str] = None  # Why this dependency is needed
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "version_constraint": self.version_constraint,
            "required": self.required,
            "purpose": self.purpose,
            "confidence": self.confidence,
        }


@dataclass
class NetworkEndpoint:
    """A network endpoint (domain, IP, or URL)."""
    type: str  # "domain", "ip", "url"
    value: str
    port: Optional[int] = None
    protocol: NetworkProtocol = NetworkProtocol.TCP
    purpose: Optional[str] = None  # "c2", "download", "exfiltration"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "port": self.port,
            "protocol": self.protocol.value,
            "purpose": self.purpose,
        }


@dataclass
class NetworkConstraint:
    """Network environment constraints."""
    requires_internet: bool = True
    protocols: List[NetworkProtocol] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    endpoints: List[NetworkEndpoint] = field(default_factory=list)
    dns_servers: List[str] = field(default_factory=list)
    uses_tor: bool = False
    uses_proxy: bool = False
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requires_internet": self.requires_internet,
            "protocols": [p.value for p in self.protocols],
            "ports": self.ports,
            "domains": self.domains,
            "ip_addresses": self.ip_addresses,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "dns_servers": self.dns_servers,
            "uses_tor": self.uses_tor,
            "uses_proxy": self.uses_proxy,
            "confidence": self.confidence,
        }


@dataclass
class HardwareProfile:
    """Hardware requirements and constraints."""
    min_memory_mb: Optional[int] = None
    min_disk_mb: Optional[int] = None
    cpu_features: List[str] = field(default_factory=list)  # e.g., ["vmx", "svm"]
    requires_gpu: bool = False
    vm_detection: bool = False  # Whether it detects VMs
    sandbox_detection: bool = False  # Whether it detects sandboxes
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "min_memory_mb": self.min_memory_mb,
            "min_disk_mb": self.min_disk_mb,
            "cpu_features": self.cpu_features,
            "requires_gpu": self.requires_gpu,
            "vm_detection": self.vm_detection,
            "sandbox_detection": self.sandbox_detection,
            "confidence": self.confidence,
        }


@dataclass
class MITREMapping:
    """MITRE ATT&CK technique mapping."""
    technique_id: str  # e.g., "T1059.001"
    technique_name: str
    tactic: str  # e.g., "Execution", "Persistence"
    description: Optional[str] = None
    evidence: List[str] = field(default_factory=list)  # Supporting evidence
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "description": self.description,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


@dataclass
class ThreatProfile:
    """Threat profile and classification."""
    primary_category: ThreatCategory
    secondary_categories: List[ThreatCategory] = field(default_factory=list)
    family_name: Optional[str] = None
    variant: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    severity: float = 0.0  # 0-10 scale
    capabilities: List[str] = field(default_factory=list)
    target_sectors: List[str] = field(default_factory=list)
    attribution: Optional[str] = None  # Threat actor attribution
    first_seen: Optional[str] = None
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary_category": self.primary_category.value,
            "secondary_categories": [c.value for c in self.secondary_categories],
            "family_name": self.family_name,
            "variant": self.variant,
            "aliases": self.aliases,
            "severity": self.severity,
            "capabilities": self.capabilities,
            "target_sectors": self.target_sectors,
            "attribution": self.attribution,
            "first_seen": self.first_seen,
            "confidence": self.confidence,
        }


@dataclass
class AttackChainStep:
    """A step in the attack chain."""
    order: int
    phase: str  # e.g., "Initial Access", "Execution", "Persistence"
    action: str
    technique_id: Optional[str] = None
    artifacts: List[str] = field(default_factory=list)  # Files, registry keys, etc.
    network_activity: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "order": self.order,
            "phase": self.phase,
            "action": self.action,
            "technique_id": self.technique_id,
            "artifacts": self.artifacts,
            "network_activity": self.network_activity,
        }


@dataclass
class EnvironmentSpecification:
    """Complete environment specification output from Stage I."""
    sample_hash: str
    os_requirements: OSRequirement
    software_dependencies: List[SoftwareDependency] = field(default_factory=list)
    network_constraints: NetworkConstraint = field(default_factory=NetworkConstraint)
    hardware_profile: HardwareProfile = field(default_factory=HardwareProfile)
    mitre_mapping: List[MITREMapping] = field(default_factory=list)
    threat_profile: Optional[ThreatProfile] = None
    attack_chain: List[AttackChainStep] = field(default_factory=list)

    # Metadata from deliberation
    grounded_extension_size: int = 0
    deliberation_rounds: int = 0
    total_hypotheses: int = 0
    conflicts_resolved: int = 0

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    analysis_duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_hash": self.sample_hash,
            "os_requirements": self.os_requirements.to_dict(),
            "software_dependencies": [d.to_dict() for d in self.software_dependencies],
            "network_constraints": self.network_constraints.to_dict(),
            "hardware_profile": self.hardware_profile.to_dict(),
            "mitre_mapping": [m.to_dict() for m in self.mitre_mapping],
            "threat_profile": self.threat_profile.to_dict() if self.threat_profile else None,
            "attack_chain": [s.to_dict() for s in self.attack_chain],
            "metadata": {
                "grounded_extension_size": self.grounded_extension_size,
                "deliberation_rounds": self.deliberation_rounds,
                "total_hypotheses": self.total_hypotheses,
                "conflicts_resolved": self.conflicts_resolved,
                "created_at": self.created_at.isoformat(),
                "analysis_duration_seconds": self.analysis_duration_seconds,
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, filepath: str) -> None:
        with open(filepath, 'w') as f:
            f.write(self.to_json())
