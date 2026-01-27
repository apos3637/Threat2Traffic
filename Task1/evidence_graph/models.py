"""Evidence Graph node and edge type definitions (Definition 1 from paper)."""

from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime
import uuid


class NodeType(str, Enum):
    """Node types in Evidence Graph (Definition 1).

    - OBSERVATION: Immutable facts extracted from VT reports
    - HYPOTHESIS: Inferred constraints proposed by agents
    - REASONING: Deliberation process records
    - CONCLUSION: Final accepted specifications
    """
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    REASONING = "reasoning"
    CONCLUSION = "conclusion"


class EdgeType(str, Enum):
    """Edge types in Evidence Graph (Definition 1).

    - SUPPORTS: observation -> hypothesis (evidence supports inference)
    - DEBATE: hypothesis <-> hypothesis (attack relation in AAF)
    - INPUT: hypothesis -> reasoning (input to deliberation)
    - MODIFICATION: reasoning -> hypothesis (hypothesis revision)
    - VALIDATION: hypothesis -> conclusion (accepted after grounded extension)
    """
    SUPPORTS = "supports"
    DEBATE = "debate"
    INPUT = "input"
    MODIFICATION = "modification"
    VALIDATION = "validation"


class SourceType(str, Enum):
    """Source of evidence or hypothesis."""
    VT_STATIC = "vt_static"           # VirusTotal static analysis
    VT_BEHAVIOR = "vt_behavior"       # VirusTotal sandbox behavior
    VT_THREAT_INTEL = "vt_threat_intel"  # VirusTotal threat intelligence
    AGENT_STATIC = "agent_static"     # Static analysis agent
    AGENT_BEHAVIOR = "agent_behavior" # Behavior analysis agent
    AGENT_THREAT = "agent_threat"     # Threat intel agent
    DELIBERATION = "deliberation"     # Deliberation process
    GROUNDED_EXT = "grounded_extension"  # Grounded extension result


class ConstraintCategory(str, Enum):
    """Categories of environment constraints."""
    OS_VERSION = "os_version"
    OS_ARCHITECTURE = "os_architecture"
    OS_LANGUAGE = "os_language"
    SOFTWARE_DEPENDENCY = "software_dependency"
    RUNTIME_DEPENDENCY = "runtime_dependency"
    NETWORK_PROTOCOL = "network_protocol"
    NETWORK_PORT = "network_port"
    NETWORK_DOMAIN = "network_domain"
    NETWORK_IP = "network_ip"
    HARDWARE_CPU = "hardware_cpu"
    HARDWARE_MEMORY = "hardware_memory"
    HARDWARE_DISK = "hardware_disk"
    FILE_SYSTEM = "file_system"
    REGISTRY = "registry"
    PERMISSION = "permission"
    ANTI_ANALYSIS = "anti_analysis"


@dataclass
class EvidenceNode:
    """A node in the Evidence Graph."""
    id: str
    node_type: NodeType
    content: str
    source: SourceType
    category: Optional[ConstraintCategory] = None
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

    # For hypothesis nodes
    support_count: int = 0
    attack_count: int = 0

    @classmethod
    def create_observation(
        cls,
        content: str,
        source: SourceType,
        category: Optional[ConstraintCategory] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "EvidenceNode":
        """Create an observation node (immutable fact)."""
        return cls(
            id=f"obs_{uuid.uuid4().hex[:8]}",
            node_type=NodeType.OBSERVATION,
            content=content,
            source=source,
            category=category,
            confidence=1.0,  # Observations are facts
            metadata=metadata or {},
        )

    @classmethod
    def create_hypothesis(
        cls,
        content: str,
        source: SourceType,
        category: ConstraintCategory,
        confidence: float = 0.5,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "EvidenceNode":
        """Create a hypothesis node (inferred constraint)."""
        return cls(
            id=f"hyp_{uuid.uuid4().hex[:8]}",
            node_type=NodeType.HYPOTHESIS,
            content=content,
            source=source,
            category=category,
            confidence=confidence,
            metadata=metadata or {},
        )

    @classmethod
    def create_reasoning(
        cls,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "EvidenceNode":
        """Create a reasoning node (deliberation process)."""
        return cls(
            id=f"rsn_{uuid.uuid4().hex[:8]}",
            node_type=NodeType.REASONING,
            content=content,
            source=SourceType.DELIBERATION,
            metadata=metadata or {},
        )

    @classmethod
    def create_conclusion(
        cls,
        content: str,
        category: ConstraintCategory,
        confidence: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "EvidenceNode":
        """Create a conclusion node (accepted specification)."""
        return cls(
            id=f"con_{uuid.uuid4().hex[:8]}",
            node_type=NodeType.CONCLUSION,
            content=content,
            source=SourceType.GROUNDED_EXT,
            category=category,
            confidence=confidence,
            metadata=metadata or {},
        )


@dataclass
class EvidenceEdge:
    """An edge in the Evidence Graph."""
    id: str
    edge_type: EdgeType
    source_id: str
    target_id: str
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

    @classmethod
    def create(
        cls,
        edge_type: EdgeType,
        source_id: str,
        target_id: str,
        weight: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "EvidenceEdge":
        """Create an edge with auto-generated ID."""
        return cls(
            id=f"edge_{uuid.uuid4().hex[:8]}",
            edge_type=edge_type,
            source_id=source_id,
            target_id=target_id,
            weight=weight,
            metadata=metadata or {},
        )


@dataclass
class HypothesisConflict:
    """Represents a conflict between two hypotheses."""
    hypothesis_a_id: str
    hypothesis_b_id: str
    conflict_type: str
    description: str
    severity: float = 0.5  # 0-1, higher = more severe

    @property
    def is_symmetric(self) -> bool:
        """DEBATE edges are bidirectional."""
        return True
