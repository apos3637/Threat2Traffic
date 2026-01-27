"""Evidence Graph construction invariant checking."""

from typing import List, Tuple
from dataclasses import dataclass
from enum import Enum

from .models import NodeType, EdgeType, EvidenceNode, EvidenceEdge
from .graph import EvidenceGraph


class InvariantViolationType(str, Enum):
    """Types of invariant violations."""
    INVALID_EDGE_SOURCE = "invalid_edge_source"
    INVALID_EDGE_TARGET = "invalid_edge_target"
    OBSERVATION_MODIFIED = "observation_modified"
    HYPOTHESIS_NO_SUPPORT = "hypothesis_no_support"
    CONCLUSION_NO_VALIDATION = "conclusion_no_validation"
    CYCLE_DETECTED = "cycle_detected"


@dataclass
class InvariantViolation:
    """Represents an invariant violation."""
    violation_type: InvariantViolationType
    description: str
    node_id: str = None
    edge_id: str = None


class GraphInvariantChecker:
    """Checks construction invariants for Evidence Graph.

    Invariants (from paper):
    1. Observations are immutable (no incoming MODIFICATION edges)
    2. SUPPORTS edges: observation -> hypothesis only
    3. DEBATE edges: hypothesis <-> hypothesis only
    4. INPUT edges: hypothesis -> reasoning only
    5. MODIFICATION edges: reasoning -> hypothesis only
    6. VALIDATION edges: hypothesis -> conclusion only
    7. Every hypothesis should have at least one supporting observation
    8. Every conclusion should have a validation edge from an accepted hypothesis
    """

    # Valid edge patterns: (source_type, target_type) for each edge_type
    VALID_EDGE_PATTERNS = {
        EdgeType.SUPPORTS: [(NodeType.OBSERVATION, NodeType.HYPOTHESIS)],
        EdgeType.DEBATE: [(NodeType.HYPOTHESIS, NodeType.HYPOTHESIS)],
        EdgeType.INPUT: [(NodeType.HYPOTHESIS, NodeType.REASONING)],
        EdgeType.MODIFICATION: [(NodeType.REASONING, NodeType.HYPOTHESIS)],
        EdgeType.VALIDATION: [(NodeType.HYPOTHESIS, NodeType.CONCLUSION)],
    }

    def __init__(self, graph: EvidenceGraph):
        self.graph = graph

    def check_all(self) -> List[InvariantViolation]:
        """Run all invariant checks."""
        violations = []
        violations.extend(self.check_edge_type_constraints())
        violations.extend(self.check_observation_immutability())
        violations.extend(self.check_hypothesis_support())
        violations.extend(self.check_conclusion_validation())
        return violations

    def check_edge_type_constraints(self) -> List[InvariantViolation]:
        """Check that edges connect valid node types."""
        violations = []

        for edge in self.graph._edges.values():
            source_node = self.graph.get_node(edge.source_id)
            target_node = self.graph.get_node(edge.target_id)

            if not source_node or not target_node:
                violations.append(InvariantViolation(
                    violation_type=InvariantViolationType.INVALID_EDGE_SOURCE,
                    description=f"Edge {edge.id} references non-existent node",
                    edge_id=edge.id,
                ))
                continue

            valid_patterns = self.VALID_EDGE_PATTERNS.get(edge.edge_type, [])
            is_valid = any(
                source_node.node_type == src_type and target_node.node_type == tgt_type
                for src_type, tgt_type in valid_patterns
            )

            if not is_valid:
                violations.append(InvariantViolation(
                    violation_type=InvariantViolationType.INVALID_EDGE_SOURCE,
                    description=(
                        f"Edge {edge.id} ({edge.edge_type.value}) connects "
                        f"{source_node.node_type.value} -> {target_node.node_type.value}, "
                        f"but should be one of {valid_patterns}"
                    ),
                    edge_id=edge.id,
                ))

        return violations

    def check_observation_immutability(self) -> List[InvariantViolation]:
        """Check that observations have no incoming MODIFICATION edges."""
        violations = []

        for obs in self.graph.get_observations():
            incoming = self.graph.get_incoming_edges(obs.id)
            for edge in incoming:
                if edge.edge_type == EdgeType.MODIFICATION:
                    violations.append(InvariantViolation(
                        violation_type=InvariantViolationType.OBSERVATION_MODIFIED,
                        description=f"Observation {obs.id} has incoming MODIFICATION edge {edge.id}",
                        node_id=obs.id,
                        edge_id=edge.id,
                    ))

        return violations

    def check_hypothesis_support(self) -> List[InvariantViolation]:
        """Check that every hypothesis has at least one supporting observation.

        Note: This is a soft invariant - hypotheses may be created during
        deliberation before evidence is linked.
        """
        violations = []

        for hyp in self.graph.get_hypotheses():
            supporting = self.graph.get_supporting_observations(hyp.id)
            if len(supporting) == 0:
                violations.append(InvariantViolation(
                    violation_type=InvariantViolationType.HYPOTHESIS_NO_SUPPORT,
                    description=f"Hypothesis {hyp.id} has no supporting observations",
                    node_id=hyp.id,
                ))

        return violations

    def check_conclusion_validation(self) -> List[InvariantViolation]:
        """Check that every conclusion has a validation edge."""
        violations = []

        for conclusion in self.graph.get_conclusions():
            incoming = self.graph.get_incoming_edges(conclusion.id)
            has_validation = any(
                e.edge_type == EdgeType.VALIDATION for e in incoming
            )
            if not has_validation:
                violations.append(InvariantViolation(
                    violation_type=InvariantViolationType.CONCLUSION_NO_VALIDATION,
                    description=f"Conclusion {conclusion.id} has no VALIDATION edge",
                    node_id=conclusion.id,
                ))

        return violations

    def is_valid(self) -> bool:
        """Check if graph satisfies all invariants."""
        return len(self.check_all()) == 0

    def validate_edge_addition(
        self,
        edge_type: EdgeType,
        source_id: str,
        target_id: str,
    ) -> Tuple[bool, str]:
        """Validate before adding an edge.

        Returns (is_valid, error_message).
        """
        source_node = self.graph.get_node(source_id)
        target_node = self.graph.get_node(target_id)

        if not source_node:
            return False, f"Source node {source_id} not found"
        if not target_node:
            return False, f"Target node {target_id} not found"

        valid_patterns = self.VALID_EDGE_PATTERNS.get(edge_type, [])
        is_valid = any(
            source_node.node_type == src_type and target_node.node_type == tgt_type
            for src_type, tgt_type in valid_patterns
        )

        if not is_valid:
            expected = ", ".join(f"{s.value}->{t.value}" for s, t in valid_patterns)
            actual = f"{source_node.node_type.value}->{target_node.node_type.value}"
            return False, f"Invalid edge: {actual}. Expected: {expected}"

        # Check observation immutability
        if edge_type == EdgeType.MODIFICATION and target_node.node_type == NodeType.OBSERVATION:
            return False, "Cannot modify observations"

        return True, ""
