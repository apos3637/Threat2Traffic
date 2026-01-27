"""Evidence Graph implementation."""

from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import json

from .models import (
    NodeType,
    EdgeType,
    EvidenceNode,
    EvidenceEdge,
    SourceType,
    ConstraintCategory,
    HypothesisConflict,
)


class EvidenceGraph:
    """Evidence Graph for Stage I deliberation.

    The graph tracks:
    - Observations: immutable facts from VT analysis
    - Hypotheses: inferred environment constraints
    - Reasoning: deliberation process records
    - Conclusions: accepted specifications after grounded extension
    """

    def __init__(self):
        self._nodes: Dict[str, EvidenceNode] = {}
        self._edges: Dict[str, EvidenceEdge] = {}

        # Adjacency indices
        self._outgoing: Dict[str, Set[str]] = defaultdict(set)  # node_id -> edge_ids
        self._incoming: Dict[str, Set[str]] = defaultdict(set)  # node_id -> edge_ids

        # Type indices
        self._nodes_by_type: Dict[NodeType, Set[str]] = defaultdict(set)
        self._edges_by_type: Dict[EdgeType, Set[str]] = defaultdict(set)

        # Category index for hypotheses
        self._hypotheses_by_category: Dict[ConstraintCategory, Set[str]] = defaultdict(set)

    # ===== Node Operations =====

    def add_node(self, node: EvidenceNode) -> str:
        """Add a node to the graph."""
        if node.id in self._nodes:
            raise ValueError(f"Node {node.id} already exists")

        self._nodes[node.id] = node
        self._nodes_by_type[node.node_type].add(node.id)

        if node.node_type == NodeType.HYPOTHESIS and node.category:
            self._hypotheses_by_category[node.category].add(node.id)

        return node.id

    def get_node(self, node_id: str) -> Optional[EvidenceNode]:
        """Get a node by ID."""
        return self._nodes.get(node_id)

    def has_node(self, node_id: str) -> bool:
        """Check if node exists."""
        return node_id in self._nodes

    def remove_node(self, node_id: str) -> None:
        """Remove a node and all connected edges."""
        if node_id not in self._nodes:
            return

        node = self._nodes[node_id]

        # Remove connected edges
        edges_to_remove = self._outgoing[node_id] | self._incoming[node_id]
        for edge_id in list(edges_to_remove):
            self.remove_edge(edge_id)

        # Remove from indices
        self._nodes_by_type[node.node_type].discard(node_id)
        if node.category:
            self._hypotheses_by_category[node.category].discard(node_id)

        del self._nodes[node_id]
        self._outgoing.pop(node_id, None)
        self._incoming.pop(node_id, None)

    def update_node(self, node_id: str, **kwargs) -> None:
        """Update node attributes."""
        if node_id not in self._nodes:
            raise ValueError(f"Node {node_id} not found")

        node = self._nodes[node_id]
        for key, value in kwargs.items():
            if hasattr(node, key):
                setattr(node, key, value)

    # ===== Edge Operations =====

    def add_edge(self, edge: EvidenceEdge) -> str:
        """Add an edge to the graph."""
        if edge.id in self._edges:
            raise ValueError(f"Edge {edge.id} already exists")

        if edge.source_id not in self._nodes:
            raise ValueError(f"Source node {edge.source_id} not found")
        if edge.target_id not in self._nodes:
            raise ValueError(f"Target node {edge.target_id} not found")

        self._edges[edge.id] = edge
        self._outgoing[edge.source_id].add(edge.id)
        self._incoming[edge.target_id].add(edge.id)
        self._edges_by_type[edge.edge_type].add(edge.id)

        # Update hypothesis support/attack counts
        if edge.edge_type == EdgeType.SUPPORTS:
            target = self._nodes.get(edge.target_id)
            if target and target.node_type == NodeType.HYPOTHESIS:
                target.support_count += 1

        elif edge.edge_type == EdgeType.DEBATE:
            # Debate edges represent attacks between hypotheses
            target = self._nodes.get(edge.target_id)
            if target and target.node_type == NodeType.HYPOTHESIS:
                target.attack_count += 1

        return edge.id

    def get_edge(self, edge_id: str) -> Optional[EvidenceEdge]:
        """Get an edge by ID."""
        return self._edges.get(edge_id)

    def has_edge(self, edge_id: str) -> bool:
        """Check if edge exists."""
        return edge_id in self._edges

    def remove_edge(self, edge_id: str) -> None:
        """Remove an edge."""
        if edge_id not in self._edges:
            return

        edge = self._edges[edge_id]
        self._outgoing[edge.source_id].discard(edge_id)
        self._incoming[edge.target_id].discard(edge_id)
        self._edges_by_type[edge.edge_type].discard(edge_id)

        del self._edges[edge_id]

    # ===== Query Operations =====

    def get_nodes_by_type(self, node_type: NodeType) -> List[EvidenceNode]:
        """Get all nodes of a specific type."""
        return [self._nodes[nid] for nid in self._nodes_by_type[node_type]]

    def get_observations(self) -> List[EvidenceNode]:
        """Get all observation nodes."""
        return self.get_nodes_by_type(NodeType.OBSERVATION)

    def get_hypotheses(self) -> List[EvidenceNode]:
        """Get all hypothesis nodes."""
        return self.get_nodes_by_type(NodeType.HYPOTHESIS)

    def get_hypotheses_by_category(
        self, category: ConstraintCategory
    ) -> List[EvidenceNode]:
        """Get hypotheses in a specific category."""
        return [
            self._nodes[nid]
            for nid in self._hypotheses_by_category[category]
        ]

    def get_conclusions(self) -> List[EvidenceNode]:
        """Get all conclusion nodes."""
        return self.get_nodes_by_type(NodeType.CONCLUSION)

    def get_edges_by_type(self, edge_type: EdgeType) -> List[EvidenceEdge]:
        """Get all edges of a specific type."""
        return [self._edges[eid] for eid in self._edges_by_type[edge_type]]

    def get_outgoing_edges(self, node_id: str) -> List[EvidenceEdge]:
        """Get all outgoing edges from a node."""
        return [self._edges[eid] for eid in self._outgoing.get(node_id, set())]

    def get_incoming_edges(self, node_id: str) -> List[EvidenceEdge]:
        """Get all incoming edges to a node."""
        return [self._edges[eid] for eid in self._incoming.get(node_id, set())]

    def get_supporting_observations(self, hypothesis_id: str) -> List[EvidenceNode]:
        """Get observations that support a hypothesis."""
        observations = []
        for edge_id in self._incoming.get(hypothesis_id, set()):
            edge = self._edges[edge_id]
            if edge.edge_type == EdgeType.SUPPORTS:
                source_node = self._nodes.get(edge.source_id)
                if source_node and source_node.node_type == NodeType.OBSERVATION:
                    observations.append(source_node)
        return observations

    def get_attacking_hypotheses(self, hypothesis_id: str) -> List[EvidenceNode]:
        """Get hypotheses that attack a given hypothesis."""
        attackers = []
        for edge_id in self._incoming.get(hypothesis_id, set()):
            edge = self._edges[edge_id]
            if edge.edge_type == EdgeType.DEBATE:
                source_node = self._nodes.get(edge.source_id)
                if source_node and source_node.node_type == NodeType.HYPOTHESIS:
                    attackers.append(source_node)
        return attackers

    def get_debate_pairs(self) -> List[Tuple[EvidenceNode, EvidenceNode]]:
        """Get all pairs of hypotheses in debate."""
        pairs = []
        seen = set()
        for edge_id in self._edges_by_type[EdgeType.DEBATE]:
            edge = self._edges[edge_id]
            pair_key = tuple(sorted([edge.source_id, edge.target_id]))
            if pair_key not in seen:
                seen.add(pair_key)
                source = self._nodes.get(edge.source_id)
                target = self._nodes.get(edge.target_id)
                if source and target:
                    pairs.append((source, target))
        return pairs

    # ===== Conflict Detection =====

    def find_conflicts(self) -> List[HypothesisConflict]:
        """Find all conflicts between hypotheses."""
        conflicts = []
        hypotheses = self.get_hypotheses()

        for i, h1 in enumerate(hypotheses):
            for h2 in hypotheses[i + 1:]:
                conflict = self._detect_conflict(h1, h2)
                if conflict:
                    conflicts.append(conflict)

        return conflicts

    def _detect_conflict(
        self, h1: EvidenceNode, h2: EvidenceNode
    ) -> Optional[HypothesisConflict]:
        """Detect if two hypotheses conflict."""
        # Same category may have contradictions
        if h1.category == h2.category:
            # Check for explicit contradictions
            if self._is_contradictory(h1.content, h2.content):
                return HypothesisConflict(
                    hypothesis_a_id=h1.id,
                    hypothesis_b_id=h2.id,
                    conflict_type="contradiction",
                    description=f"Conflicting {h1.category.value} constraints",
                    severity=0.8,
                )
        return None

    def _is_contradictory(self, content1: str, content2: str) -> bool:
        """Simple contradiction detection based on content."""
        # This is a heuristic; real implementation should use LLM
        content1_lower = content1.lower()
        content2_lower = content2.lower()

        # Check for explicit negation patterns
        negation_pairs = [
            ("requires", "not require"),
            ("windows", "linux"),
            ("x86", "x64"),
            ("32-bit", "64-bit"),
        ]

        for pos, neg in negation_pairs:
            if (pos in content1_lower and neg in content2_lower) or \
               (neg in content1_lower and pos in content2_lower):
                return True

        return False

    # ===== Deliberation Link Operations =====

    def create_deliberation_link(
        self,
        hypothesis_ids: List[str],
        reasoning_content: str,
        link_type: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[EvidenceNode, List[EvidenceEdge]]:
        """Create a REASONING node with INPUT edges from hypotheses.

        This is the primary method for creating proper deliberation traces.
        Every deliberation action (challenge, rebuttal, merge) should use this.

        Args:
            hypothesis_ids: List of hypothesis IDs that feed into this reasoning
            reasoning_content: Content describing the deliberation step
            link_type: Type of deliberation ("challenge", "rebuttal", "merge", "validation")
            metadata: Additional metadata for the reasoning node

        Returns:
            Tuple of (reasoning_node, list_of_input_edges)
        """
        reasoning = EvidenceNode.create_reasoning(
            content=reasoning_content,
            metadata={
                "link_type": link_type,
                "hypothesis_ids": hypothesis_ids,
                **(metadata or {}),
            },
        )
        self.add_node(reasoning)

        input_edges = []
        for hyp_id in hypothesis_ids:
            if self.has_node(hyp_id):
                edge = EvidenceEdge.create(
                    edge_type=EdgeType.INPUT,
                    source_id=hyp_id,
                    target_id=reasoning.id,
                    metadata={"link_type": link_type},
                )
                self.add_edge(edge)
                input_edges.append(edge)

        return reasoning, input_edges

    def create_modification_link(
        self,
        reasoning_id: str,
        target_hypothesis_id: str,
        modification_type: str = "refinement",
    ) -> EvidenceEdge:
        """Create a MODIFICATION edge from reasoning to hypothesis.

        Used when a deliberation step modifies or creates a hypothesis.

        Args:
            reasoning_id: ID of the REASONING node
            target_hypothesis_id: ID of the target hypothesis (new or modified)
            modification_type: Type of modification ("refinement", "confidence_update", "merge_result")

        Returns:
            The created MODIFICATION edge
        """
        edge = EvidenceEdge.create(
            edge_type=EdgeType.MODIFICATION,
            source_id=reasoning_id,
            target_id=target_hypothesis_id,
            metadata={"modification_type": modification_type},
        )
        self.add_edge(edge)
        return edge

    def get_deliberation_trace(
        self,
        hypothesis_id: str,
    ) -> List[Dict[str, Any]]:
        """Reconstruct the deliberation decision tree for a hypothesis.

        Returns chronologically ordered list of all deliberation steps
        that involved this hypothesis (as input or output).

        Args:
            hypothesis_id: ID of the hypothesis to trace

        Returns:
            List of deliberation steps with type, reasoning, and timestamp
        """
        trace = []

        # Get all INPUT edges (this hypothesis was input to reasoning)
        for edge in self.get_outgoing_edges(hypothesis_id):
            if edge.edge_type == EdgeType.INPUT:
                reasoning = self.get_node(edge.target_id)
                if reasoning:
                    trace.append({
                        "type": "input_to_reasoning",
                        "direction": "outgoing",
                        "reasoning_id": reasoning.id,
                        "reasoning_content": reasoning.content,
                        "link_type": reasoning.metadata.get("link_type"),
                        "timestamp": reasoning.created_at,
                    })

        # Get all MODIFICATION edges (reasoning modified this hypothesis)
        for edge in self.get_incoming_edges(hypothesis_id):
            if edge.edge_type == EdgeType.MODIFICATION:
                reasoning = self.get_node(edge.source_id)
                if reasoning:
                    trace.append({
                        "type": "modified_by_reasoning",
                        "direction": "incoming",
                        "reasoning_id": reasoning.id,
                        "reasoning_content": reasoning.content,
                        "modification_type": edge.metadata.get("modification_type"),
                        "timestamp": reasoning.created_at,
                    })

        # Sort by timestamp
        trace.sort(key=lambda x: x["timestamp"])
        return trace

    def get_reasoning_chain(
        self,
        hypothesis_id: str,
    ) -> List[EvidenceNode]:
        """Get all REASONING nodes connected to a hypothesis.

        Returns REASONING nodes that either:
        - Received this hypothesis as INPUT
        - Produced a MODIFICATION to this hypothesis
        """
        reasoning_nodes = []
        seen_ids = set()

        # REASONING nodes this hypothesis fed into
        for edge in self.get_outgoing_edges(hypothesis_id):
            if edge.edge_type == EdgeType.INPUT:
                if edge.target_id not in seen_ids:
                    reasoning = self.get_node(edge.target_id)
                    if reasoning and reasoning.node_type == NodeType.REASONING:
                        reasoning_nodes.append(reasoning)
                        seen_ids.add(edge.target_id)

        # REASONING nodes that modified this hypothesis
        for edge in self.get_incoming_edges(hypothesis_id):
            if edge.edge_type == EdgeType.MODIFICATION:
                if edge.source_id not in seen_ids:
                    reasoning = self.get_node(edge.source_id)
                    if reasoning and reasoning.node_type == NodeType.REASONING:
                        reasoning_nodes.append(reasoning)
                        seen_ids.add(edge.source_id)

        return reasoning_nodes

    def get_input_hypotheses_for_reasoning(
        self,
        reasoning_id: str,
    ) -> List[EvidenceNode]:
        """Get all hypotheses that were INPUT to a REASONING node."""
        hypotheses = []
        for edge in self.get_incoming_edges(reasoning_id):
            if edge.edge_type == EdgeType.INPUT:
                hyp = self.get_node(edge.source_id)
                if hyp and hyp.node_type == NodeType.HYPOTHESIS:
                    hypotheses.append(hyp)
        return hypotheses

    def get_modified_hypotheses_from_reasoning(
        self,
        reasoning_id: str,
    ) -> List[EvidenceNode]:
        """Get all hypotheses that were MODIFIED by a REASONING node."""
        hypotheses = []
        for edge in self.get_outgoing_edges(reasoning_id):
            if edge.edge_type == EdgeType.MODIFICATION:
                hyp = self.get_node(edge.target_id)
                if hyp and hyp.node_type == NodeType.HYPOTHESIS:
                    hypotheses.append(hyp)
        return hypotheses

    def get_reasoning_nodes(self) -> List[EvidenceNode]:
        """Get all reasoning nodes."""
        return self.get_nodes_by_type(NodeType.REASONING)

    # ===== Graph Statistics =====

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def get_statistics(self) -> Dict[str, Any]:
        """Get graph statistics."""
        return {
            "total_nodes": self.node_count,
            "total_edges": self.edge_count,
            "nodes_by_type": {
                nt.value: len(self._nodes_by_type[nt])
                for nt in NodeType
            },
            "edges_by_type": {
                et.value: len(self._edges_by_type[et])
                for et in EdgeType
            },
            "hypotheses_by_category": {
                cat.value: len(self._hypotheses_by_category[cat])
                for cat in ConstraintCategory
                if len(self._hypotheses_by_category[cat]) > 0
            },
        }

    # ===== Serialization =====

    def to_dict(self) -> Dict[str, Any]:
        """Serialize graph to dictionary."""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.node_type.value,
                    "content": n.content,
                    "source": n.source.value,
                    "category": n.category.value if n.category else None,
                    "confidence": n.confidence,
                    "metadata": n.metadata,
                    "support_count": n.support_count,
                    "attack_count": n.attack_count,
                }
                for n in self._nodes.values()
            ],
            "edges": [
                {
                    "id": e.id,
                    "type": e.edge_type.value,
                    "source": e.source_id,
                    "target": e.target_id,
                    "weight": e.weight,
                    "metadata": e.metadata,
                }
                for e in self._edges.values()
            ],
            "statistics": self.get_statistics(),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize graph to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceGraph":
        """Deserialize graph from dictionary."""
        graph = cls()

        for node_data in data.get("nodes", []):
            node = EvidenceNode(
                id=node_data["id"],
                node_type=NodeType(node_data["type"]),
                content=node_data["content"],
                source=SourceType(node_data["source"]),
                category=ConstraintCategory(node_data["category"]) if node_data.get("category") else None,
                confidence=node_data.get("confidence", 1.0),
                metadata=node_data.get("metadata", {}),
                support_count=node_data.get("support_count", 0),
                attack_count=node_data.get("attack_count", 0),
            )
            graph.add_node(node)

        for edge_data in data.get("edges", []):
            edge = EvidenceEdge(
                id=edge_data["id"],
                edge_type=EdgeType(edge_data["type"]),
                source_id=edge_data["source"],
                target_id=edge_data["target"],
                weight=edge_data.get("weight", 1.0),
                metadata=edge_data.get("metadata", {}),
            )
            graph.add_edge(edge)

        return graph
