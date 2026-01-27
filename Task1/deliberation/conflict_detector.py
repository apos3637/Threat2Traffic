"""Conflict detection for hypotheses using ensemble sampling."""

import json
from typing import Any, Dict, List, Optional, Set, Tuple

from ..evidence_graph.models import (
    EvidenceNode,
    EvidenceEdge,
    EdgeType,
    NodeType,
    ConstraintCategory,
    HypothesisConflict,
)
from ..evidence_graph.graph import EvidenceGraph
from ..utils.llm_client import LLMClient
from ..utils.logger import get_logger
from ..agents.prompts import CONFLICT_DETECTION_PROMPT

logger = get_logger("conflict_detector")


class ConflictDetector:
    """Detects conflicts between hypotheses using LLM ensemble sampling.

    Implements conflict detection as described in the paper:
    - Samples multiple LLM responses to identify potential conflicts
    - Categorizes conflicts: contradiction, subsumption, incompatibility
    - Assigns severity scores to conflicts
    """

    def __init__(
        self,
        llm_client: LLMClient,
        ensemble_samples: int = 3,
        conflict_threshold: float = 0.5,
    ):
        self.llm_client = llm_client
        self.ensemble_samples = ensemble_samples
        self.conflict_threshold = conflict_threshold

    async def detect_conflicts(
        self,
        graph: EvidenceGraph,
    ) -> List[HypothesisConflict]:
        """Detect conflicts between hypotheses in the graph.

        Uses both heuristic detection and LLM-based detection.
        """
        conflicts = []

        # Phase 1: Heuristic conflict detection
        heuristic_conflicts = self._detect_heuristic_conflicts(graph)
        conflicts.extend(heuristic_conflicts)
        logger.info(f"Heuristic detection found {len(heuristic_conflicts)} conflicts")

        # Phase 2: LLM-based conflict detection via ensemble sampling
        llm_conflicts = await self._detect_llm_conflicts(graph)
        conflicts.extend(llm_conflicts)
        logger.info(f"LLM detection found {len(llm_conflicts)} conflicts")

        # Deduplicate conflicts
        unique_conflicts = self._deduplicate_conflicts(conflicts)
        logger.info(f"Total unique conflicts: {len(unique_conflicts)}")

        return unique_conflicts

    def _detect_heuristic_conflicts(
        self,
        graph: EvidenceGraph,
    ) -> List[HypothesisConflict]:
        """Detect conflicts using heuristic rules."""
        conflicts = []
        hypotheses = graph.get_hypotheses()

        for i, h1 in enumerate(hypotheses):
            for h2 in hypotheses[i + 1:]:
                conflict = self._check_heuristic_conflict(h1, h2)
                if conflict:
                    conflicts.append(conflict)

        return conflicts

    def _check_heuristic_conflict(
        self,
        h1: EvidenceNode,
        h2: EvidenceNode,
    ) -> Optional[HypothesisConflict]:
        """Check for conflicts between two hypotheses using heuristics."""
        # Same category conflicts
        if h1.category == h2.category:
            # OS version conflicts
            if h1.category == ConstraintCategory.OS_VERSION:
                if self._os_conflict(h1.content, h2.content):
                    return HypothesisConflict(
                        hypothesis_a_id=h1.id,
                        hypothesis_b_id=h2.id,
                        conflict_type="contradiction",
                        description="Conflicting OS version requirements",
                        severity=0.9,
                    )

            # Architecture conflicts
            if h1.category == ConstraintCategory.OS_ARCHITECTURE:
                if self._arch_conflict(h1.content, h2.content):
                    return HypothesisConflict(
                        hypothesis_a_id=h1.id,
                        hypothesis_b_id=h2.id,
                        conflict_type="contradiction",
                        description="Conflicting architecture requirements",
                        severity=0.9,
                    )

        return None

    def _os_conflict(self, content1: str, content2: str) -> bool:
        """Check for OS version conflicts."""
        c1 = content1.lower()
        c2 = content2.lower()

        # Windows vs Linux
        if ("windows" in c1 and "linux" in c2) or \
           ("linux" in c1 and "windows" in c2):
            return True

        # Windows vs macOS
        if ("windows" in c1 and "macos" in c2) or \
           ("macos" in c1 and "windows" in c2):
            return True

        return False

    def _arch_conflict(self, content1: str, content2: str) -> bool:
        """Check for architecture conflicts."""
        c1 = content1.lower()
        c2 = content2.lower()

        # x86 vs x64 exclusive requirements
        if ("x86 only" in c1 and "x64" in c2) or \
           ("x64 only" in c1 and "x86" in c2):
            return True

        if ("32-bit only" in c1 and "64-bit" in c2) or \
           ("64-bit only" in c1 and "32-bit" in c2):
            return True

        return False

    async def _detect_llm_conflicts(
        self,
        graph: EvidenceGraph,
    ) -> List[HypothesisConflict]:
        """Detect conflicts using LLM ensemble sampling."""
        hypotheses = graph.get_hypotheses()
        if len(hypotheses) < 2:
            return []

        # Group hypotheses by source for the prompt
        static_hyps = [h for h in hypotheses if "static" in h.source.value]
        behavior_hyps = [h for h in hypotheses if "behavior" in h.source.value]
        threat_hyps = [h for h in hypotheses if "threat" in h.source.value]

        def format_hypotheses(hyps: List[EvidenceNode]) -> str:
            if not hyps:
                return "No hypotheses"
            return "\n".join([
                f"- [{h.id}] ({h.category.value if h.category else 'general'}, "
                f"conf={h.confidence:.2f}): {h.content}"
                for h in hyps
            ])

        prompt = CONFLICT_DETECTION_PROMPT.format(
            static_hypotheses=format_hypotheses(static_hyps),
            behavior_hypotheses=format_hypotheses(behavior_hyps),
            threat_intel_hypotheses=format_hypotheses(threat_hyps),
        )

        # Ensemble sampling
        all_conflicts: Dict[Tuple[str, str], List[HypothesisConflict]] = {}

        for _ in range(self.ensemble_samples):
            try:
                result = await self.llm_client.chat_json([
                    {"role": "system", "content": "You are a conflict detection expert."},
                    {"role": "user", "content": prompt},
                ])

                for conflict_data in result.get("conflicts", []):
                    conflict = HypothesisConflict(
                        hypothesis_a_id=conflict_data.get("hypothesis_a_id", ""),
                        hypothesis_b_id=conflict_data.get("hypothesis_b_id", ""),
                        conflict_type=conflict_data.get("conflict_type", "contradiction"),
                        description=conflict_data.get("description", ""),
                        severity=float(conflict_data.get("severity", 0.5)),
                    )

                    # Normalize pair ordering for deduplication
                    pair_key = tuple(sorted([conflict.hypothesis_a_id, conflict.hypothesis_b_id]))
                    if pair_key not in all_conflicts:
                        all_conflicts[pair_key] = []
                    all_conflicts[pair_key].append(conflict)

            except Exception as e:
                logger.warning(f"LLM conflict detection sample failed: {e}")
                continue

        # Aggregate ensemble results
        final_conflicts = []
        for pair_key, conflict_samples in all_conflicts.items():
            # Only keep conflicts detected in majority of samples
            if len(conflict_samples) >= self.ensemble_samples * self.conflict_threshold:
                # Use average severity and most common conflict type
                avg_severity = sum(c.severity for c in conflict_samples) / len(conflict_samples)
                most_common_type = max(
                    set(c.conflict_type for c in conflict_samples),
                    key=lambda t: sum(1 for c in conflict_samples if c.conflict_type == t)
                )

                final_conflicts.append(HypothesisConflict(
                    hypothesis_a_id=pair_key[0],
                    hypothesis_b_id=pair_key[1],
                    conflict_type=most_common_type,
                    description=conflict_samples[0].description,
                    severity=avg_severity,
                ))

        return final_conflicts

    def _deduplicate_conflicts(
        self,
        conflicts: List[HypothesisConflict],
    ) -> List[HypothesisConflict]:
        """Remove duplicate conflicts."""
        seen_pairs: Set[Tuple[str, str]] = set()
        unique = []

        for conflict in conflicts:
            pair_key = tuple(sorted([conflict.hypothesis_a_id, conflict.hypothesis_b_id]))
            if pair_key not in seen_pairs:
                seen_pairs.add(pair_key)
                unique.append(conflict)

        return unique

    def add_conflict_edges(
        self,
        graph: EvidenceGraph,
        conflicts: List[HypothesisConflict],
    ) -> None:
        """Add DEBATE edges to the graph for detected conflicts."""
        for conflict in conflicts:
            # Add bidirectional DEBATE edges
            edge1 = EvidenceEdge.create(
                edge_type=EdgeType.DEBATE,
                source_id=conflict.hypothesis_a_id,
                target_id=conflict.hypothesis_b_id,
                weight=conflict.severity,
                metadata={
                    "conflict_type": conflict.conflict_type,
                    "description": conflict.description,
                },
            )

            edge2 = EvidenceEdge.create(
                edge_type=EdgeType.DEBATE,
                source_id=conflict.hypothesis_b_id,
                target_id=conflict.hypothesis_a_id,
                weight=conflict.severity,
                metadata={
                    "conflict_type": conflict.conflict_type,
                    "description": conflict.description,
                },
            )

            try:
                graph.add_edge(edge1)
                graph.add_edge(edge2)
            except ValueError as e:
                logger.warning(f"Failed to add conflict edge: {e}")
