"""Data models for adversarial deliberation."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum

from ..evidence_graph.models import SourceType, EvidenceNode


class ChallengeType(str, Enum):
    """Types of challenges an agent can raise."""
    EVIDENCE_GAP = "evidence_gap"           # Insufficient evidence
    LOGICAL_FLAW = "logical_flaw"           # Reasoning error
    CONTRADICTION = "contradiction"          # Conflicts with evidence
    INSUFFICIENT_SUPPORT = "insufficient_support"  # Weak supporting evidence
    OVERGENERALIZATION = "overgeneralization"     # Too broad a claim


class DebateVerdict(str, Enum):
    """Verdict from a debate or validation."""
    SUPPORT = "support"      # Evidence supports hypothesis
    NEUTRAL = "neutral"      # No strong evidence either way
    OPPOSE = "oppose"        # Evidence contradicts hypothesis


class ConvergenceReason(str, Enum):
    """Reason for debate convergence."""
    CONFIDENCE_GAP = "confidence_gap"       # Clear winner by confidence
    MAX_ROUNDS = "max_rounds"               # Hit iteration limit
    MUTUAL_REFINEMENT = "mutual_refinement" # Both accepted modifications
    DEFENDER_CONCEDES = "defender_concedes" # Defender accepts challenge
    CHALLENGER_WITHDRAWS = "challenger_withdraws"  # Challenge withdrawn


@dataclass
class ChallengeResult:
    """Result of an agent challenging another agent's hypothesis."""
    challenger_source: SourceType
    target_hypothesis_id: str
    challenge_type: ChallengeType
    challenge_content: str
    counter_evidence: List[str] = field(default_factory=list)  # Observation IDs
    severity: float = 0.5  # 0-1
    suggested_modification: Optional[str] = None
    reasoning: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "challenger_source": self.challenger_source.value,
            "target_hypothesis_id": self.target_hypothesis_id,
            "challenge_type": self.challenge_type.value,
            "challenge_content": self.challenge_content,
            "counter_evidence": self.counter_evidence,
            "severity": self.severity,
            "suggested_modification": self.suggested_modification,
            "reasoning": self.reasoning,
        }


@dataclass
class RebuttalResult:
    """Result of an agent defending their hypothesis against a challenge."""
    defender_source: SourceType
    hypothesis_id: str
    rebuttal_content: str
    supporting_evidence: List[str] = field(default_factory=list)  # Observation IDs
    accepts_modification: bool = False
    proposed_refinement: Optional[str] = None
    confidence_adjustment: float = 0.0  # -0.5 to +0.5
    reasoning: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "defender_source": self.defender_source.value,
            "hypothesis_id": self.hypothesis_id,
            "rebuttal_content": self.rebuttal_content,
            "supporting_evidence": self.supporting_evidence,
            "accepts_modification": self.accepts_modification,
            "proposed_refinement": self.proposed_refinement,
            "confidence_adjustment": self.confidence_adjustment,
            "reasoning": self.reasoning,
        }


@dataclass
class ValidationResult:
    """Result of an agent cross-validating another agent's hypothesis."""
    validator_source: SourceType
    hypothesis_id: str
    verdict: DebateVerdict
    reasoning: str
    confidence_modifier: float = 0.0  # -0.3 to +0.3
    relevant_observations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "validator_source": self.validator_source.value,
            "hypothesis_id": self.hypothesis_id,
            "verdict": self.verdict.value,
            "reasoning": self.reasoning,
            "confidence_modifier": self.confidence_modifier,
            "relevant_observations": self.relevant_observations,
        }


@dataclass
class DebateRound:
    """A single round in a debate session."""
    round_number: int
    challenge: ChallengeResult
    rebuttal: Optional[RebuttalResult] = None
    refinement: Optional[EvidenceNode] = None
    challenge_reasoning_node_id: Optional[str] = None  # REASONING node for challenge
    rebuttal_reasoning_node_id: Optional[str] = None   # REASONING node for rebuttal

    def to_dict(self) -> Dict[str, Any]:
        return {
            "round_number": self.round_number,
            "challenge": self.challenge.to_dict(),
            "rebuttal": self.rebuttal.to_dict() if self.rebuttal else None,
            "refinement_id": self.refinement.id if self.refinement else None,
            "challenge_reasoning_node_id": self.challenge_reasoning_node_id,
            "rebuttal_reasoning_node_id": self.rebuttal_reasoning_node_id,
        }


@dataclass
class DebateOutcome:
    """Final outcome of a debate session."""
    winner_hypothesis_id: Optional[str] = None  # None for merge/tie
    confidence_a_final: float = 0.0
    confidence_b_final: float = 0.0
    merged_hypothesis: Optional[EvidenceNode] = None
    rounds_completed: int = 0
    convergence_reason: ConvergenceReason = ConvergenceReason.MAX_ROUNDS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "winner_hypothesis_id": self.winner_hypothesis_id,
            "confidence_a_final": self.confidence_a_final,
            "confidence_b_final": self.confidence_b_final,
            "merged_hypothesis_id": self.merged_hypothesis.id if self.merged_hypothesis else None,
            "rounds_completed": self.rounds_completed,
            "convergence_reason": self.convergence_reason.value,
        }


@dataclass
class DebateSession:
    """A complete debate session between two hypotheses.

    Tracks the multi-round adversarial debate process:
    - Protagonist defends hypothesis_a
    - Antagonist challenges with hypothesis_b's perspective
    """
    conflict_id: str
    hypothesis_a_id: str
    hypothesis_b_id: str
    protagonist_source: SourceType  # Agent defending hypothesis_a
    antagonist_source: SourceType   # Agent attacking from hypothesis_b's perspective
    rounds: List[DebateRound] = field(default_factory=list)
    max_rounds: int = 3
    outcome: Optional[DebateOutcome] = None

    # Initial state
    initial_confidence_a: float = 0.0
    initial_confidence_b: float = 0.0

    # Reasoning chain for traceability
    reasoning_node_ids: List[str] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        """Check if debate has concluded."""
        return self.outcome is not None

    @property
    def current_round(self) -> int:
        """Get current round number."""
        return len(self.rounds)

    def add_round(self, debate_round: DebateRound) -> None:
        """Add a completed debate round."""
        self.rounds.append(debate_round)
        if debate_round.challenge_reasoning_node_id:
            self.reasoning_node_ids.append(debate_round.challenge_reasoning_node_id)
        if debate_round.rebuttal_reasoning_node_id:
            self.reasoning_node_ids.append(debate_round.rebuttal_reasoning_node_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "conflict_id": self.conflict_id,
            "hypothesis_a_id": self.hypothesis_a_id,
            "hypothesis_b_id": self.hypothesis_b_id,
            "protagonist_source": self.protagonist_source.value,
            "antagonist_source": self.antagonist_source.value,
            "rounds": [r.to_dict() for r in self.rounds],
            "max_rounds": self.max_rounds,
            "outcome": self.outcome.to_dict() if self.outcome else None,
            "initial_confidence_a": self.initial_confidence_a,
            "initial_confidence_b": self.initial_confidence_b,
            "reasoning_node_ids": self.reasoning_node_ids,
        }


@dataclass
class CrossValidationRound:
    """Results of a cross-validation round where all agents validate surviving hypotheses."""
    round_number: int
    validations: List[ValidationResult] = field(default_factory=list)
    reasoning_node_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "round_number": self.round_number,
            "validations": [v.to_dict() for v in self.validations],
            "reasoning_node_ids": self.reasoning_node_ids,
        }


@dataclass
class AdversarialDeliberationResult:
    """Complete result of adversarial deliberation process."""
    debates: List[DebateSession] = field(default_factory=list)
    cross_validations: List[CrossValidationRound] = field(default_factory=list)
    total_conflicts_detected: int = 0
    total_conflicts_resolved: int = 0
    total_debates_conducted: int = 0
    total_reasoning_nodes_created: int = 0
    accepted_hypotheses: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "debates": [d.to_dict() for d in self.debates],
            "cross_validations": [cv.to_dict() for cv in self.cross_validations],
            "total_conflicts_detected": self.total_conflicts_detected,
            "total_conflicts_resolved": self.total_conflicts_resolved,
            "total_debates_conducted": self.total_debates_conducted,
            "total_reasoning_nodes_created": self.total_reasoning_nodes_created,
            "accepted_hypotheses": self.accepted_hypotheses,
        }
