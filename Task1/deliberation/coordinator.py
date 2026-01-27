"""Deliberation coordinator for multi-round adversarial resolution."""

import json
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field

from ..evidence_graph.models import (
    EvidenceNode,
    EvidenceEdge,
    EdgeType,
    NodeType,
    SourceType,
    ConstraintCategory,
    HypothesisConflict,
)
from ..evidence_graph.graph import EvidenceGraph
from ..argumentation.models import (
    Argument,
    Attack,
    ArgumentationFramework,
    ExtensionResult,
)
from ..argumentation.preference import PreferenceCalculator, PreferenceConfig
from ..argumentation.grounded_extension import GroundedExtensionSolver
from ..utils.llm_client import LLMClient
from ..utils.logger import get_logger
from ..agents.prompts import DELIBERATION_PROMPT
from .conflict_detector import ConflictDetector
from .models import (
    ChallengeResult,
    RebuttalResult,
    ValidationResult,
    DebateRound,
    DebateOutcome,
    DebateSession,
    CrossValidationRound,
    AdversarialDeliberationResult,
    ConvergenceReason,
    DebateVerdict,
)

if TYPE_CHECKING:
    from ..agents.base_agent import BaseAgent

logger = get_logger("deliberation_coordinator")


@dataclass
class DeliberationRound:
    """Record of a single deliberation round."""
    round_number: int
    conflicts_before: int
    conflicts_resolved: int
    hypotheses_modified: int
    hypotheses_merged: int
    new_hypotheses: int


@dataclass
class DeliberationResult:
    """Result of the complete deliberation process."""
    rounds: List[DeliberationRound] = field(default_factory=list)
    total_conflicts_detected: int = 0
    total_conflicts_resolved: int = 0
    final_extension: Optional[ExtensionResult] = None
    accepted_hypotheses: List[str] = field(default_factory=list)


class DeliberationCoordinator:
    """Coordinates multi-round adversarial deliberation.

    Implements the deliberation process:
    1. Detect conflicts between hypotheses
    2. Build AAF from hypotheses and conflicts
    3. Use LLM to attempt conflict resolution
    4. Compute grounded extension
    5. Repeat until convergence or max rounds
    """

    def __init__(
        self,
        llm_client: LLMClient,
        preference_config: Optional[PreferenceConfig] = None,
        max_rounds: int = 3,
        convergence_threshold: float = 0.9,
    ):
        self.llm_client = llm_client
        self.preference_config = preference_config or PreferenceConfig()
        self.max_rounds = max_rounds
        self.convergence_threshold = convergence_threshold

        self.conflict_detector = ConflictDetector(llm_client)
        self.preference_calculator = PreferenceCalculator(self.preference_config)
        self.extension_solver = GroundedExtensionSolver(
            preference_calculator=self.preference_calculator
        )

    async def deliberate(
        self,
        graph: EvidenceGraph,
    ) -> DeliberationResult:
        """Run the complete deliberation process.

        Returns:
            DeliberationResult containing the grounded extension and statistics.
        """
        result = DeliberationResult()
        previous_extension_size = 0

        for round_num in range(1, self.max_rounds + 1):
            logger.info(f"Starting deliberation round {round_num}")

            # Step 1: Detect conflicts
            conflicts = await self.conflict_detector.detect_conflicts(graph)
            result.total_conflicts_detected += len(conflicts)
            logger.info(f"Round {round_num}: Detected {len(conflicts)} conflicts")

            # Step 2: Add conflict edges to graph
            self.conflict_detector.add_conflict_edges(graph, conflicts)

            # Step 3: Build AAF from graph
            aaf = self._build_aaf(graph)
            logger.info(f"Round {round_num}: Built AAF with {aaf.argument_count} arguments, {aaf.attack_count} attacks")

            # Step 4: Attempt to resolve conflicts via LLM
            round_result = await self._resolve_conflicts(graph, conflicts, round_num)
            result.rounds.append(round_result)
            result.total_conflicts_resolved += round_result.conflicts_resolved

            # Step 5: Recompute AAF after modifications
            aaf = self._build_aaf(graph)

            # Step 6: Compute grounded extension
            extension = self.extension_solver.compute(aaf)
            result.final_extension = extension
            logger.info(
                f"Round {round_num}: Grounded extension has {len(extension.accepted)} accepted arguments"
            )

            # Check convergence
            if len(extension.accepted) == previous_extension_size:
                logger.info(f"Converged after round {round_num}")
                break

            previous_extension_size = len(extension.accepted)

            # Check if most hypotheses are decided
            decided_ratio = (len(extension.accepted) + len(extension.rejected)) / aaf.argument_count
            if decided_ratio >= self.convergence_threshold:
                logger.info(f"Reached convergence threshold ({decided_ratio:.2%} decided)")
                break

        # Extract accepted hypothesis IDs
        if result.final_extension:
            result.accepted_hypotheses = list(result.final_extension.accepted)

        return result

    def _build_aaf(self, graph: EvidenceGraph) -> ArgumentationFramework:
        """Build an AAF from the Evidence Graph."""
        aaf = ArgumentationFramework()

        # Add arguments from hypotheses
        for hyp in graph.get_hypotheses():
            support_degree = self.preference_calculator.calculate_support_degree(hyp, graph)

            arg = Argument(
                id=f"arg_{hyp.id}",
                hypothesis_id=hyp.id,
                content=hyp.content,
                confidence=hyp.confidence,
                support_degree=support_degree,
            )
            arg.preference = self.preference_calculator.calculate_argument_preference(arg)
            aaf.add_argument(arg)

        # Add attacks from DEBATE edges
        for edge in graph.get_edges_by_type(EdgeType.DEBATE):
            source_arg_id = f"arg_{edge.source_id}"
            target_arg_id = f"arg_{edge.target_id}"

            if source_arg_id in aaf.arguments and target_arg_id in aaf.arguments:
                attack = Attack(
                    attacker_id=source_arg_id,
                    target_id=target_arg_id,
                    attack_type=edge.metadata.get("conflict_type", "debate"),
                    strength=edge.weight,
                )
                aaf.add_attack(attack)

        return aaf

    async def _resolve_conflicts(
        self,
        graph: EvidenceGraph,
        conflicts: List[HypothesisConflict],
        round_number: int,
    ) -> DeliberationRound:
        """Attempt to resolve conflicts using LLM deliberation."""
        resolved = 0
        modified = 0
        merged = 0
        new_hyps = 0

        for conflict in conflicts:
            try:
                resolution = await self._resolve_single_conflict(graph, conflict)

                if resolution.get("resolution") == "merge":
                    # Create merged hypothesis
                    merged_data = resolution.get("merged_hypothesis", {})
                    if merged_data.get("content"):
                        category = self._infer_category(graph, conflict)
                        new_node = EvidenceNode.create_hypothesis(
                            content=merged_data["content"],
                            source=SourceType.DELIBERATION,
                            category=category,
                            confidence=float(merged_data.get("confidence", 0.6)),
                            metadata={
                                "merged_from": [conflict.hypothesis_a_id, conflict.hypothesis_b_id],
                                "round": round_number,
                            },
                        )
                        graph.add_node(new_node)

                        # Add reasoning node
                        reasoning = EvidenceNode.create_reasoning(
                            content=resolution.get("reasoning", "Merged conflicting hypotheses"),
                            metadata={"conflict": conflict.__dict__},
                        )
                        graph.add_node(reasoning)

                        # Link reasoning to merged hypothesis
                        mod_edge = EvidenceEdge.create(
                            edge_type=EdgeType.MODIFICATION,
                            source_id=reasoning.id,
                            target_id=new_node.id,
                        )
                        graph.add_edge(mod_edge)

                        merged += 1
                        new_hyps += 1
                        resolved += 1

                elif resolution.get("resolution") in ("accept_a", "accept_b"):
                    # One hypothesis wins - adjust confidences
                    winner_id = conflict.hypothesis_a_id if resolution["resolution"] == "accept_a" else conflict.hypothesis_b_id
                    loser_id = conflict.hypothesis_b_id if resolution["resolution"] == "accept_a" else conflict.hypothesis_a_id

                    winner = graph.get_node(winner_id)
                    loser = graph.get_node(loser_id)

                    if winner:
                        graph.update_node(winner_id, confidence=min(1.0, winner.confidence + 0.1))
                        modified += 1
                    if loser:
                        graph.update_node(loser_id, confidence=max(0.1, loser.confidence - 0.2))
                        modified += 1

                    resolved += 1

                # Apply any explicit modifications
                for mod in resolution.get("modifications", []):
                    target_id = mod.get("target_hypothesis_id")
                    if target_id and graph.has_node(target_id):
                        if mod.get("new_confidence"):
                            graph.update_node(target_id, confidence=float(mod["new_confidence"]))
                        if mod.get("new_content"):
                            graph.update_node(target_id, content=mod["new_content"])
                        modified += 1

            except Exception as e:
                logger.warning(f"Failed to resolve conflict: {e}")
                continue

        return DeliberationRound(
            round_number=round_number,
            conflicts_before=len(conflicts),
            conflicts_resolved=resolved,
            hypotheses_modified=modified,
            hypotheses_merged=merged,
            new_hypotheses=new_hyps,
        )

    async def _resolve_single_conflict(
        self,
        graph: EvidenceGraph,
        conflict: HypothesisConflict,
    ) -> Dict[str, Any]:
        """Use LLM to resolve a single conflict."""
        hyp_a = graph.get_node(conflict.hypothesis_a_id)
        hyp_b = graph.get_node(conflict.hypothesis_b_id)

        if not hyp_a or not hyp_b:
            return {"resolution": "neither", "reasoning": "Missing hypothesis"}

        # Gather evidence for each hypothesis
        evidence_a = self._gather_evidence(graph, conflict.hypothesis_a_id)
        evidence_b = self._gather_evidence(graph, conflict.hypothesis_b_id)

        prompt = DELIBERATION_PROMPT.format(
            hypothesis_a=f"[{hyp_a.id}] (conf={hyp_a.confidence:.2f}): {hyp_a.content}",
            hypothesis_b=f"[{hyp_b.id}] (conf={hyp_b.confidence:.2f}): {hyp_b.content}",
            conflict_type=conflict.conflict_type,
            conflict_description=conflict.description,
            evidence_a=evidence_a,
            evidence_b=evidence_b,
        )

        try:
            result = await self.llm_client.chat_json([
                {"role": "system", "content": "You are a deliberation coordinator resolving conflicts."},
                {"role": "user", "content": prompt},
            ])
            return result
        except Exception as e:
            logger.error(f"LLM conflict resolution failed: {e}")
            return {"resolution": "neither", "reasoning": str(e)}

    def _gather_evidence(self, graph: EvidenceGraph, hypothesis_id: str) -> str:
        """Gather supporting evidence for a hypothesis."""
        observations = graph.get_supporting_observations(hypothesis_id)
        if not observations:
            return "No direct supporting observations"

        evidence_lines = []
        for obs in observations:
            evidence_lines.append(f"- [{obs.source.value}] {obs.content}")

        return "\n".join(evidence_lines)

    def _infer_category(
        self,
        graph: EvidenceGraph,
        conflict: HypothesisConflict,
    ) -> Optional[ConstraintCategory]:
        """Infer category for merged hypothesis from original hypotheses."""
        hyp_a = graph.get_node(conflict.hypothesis_a_id)
        hyp_b = graph.get_node(conflict.hypothesis_b_id)

        if hyp_a and hyp_a.category:
            return hyp_a.category
        if hyp_b and hyp_b.category:
            return hyp_b.category
        return None

    def create_conclusions(
        self,
        graph: EvidenceGraph,
        extension_result: ExtensionResult,
    ) -> List[EvidenceNode]:
        """Create conclusion nodes for accepted hypotheses."""
        conclusions = []

        for arg_id in extension_result.accepted:
            # arg_id is "arg_hyp_xxx", extract hypothesis id
            hyp_id = arg_id.replace("arg_", "", 1)
            hyp = graph.get_node(hyp_id)

            if not hyp:
                continue

            conclusion = EvidenceNode.create_conclusion(
                content=hyp.content,
                category=hyp.category,
                confidence=hyp.confidence,
                metadata={
                    "source_hypothesis": hyp_id,
                    "source_agent": hyp.source.value,
                },
            )
            graph.add_node(conclusion)

            # Add validation edge
            validation_edge = EvidenceEdge.create(
                edge_type=EdgeType.VALIDATION,
                source_id=hyp_id,
                target_id=conclusion.id,
            )
            graph.add_edge(validation_edge)

            conclusions.append(conclusion)

        logger.info(f"Created {len(conclusions)} conclusion nodes")
        return conclusions


@dataclass
class DebateConfig:
    """Configuration for adversarial debate."""
    max_debate_rounds: int = 2           # Max rounds per debate (reduced for performance)
    convergence_gap: float = 0.3         # Confidence gap to declare winner
    enable_cross_validation: bool = True
    cross_validation_weight: float = 0.2  # How much cross-validation affects confidence
    min_challenge_severity: float = 0.3   # Minimum severity to accept a challenge
    max_debates_per_round: int = 5       # Limit debates to control LLM calls
    min_conflict_severity: float = 0.6   # Only debate high-severity conflicts


class AdversarialCoordinator(DeliberationCoordinator):
    """Extended coordinator with true adversarial multi-round debate.

    Implements the full dialectic process:
    1. Detect conflicts between hypotheses
    2. For each conflict, run adversarial debate:
       - Antagonist challenges protagonist's hypothesis
       - Protagonist rebuts the challenge
       - Repeat until convergence or max rounds
    3. Run cross-validation phase
    4. Build AAF and compute grounded extension
    5. Create conclusions with full reasoning trace
    """

    def __init__(
        self,
        llm_client: LLMClient,
        agents: Optional[Dict[SourceType, "BaseAgent"]] = None,
        preference_config: Optional[PreferenceConfig] = None,
        debate_config: Optional[DebateConfig] = None,
        max_rounds: int = 3,
        convergence_threshold: float = 0.9,
    ):
        super().__init__(
            llm_client=llm_client,
            preference_config=preference_config,
            max_rounds=max_rounds,
            convergence_threshold=convergence_threshold,
        )
        self.agents = agents or {}
        self.debate_config = debate_config or DebateConfig()

    def set_agents(self, agents: Dict[SourceType, "BaseAgent"]) -> None:
        """Set the agent registry for adversarial debate."""
        self.agents = agents

    async def deliberate(
        self,
        graph: EvidenceGraph,
    ) -> AdversarialDeliberationResult:
        """Run the complete adversarial deliberation process."""
        result = AdversarialDeliberationResult()
        previous_extension_size = 0

        for round_num in range(1, self.max_rounds + 1):
            logger.info(f"Starting adversarial deliberation round {round_num}")

            # Step 1: Detect conflicts
            conflicts = await self.conflict_detector.detect_conflicts(graph)
            result.total_conflicts_detected += len(conflicts)
            logger.info(f"Round {round_num}: Detected {len(conflicts)} conflicts")

            # Step 2: Add conflict edges to graph
            self.conflict_detector.add_conflict_edges(graph, conflicts)

            # Step 3: Run adversarial debates for each conflict
            debated_hypothesis_ids: Set[str] = set()
            if self.agents:
                debates = await self._run_adversarial_debates(graph, conflicts, round_num)
                result.debates.extend(debates)
                result.total_debates_conducted += len(debates)

                # Collect debated hypothesis IDs and count resolved
                for debate in debates:
                    debated_hypothesis_ids.add(debate.hypothesis_a_id)
                    debated_hypothesis_ids.add(debate.hypothesis_b_id)
                    if debate.outcome and debate.outcome.convergence_reason != ConvergenceReason.MAX_ROUNDS:
                        result.total_conflicts_resolved += 1
            else:
                # Fallback to original resolution if no agents
                round_result = await self._resolve_conflicts(graph, conflicts, round_num)
                result.total_conflicts_resolved += round_result.conflicts_resolved

            # Step 4: Run cross-validation if enabled (only for debated hypotheses)
            if self.debate_config.enable_cross_validation and self.agents:
                cv_round = await self._run_cross_validation(
                    graph, round_num, debated_hypothesis_ids if debated_hypothesis_ids else None
                )
                result.cross_validations.append(cv_round)
                result.total_reasoning_nodes_created += len(cv_round.reasoning_node_ids)

            # Step 5: Build AAF and compute extension
            aaf = self._build_aaf(graph)
            extension = self.extension_solver.compute(aaf)
            logger.info(
                f"Round {round_num}: Grounded extension has {len(extension.accepted)} accepted arguments"
            )

            # Check convergence
            if len(extension.accepted) == previous_extension_size:
                logger.info(f"Converged after round {round_num}")
                break

            previous_extension_size = len(extension.accepted)

            decided_ratio = (len(extension.accepted) + len(extension.rejected)) / max(aaf.argument_count, 1)
            if decided_ratio >= self.convergence_threshold:
                logger.info(f"Reached convergence threshold ({decided_ratio:.2%} decided)")
                break

        # Extract accepted hypotheses
        aaf = self._build_aaf(graph)
        final_extension = self.extension_solver.compute(aaf)
        result.accepted_hypotheses = list(final_extension.accepted)

        # Count reasoning nodes
        result.total_reasoning_nodes_created = len(graph.get_reasoning_nodes())

        return result

    async def _run_adversarial_debates(
        self,
        graph: EvidenceGraph,
        conflicts: List[HypothesisConflict],
        round_number: int,
    ) -> List[DebateSession]:
        """Run adversarial debates for high-severity conflicts only."""
        debates = []

        # Limit debates to avoid LLM call explosion
        # Only debate high-severity conflicts
        min_severity = self.debate_config.min_conflict_severity
        high_severity_conflicts = [c for c in conflicts if c.severity >= min_severity]
        # Cap debates per round to limit LLM calls
        max_debates = self.debate_config.max_debates_per_round
        conflicts_to_debate = high_severity_conflicts[:max_debates]

        logger.info(
            f"Round {round_number}: Running {len(conflicts_to_debate)} debates "
            f"(filtered from {len(conflicts)} conflicts, {len(high_severity_conflicts)} high-severity)"
        )

        for conflict in conflicts_to_debate:
            hyp_a = graph.get_node(conflict.hypothesis_a_id)
            hyp_b = graph.get_node(conflict.hypothesis_b_id)

            if not hyp_a or not hyp_b:
                continue

            # Get agents for each hypothesis
            agent_a = self.agents.get(hyp_a.source)
            agent_b = self.agents.get(hyp_b.source)

            if not agent_a or not agent_b:
                # Fallback to LLM resolution if agents not available
                continue

            # Create debate session
            session = DebateSession(
                conflict_id=f"conflict_{uuid.uuid4().hex[:8]}",
                hypothesis_a_id=conflict.hypothesis_a_id,
                hypothesis_b_id=conflict.hypothesis_b_id,
                protagonist_source=hyp_a.source,
                antagonist_source=hyp_b.source,
                max_rounds=self.debate_config.max_debate_rounds,
                initial_confidence_a=hyp_a.confidence,
                initial_confidence_b=hyp_b.confidence,
            )

            # Run the debate
            await self._run_single_debate(session, graph, agent_a, agent_b)
            debates.append(session)

            # Apply debate outcome
            await self._apply_debate_outcome(session, graph)

        return debates

    async def _run_single_debate(
        self,
        session: DebateSession,
        graph: EvidenceGraph,
        protagonist_agent: "BaseAgent",
        antagonist_agent: "BaseAgent",
    ) -> None:
        """Run a single adversarial debate between two hypotheses."""
        hyp_a = graph.get_node(session.hypothesis_a_id)
        hyp_b = graph.get_node(session.hypothesis_b_id)

        if not hyp_a or not hyp_b:
            return

        current_conf_a = hyp_a.confidence
        current_conf_b = hyp_b.confidence

        for round_num in range(1, session.max_rounds + 1):
            logger.info(f"Debate {session.conflict_id}: Starting round {round_num}")

            # Step 1: Antagonist challenges protagonist's hypothesis
            challenge = await antagonist_agent.challenge_hypothesis(hyp_a, graph)

            if not challenge or challenge.severity < self.debate_config.min_challenge_severity:
                logger.info(f"Debate {session.conflict_id}: No significant challenge in round {round_num}")
                # If no challenge, the defender wins this round
                session.outcome = DebateOutcome(
                    winner_hypothesis_id=session.hypothesis_a_id,
                    confidence_a_final=current_conf_a,
                    confidence_b_final=current_conf_b,
                    rounds_completed=round_num,
                    convergence_reason=ConvergenceReason.CHALLENGER_WITHDRAWS,
                )
                break

            # Create REASONING node for challenge with INPUT edges
            challenge_reasoning, _ = graph.create_deliberation_link(
                hypothesis_ids=[session.hypothesis_a_id, session.hypothesis_b_id],
                reasoning_content=f"Challenge from {antagonist_agent.agent_name}: {challenge.challenge_content}",
                link_type="challenge",
                metadata={
                    "round": round_num,
                    "challenge_type": challenge.challenge_type.value,
                    "severity": challenge.severity,
                },
            )

            # Step 2: Protagonist rebuts the challenge
            rebuttal = await protagonist_agent.rebut_challenge(hyp_a, challenge, graph)

            rebuttal_reasoning = None
            if rebuttal:
                # Create REASONING node for rebuttal
                rebuttal_reasoning, _ = graph.create_deliberation_link(
                    hypothesis_ids=[session.hypothesis_a_id],
                    reasoning_content=f"Rebuttal from {protagonist_agent.agent_name}: {rebuttal.rebuttal_content}",
                    link_type="rebuttal",
                    metadata={
                        "round": round_num,
                        "accepts_modification": rebuttal.accepts_modification,
                        "confidence_adjustment": rebuttal.confidence_adjustment,
                    },
                )

                # Apply confidence adjustment
                current_conf_a = max(0.1, min(1.0, current_conf_a + rebuttal.confidence_adjustment))
                graph.update_node(hyp_a.id, confidence=current_conf_a)

                # If defender accepts modification, create refined hypothesis
                if rebuttal.accepts_modification and rebuttal.proposed_refinement:
                    refined_hyp = EvidenceNode.create_hypothesis(
                        content=rebuttal.proposed_refinement,
                        source=hyp_a.source,
                        category=hyp_a.category,
                        confidence=current_conf_a,
                        metadata={
                            "refined_from": hyp_a.id,
                            "debate_round": round_num,
                        },
                    )
                    graph.add_node(refined_hyp)

                    # Create MODIFICATION edge
                    graph.create_modification_link(
                        reasoning_id=rebuttal_reasoning.id,
                        target_hypothesis_id=refined_hyp.id,
                        modification_type="refinement",
                    )

                    # Record refinement in debate round
                    debate_round = DebateRound(
                        round_number=round_num,
                        challenge=challenge,
                        rebuttal=rebuttal,
                        refinement=refined_hyp,
                        challenge_reasoning_node_id=challenge_reasoning.id,
                        rebuttal_reasoning_node_id=rebuttal_reasoning.id,
                    )
                    session.add_round(debate_round)

                    # Defender concedes partially
                    session.outcome = DebateOutcome(
                        winner_hypothesis_id=None,  # Partial concession
                        confidence_a_final=current_conf_a,
                        confidence_b_final=current_conf_b,
                        merged_hypothesis=refined_hyp,
                        rounds_completed=round_num,
                        convergence_reason=ConvergenceReason.MUTUAL_REFINEMENT,
                    )
                    break

            # Record debate round
            debate_round = DebateRound(
                round_number=round_num,
                challenge=challenge,
                rebuttal=rebuttal,
                challenge_reasoning_node_id=challenge_reasoning.id,
                rebuttal_reasoning_node_id=rebuttal_reasoning.id if rebuttal_reasoning else None,
            )
            session.add_round(debate_round)

            # Check for convergence based on confidence gap
            conf_gap = abs(current_conf_a - current_conf_b)
            if conf_gap >= self.debate_config.convergence_gap:
                winner_id = session.hypothesis_a_id if current_conf_a > current_conf_b else session.hypothesis_b_id
                session.outcome = DebateOutcome(
                    winner_hypothesis_id=winner_id,
                    confidence_a_final=current_conf_a,
                    confidence_b_final=current_conf_b,
                    rounds_completed=round_num,
                    convergence_reason=ConvergenceReason.CONFIDENCE_GAP,
                )
                break

        # If no outcome yet, set based on final state
        if not session.outcome:
            winner_id = None
            if current_conf_a > current_conf_b + 0.1:
                winner_id = session.hypothesis_a_id
            elif current_conf_b > current_conf_a + 0.1:
                winner_id = session.hypothesis_b_id

            session.outcome = DebateOutcome(
                winner_hypothesis_id=winner_id,
                confidence_a_final=current_conf_a,
                confidence_b_final=current_conf_b,
                rounds_completed=session.current_round,
                convergence_reason=ConvergenceReason.MAX_ROUNDS,
            )

    async def _apply_debate_outcome(
        self,
        session: DebateSession,
        graph: EvidenceGraph,
    ) -> None:
        """Apply the outcome of a debate to the graph."""
        if not session.outcome:
            return

        outcome = session.outcome

        # Update confidences
        hyp_a = graph.get_node(session.hypothesis_a_id)
        hyp_b = graph.get_node(session.hypothesis_b_id)

        if hyp_a:
            graph.update_node(hyp_a.id, confidence=outcome.confidence_a_final)
        if hyp_b:
            graph.update_node(hyp_b.id, confidence=outcome.confidence_b_final)

        # Create outcome REASONING node
        outcome_content = f"Debate outcome: {outcome.convergence_reason.value}"
        if outcome.winner_hypothesis_id:
            outcome_content += f". Winner: {outcome.winner_hypothesis_id}"

        outcome_reasoning, _ = graph.create_deliberation_link(
            hypothesis_ids=[session.hypothesis_a_id, session.hypothesis_b_id],
            reasoning_content=outcome_content,
            link_type="debate_outcome",
            metadata={
                "rounds_completed": outcome.rounds_completed,
                "convergence_reason": outcome.convergence_reason.value,
                "winner": outcome.winner_hypothesis_id,
            },
        )

        # If there's a merged hypothesis, link it
        if outcome.merged_hypothesis:
            graph.create_modification_link(
                reasoning_id=outcome_reasoning.id,
                target_hypothesis_id=outcome.merged_hypothesis.id,
                modification_type="merge_result",
            )

    async def _run_cross_validation(
        self,
        graph: EvidenceGraph,
        round_number: int,
        debated_hypothesis_ids: Optional[Set[str]] = None,
    ) -> CrossValidationRound:
        """Run cross-validation phase where all agents validate hypotheses.

        Args:
            graph: Evidence graph
            round_number: Current deliberation round
            debated_hypothesis_ids: If provided, only validate these hypotheses (optimization)
        """
        cv_round = CrossValidationRound(round_number=round_number)

        # Get hypotheses to validate
        all_hypotheses = graph.get_hypotheses()

        # Optimization: only validate hypotheses involved in debates
        if debated_hypothesis_ids:
            hypotheses_to_validate = [h for h in all_hypotheses if h.id in debated_hypothesis_ids]
            logger.info(f"Cross-validation limited to {len(hypotheses_to_validate)} debated hypotheses")
        else:
            hypotheses_to_validate = all_hypotheses

        for source_type, agent in self.agents.items():
            # Get hypotheses from OTHER agents (using filtered list)
            other_hypotheses = [h for h in hypotheses_to_validate if h.source != source_type]

            if not other_hypotheses:
                continue

            # Run cross-validation
            validations = await agent.cross_validate(other_hypotheses, graph)

            for validation in validations:
                cv_round.validations.append(validation)

                # Apply confidence modifier
                hyp = graph.get_node(validation.hypothesis_id)
                if hyp:
                    new_conf = hyp.confidence + (
                        validation.confidence_modifier * self.debate_config.cross_validation_weight
                    )
                    new_conf = max(0.1, min(1.0, new_conf))
                    graph.update_node(hyp.id, confidence=new_conf)

                    # Create REASONING node for validation
                    reasoning, _ = graph.create_deliberation_link(
                        hypothesis_ids=[validation.hypothesis_id],
                        reasoning_content=f"Cross-validation by {agent.agent_name}: {validation.verdict.value} - {validation.reasoning}",
                        link_type="cross_validation",
                        metadata={
                            "validator": validation.validator_source.value,
                            "verdict": validation.verdict.value,
                            "confidence_modifier": validation.confidence_modifier,
                        },
                    )
                    cv_round.reasoning_node_ids.append(reasoning.id)

        logger.info(f"Cross-validation round {round_number}: {len(cv_round.validations)} validations")
        return cv_round

    def create_conclusions(
        self,
        graph: EvidenceGraph,
        extension_result: ExtensionResult,
    ) -> List[EvidenceNode]:
        """Create conclusion nodes with proper VALIDATION edges and REASONING trace."""
        conclusions = []

        for arg_id in extension_result.accepted:
            hyp_id = arg_id.replace("arg_", "", 1)
            hyp = graph.get_node(hyp_id)

            if not hyp:
                continue

            # Create conclusion
            conclusion = EvidenceNode.create_conclusion(
                content=hyp.content,
                category=hyp.category,
                confidence=hyp.confidence,
                metadata={
                    "source_hypothesis": hyp_id,
                    "source_agent": hyp.source.value,
                    "deliberation_trace": graph.get_deliberation_trace(hyp_id),
                },
            )
            graph.add_node(conclusion)

            # Create REASONING node for acceptance
            acceptance_reasoning, _ = graph.create_deliberation_link(
                hypothesis_ids=[hyp_id],
                reasoning_content=f"Hypothesis accepted into grounded extension with confidence {hyp.confidence:.2f}",
                link_type="acceptance",
                metadata={"final_confidence": hyp.confidence},
            )

            # Create VALIDATION edge
            validation_edge = EvidenceEdge.create(
                edge_type=EdgeType.VALIDATION,
                source_id=hyp_id,
                target_id=conclusion.id,
            )
            graph.add_edge(validation_edge)

            conclusions.append(conclusion)

        logger.info(f"Created {len(conclusions)} conclusion nodes with reasoning traces")
        return conclusions
