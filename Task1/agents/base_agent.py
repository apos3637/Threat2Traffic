"""Base agent class for Stage I analysis."""

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from ..evidence_graph.models import (
    NodeType,
    EdgeType,
    EvidenceNode,
    EvidenceEdge,
    SourceType,
    ConstraintCategory,
)
from ..evidence_graph.graph import EvidenceGraph
from ..deliberation.models import (
    ChallengeType,
    ChallengeResult,
    RebuttalResult,
    ValidationResult,
    DebateVerdict,
)
from ..utils.llm_client import LLMClient
from ..utils.logger import get_logger
from .prompts import (
    CHALLENGE_HYPOTHESIS_PROMPT,
    REBUTTAL_PROMPT,
    CROSS_VALIDATION_PROMPT,
    REFINEMENT_SYNTHESIS_PROMPT,
)


class BaseAgent(ABC):
    """Base class for analysis agents in Stage I."""

    agent_name: str
    source_type: SourceType

    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client
        self.logger = get_logger(self.agent_name)

    @abstractmethod
    def get_analysis_prompt(self) -> str:
        """Get the prompt template for analysis."""
        pass

    @abstractmethod
    def get_hypothesis_prompt(self) -> str:
        """Get the prompt for generating environment hypotheses."""
        pass

    async def analyze(
        self,
        input_data: Dict[str, Any],
        graph: EvidenceGraph,
    ) -> Tuple[List[EvidenceNode], List[EvidenceNode]]:
        """Analyze input data and add evidence to the graph.

        Returns:
            Tuple of (observation_nodes, hypothesis_nodes)
        """
        self.logger.info("Starting analysis")

        prompt = self.get_analysis_prompt().format(
            input_data=json.dumps(input_data, indent=2, ensure_ascii=False)
        )

        try:
            result = await self.llm_client.chat_json([
                {"role": "system", "content": f"You are {self.agent_name}, an expert malware analyst."},
                {"role": "user", "content": prompt},
            ])

            observations = self._extract_observations(result, graph)
            hypotheses = await self._generate_hypotheses(result, observations, graph)

            self.logger.info(
                f"Analysis complete: {len(observations)} observations, "
                f"{len(hypotheses)} hypotheses"
            )

            return observations, hypotheses

        except Exception as e:
            self.logger.error(f"Analysis failed: {type(e).__name__}: {e}")
            raise

    def _extract_observations(
        self,
        result: Dict[str, Any],
        graph: EvidenceGraph,
    ) -> List[EvidenceNode]:
        """Extract observations from LLM analysis result."""
        observations = []

        for obs_data in result.get("observations", []):
            category = self._parse_category(obs_data.get("category"))

            node = EvidenceNode.create_observation(
                content=obs_data.get("content", ""),
                source=self.source_type,
                category=category,
                metadata={
                    "raw_data": obs_data.get("raw_data"),
                    "evidence_type": obs_data.get("evidence_type"),
                },
            )

            graph.add_node(node)
            observations.append(node)

        return observations

    async def _generate_hypotheses(
        self,
        analysis_result: Dict[str, Any],
        observations: List[EvidenceNode],
        graph: EvidenceGraph,
    ) -> List[EvidenceNode]:
        """Generate environment hypotheses based on observations."""
        obs_summary = "\n".join([
            f"- [{obs.category.value if obs.category else 'general'}] {obs.content}"
            for obs in observations
        ])

        prompt = self.get_hypothesis_prompt().format(
            observations=obs_summary,
            analysis_summary=json.dumps(analysis_result, indent=2, ensure_ascii=False),
        )

        try:
            result = await self.llm_client.chat_json([
                {"role": "system", "content": f"You are {self.agent_name}, generating environment hypotheses."},
                {"role": "user", "content": prompt},
            ])

            hypotheses = []
            for hyp_data in result.get("hypotheses", []):
                category = self._parse_category(hyp_data.get("category"))
                confidence = float(hyp_data.get("confidence", 0.5))

                node = EvidenceNode.create_hypothesis(
                    content=hyp_data.get("content", ""),
                    source=self.source_type,
                    category=category,
                    confidence=confidence,
                    metadata={
                        "reasoning": hyp_data.get("reasoning"),
                        "supporting_observations": hyp_data.get("supporting_observations", []),
                    },
                )

                graph.add_node(node)
                hypotheses.append(node)

                # Link supporting observations
                for obs in observations:
                    if self._observation_supports_hypothesis(obs, hyp_data):
                        edge = EvidenceEdge.create(
                            edge_type=EdgeType.SUPPORTS,
                            source_id=obs.id,
                            target_id=node.id,
                        )
                        graph.add_edge(edge)

            return hypotheses

        except Exception as e:
            self.logger.error(f"Hypothesis generation failed: {e}")
            return []

    def _observation_supports_hypothesis(
        self,
        observation: EvidenceNode,
        hypothesis_data: Dict[str, Any],
    ) -> bool:
        """Check if an observation supports a hypothesis."""
        supporting_ids = hypothesis_data.get("supporting_observations", [])
        if observation.id in supporting_ids:
            return True

        # Category matching as fallback
        hyp_category = self._parse_category(hypothesis_data.get("category"))
        return observation.category == hyp_category

    def _parse_category(self, category_str: Optional[str]) -> Optional[ConstraintCategory]:
        """Parse category string to ConstraintCategory enum."""
        if not category_str:
            return None
        try:
            return ConstraintCategory(category_str)
        except ValueError:
            # Map common variations
            category_map = {
                "os": ConstraintCategory.OS_VERSION,
                "windows": ConstraintCategory.OS_VERSION,
                "linux": ConstraintCategory.OS_VERSION,
                "arch": ConstraintCategory.OS_ARCHITECTURE,
                "architecture": ConstraintCategory.OS_ARCHITECTURE,
                "software": ConstraintCategory.SOFTWARE_DEPENDENCY,
                "dependency": ConstraintCategory.SOFTWARE_DEPENDENCY,
                "runtime": ConstraintCategory.RUNTIME_DEPENDENCY,
                "network": ConstraintCategory.NETWORK_PROTOCOL,
                "protocol": ConstraintCategory.NETWORK_PROTOCOL,
                "port": ConstraintCategory.NETWORK_PORT,
                "domain": ConstraintCategory.NETWORK_DOMAIN,
                "ip": ConstraintCategory.NETWORK_IP,
                "cpu": ConstraintCategory.HARDWARE_CPU,
                "memory": ConstraintCategory.HARDWARE_MEMORY,
                "disk": ConstraintCategory.HARDWARE_DISK,
                "file": ConstraintCategory.FILE_SYSTEM,
                "registry": ConstraintCategory.REGISTRY,
                "permission": ConstraintCategory.PERMISSION,
                "anti_analysis": ConstraintCategory.ANTI_ANALYSIS,
                "evasion": ConstraintCategory.ANTI_ANALYSIS,
            }
            return category_map.get(category_str.lower())

    def _parse_confidence(self, confidence_str: str) -> float:
        """Parse confidence level to float."""
        confidence_map = {
            "high": 0.9,
            "medium": 0.6,
            "low": 0.3,
            "very_high": 0.95,
            "very_low": 0.1,
        }
        if isinstance(confidence_str, (int, float)):
            return float(confidence_str)
        return confidence_map.get(confidence_str.lower(), 0.5)

    # ===== Adversarial Debate Methods =====

    def get_domain_description(self) -> str:
        """Get a description of this agent's domain expertise."""
        domain_map = {
            SourceType.AGENT_STATIC: "static malware analysis including PE headers, imports, strings, and binary structure",
            SourceType.AGENT_BEHAVIOR: "dynamic behavior analysis including sandbox execution, network activity, and system interactions",
            SourceType.AGENT_THREAT: "threat intelligence including malware family identification, MITRE ATT&CK mapping, and known indicators",
        }
        return domain_map.get(self.source_type, "malware analysis")

    def get_observations_from_graph(self, graph: EvidenceGraph) -> List[EvidenceNode]:
        """Get this agent's observations from the graph."""
        all_obs = graph.get_observations()
        return [obs for obs in all_obs if obs.source == self.source_type]

    def get_hypotheses_from_graph(self, graph: EvidenceGraph) -> List[EvidenceNode]:
        """Get this agent's hypotheses from the graph."""
        all_hyps = graph.get_hypotheses()
        return [hyp for hyp in all_hyps if hyp.source == self.source_type]

    async def challenge_hypothesis(
        self,
        hypothesis: EvidenceNode,
        graph: EvidenceGraph,
    ) -> Optional[ChallengeResult]:
        """Challenge another agent's hypothesis from this agent's perspective.

        Args:
            hypothesis: The hypothesis to challenge (from another agent)
            graph: The evidence graph

        Returns:
            ChallengeResult if a valid challenge is found, None otherwise
        """
        # Don't challenge own hypotheses
        if hypothesis.source == self.source_type:
            return None

        self.logger.info(f"Challenging hypothesis {hypothesis.id}")

        # Get this agent's observations
        my_observations = self.get_observations_from_graph(graph)
        if not my_observations:
            return None

        # Get supporting evidence for the target hypothesis
        supporting_obs = graph.get_supporting_observations(hypothesis.id)
        supporting_evidence = "\n".join([
            f"- [{obs.source.value}] {obs.content}"
            for obs in supporting_obs
        ]) if supporting_obs else "No direct supporting observations"

        # Format my observations
        my_obs_text = "\n".join([
            f"- [ID: {obs.id}] {obs.content}"
            for obs in my_observations
        ])

        prompt = CHALLENGE_HYPOTHESIS_PROMPT.format(
            agent_name=self.agent_name,
            domain=self.get_domain_description(),
            hypothesis_id=hypothesis.id,
            hypothesis_source=hypothesis.source.value,
            hypothesis_content=hypothesis.content,
            hypothesis_confidence=hypothesis.confidence,
            hypothesis_category=hypothesis.category.value if hypothesis.category else "general",
            supporting_evidence=supporting_evidence,
            your_observations=my_obs_text,
        )

        try:
            result = await self.llm_client.chat_json([
                {"role": "system", "content": f"You are {self.agent_name}, challenging another agent's hypothesis."},
                {"role": "user", "content": prompt},
            ])

            # Parse challenge type
            challenge_type_str = result.get("challenge_type", "insufficient_support")
            try:
                challenge_type = ChallengeType(challenge_type_str)
            except ValueError:
                challenge_type = ChallengeType.INSUFFICIENT_SUPPORT

            # Only return challenge if severity is significant
            severity = float(result.get("severity", 0.0))
            if severity < 0.3:
                self.logger.info(f"Challenge too weak (severity={severity}), not challenging")
                return None

            return ChallengeResult(
                challenger_source=self.source_type,
                target_hypothesis_id=hypothesis.id,
                challenge_type=challenge_type,
                challenge_content=result.get("challenge_content", ""),
                counter_evidence=result.get("counter_evidence", []),
                severity=severity,
                suggested_modification=result.get("suggested_modification"),
                reasoning=result.get("reasoning"),
            )

        except Exception as e:
            self.logger.error(f"Challenge generation failed: {e}")
            return None

    async def rebut_challenge(
        self,
        hypothesis: EvidenceNode,
        challenge: ChallengeResult,
        graph: EvidenceGraph,
    ) -> Optional[RebuttalResult]:
        """Defend own hypothesis against a challenge.

        Args:
            hypothesis: The hypothesis being defended (must be this agent's)
            challenge: The challenge to rebut
            graph: The evidence graph

        Returns:
            RebuttalResult with defense and potential refinement
        """
        # Only defend own hypotheses
        if hypothesis.source != self.source_type:
            self.logger.warning(f"Cannot rebut challenge to hypothesis from {hypothesis.source}")
            return None

        self.logger.info(f"Rebutting challenge to hypothesis {hypothesis.id}")

        # Get supporting evidence
        supporting_obs = graph.get_supporting_observations(hypothesis.id)
        my_evidence = "\n".join([
            f"- [ID: {obs.id}] {obs.content}"
            for obs in supporting_obs
        ]) if supporting_obs else "No direct supporting observations"

        # Get challenger info
        challenger_name_map = {
            SourceType.AGENT_STATIC: "StaticAnalysisAgent",
            SourceType.AGENT_BEHAVIOR: "BehaviorAnalysisAgent",
            SourceType.AGENT_THREAT: "ThreatIntelAgent",
        }
        challenger_name = challenger_name_map.get(challenge.challenger_source, "Unknown Agent")

        prompt = REBUTTAL_PROMPT.format(
            agent_name=self.agent_name,
            hypothesis_id=hypothesis.id,
            hypothesis_content=hypothesis.content,
            hypothesis_confidence=hypothesis.confidence,
            challenger_name=challenger_name,
            challenge_type=challenge.challenge_type.value,
            challenge_content=challenge.challenge_content,
            counter_evidence=", ".join(challenge.counter_evidence) if challenge.counter_evidence else "None cited",
            challenge_severity=challenge.severity,
            suggested_modification=challenge.suggested_modification or "Reject hypothesis",
            your_evidence=my_evidence,
        )

        try:
            result = await self.llm_client.chat_json([
                {"role": "system", "content": f"You are {self.agent_name}, defending your hypothesis."},
                {"role": "user", "content": prompt},
            ])

            confidence_adj = float(result.get("confidence_adjustment", 0.0))
            # Clamp confidence adjustment
            confidence_adj = max(-0.5, min(0.5, confidence_adj))

            return RebuttalResult(
                defender_source=self.source_type,
                hypothesis_id=hypothesis.id,
                rebuttal_content=result.get("rebuttal_content", ""),
                supporting_evidence=result.get("supporting_evidence", []),
                accepts_modification=result.get("accepts_modification", False),
                proposed_refinement=result.get("proposed_refinement"),
                confidence_adjustment=confidence_adj,
                reasoning=result.get("reasoning"),
            )

        except Exception as e:
            self.logger.error(f"Rebuttal generation failed: {e}")
            return None

    async def cross_validate(
        self,
        hypotheses: List[EvidenceNode],
        graph: EvidenceGraph,
    ) -> List[ValidationResult]:
        """Cross-validate other agents' hypotheses from this agent's perspective.

        Args:
            hypotheses: List of hypotheses to validate (typically from other agents)
            graph: The evidence graph

        Returns:
            List of ValidationResult for each hypothesis
        """
        # Filter out own hypotheses
        other_hypotheses = [h for h in hypotheses if h.source != self.source_type]
        if not other_hypotheses:
            return []

        self.logger.info(f"Cross-validating {len(other_hypotheses)} hypotheses")

        # Get this agent's observations
        my_observations = self.get_observations_from_graph(graph)
        if not my_observations:
            return []

        # Format observations
        my_obs_text = "\n".join([
            f"- [ID: {obs.id}] ({obs.category.value if obs.category else 'general'}) {obs.content}"
            for obs in my_observations
        ])

        # Format hypotheses to validate
        hyps_text = "\n\n".join([
            f"### Hypothesis {i+1}\n"
            f"- **ID**: {h.id}\n"
            f"- **Source**: {h.source.value}\n"
            f"- **Category**: {h.category.value if h.category else 'general'}\n"
            f"- **Content**: {h.content}\n"
            f"- **Confidence**: {h.confidence}"
            for i, h in enumerate(other_hypotheses)
        ])

        prompt = CROSS_VALIDATION_PROMPT.format(
            agent_name=self.agent_name,
            domain_description=self.get_domain_description(),
            your_observations=my_obs_text,
            hypotheses_to_validate=hyps_text,
        )

        try:
            result = await self.llm_client.chat_json([
                {"role": "system", "content": f"You are {self.agent_name}, cross-validating hypotheses."},
                {"role": "user", "content": prompt},
            ])

            validations = []
            for val_data in result.get("validations", []):
                verdict_str = val_data.get("verdict", "neutral")
                try:
                    verdict = DebateVerdict(verdict_str)
                except ValueError:
                    verdict = DebateVerdict.NEUTRAL

                conf_mod = float(val_data.get("confidence_modifier", 0.0))
                conf_mod = max(-0.3, min(0.3, conf_mod))

                validations.append(ValidationResult(
                    validator_source=self.source_type,
                    hypothesis_id=val_data.get("hypothesis_id", ""),
                    verdict=verdict,
                    reasoning=val_data.get("reasoning", ""),
                    confidence_modifier=conf_mod,
                    relevant_observations=val_data.get("relevant_observations", []),
                ))

            return validations

        except Exception as e:
            self.logger.error(f"Cross-validation failed: {e}")
            return []
