"""Stage I Orchestrator: Dialectic Intent Arbitration main entry point."""

import asyncio
import time
from typing import Any, Dict, Optional
from pathlib import Path
from datetime import datetime

from .config import Config, get_config
from .vt_client.client import VTClient
from .vt_client.parser import VTReportParser, ParsedVTReport
from .utils.llm_client import LLMClient
from .utils.logger import get_logger, get_task_logger
from .evidence_graph.graph import EvidenceGraph
from .evidence_graph.models import EvidenceNode, SourceType
from .argumentation.preference import PreferenceCalculator, PreferenceConfig
from .deliberation.coordinator import DeliberationCoordinator, AdversarialCoordinator, DebateConfig
from .agents import StaticAnalysisAgent, BehaviorAnalysisAgent, ThreatIntelAgent
from .evidence_graph.models import SourceType
from .spec_extractor.extractor import SpecificationExtractor
from .spec_extractor.mitre_mapper import MITREMapper
from .spec_extractor.models import EnvironmentSpecification

logger = get_logger("orchestrator")


class Stage1Orchestrator:
    """Orchestrates Stage I: Dialectic Intent Arbitration.

    Pipeline:
    1. Fetch VT report for sample hash
    2. Run parallel agent analysis (static, behavior, threat intel)
    3. Build Evidence Graph with observations and hypotheses
    4. Run adversarial deliberation to resolve conflicts
    5. Compute grounded extension to accept hypotheses
    6. Extract environment specification from conclusions
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self.vt_client = VTClient(self.config.vt)
        self.llm_client = LLMClient(self.config.llm)
        self.parser = VTReportParser()

        # Initialize agents
        self.static_agent = StaticAnalysisAgent(self.llm_client)
        self.behavior_agent = BehaviorAnalysisAgent(self.llm_client)
        self.threat_intel_agent = ThreatIntelAgent(self.llm_client)

        # Create agent registry for adversarial debate
        self.agent_registry: Dict[SourceType, Any] = {
            SourceType.AGENT_STATIC: self.static_agent,
            SourceType.AGENT_BEHAVIOR: self.behavior_agent,
            SourceType.AGENT_THREAT: self.threat_intel_agent,
        }

        # Initialize components
        self.preference_config = PreferenceConfig(
            alpha=self.config.aaf.alpha,
            beta=self.config.aaf.beta,
        )

        # Choose coordinator based on config
        if self.config.deliberation.use_adversarial_mode:
            debate_config = DebateConfig(
                max_debate_rounds=self.config.deliberation.debate_rounds,
                convergence_gap=self.config.deliberation.debate_convergence_gap,
                enable_cross_validation=self.config.deliberation.enable_cross_validation,
                cross_validation_weight=self.config.deliberation.cross_validation_weight,
                min_challenge_severity=self.config.deliberation.min_challenge_severity,
                max_debates_per_round=self.config.deliberation.max_debates_per_round,
                min_conflict_severity=self.config.deliberation.min_conflict_severity,
            )
            self.deliberation_coordinator = AdversarialCoordinator(
                llm_client=self.llm_client,
                agents=self.agent_registry,
                preference_config=self.preference_config,
                debate_config=debate_config,
                max_rounds=self.config.deliberation.max_rounds,
                convergence_threshold=self.config.deliberation.convergence_threshold,
            )
            logger.info("Using AdversarialCoordinator for dialectic deliberation")
        else:
            self.deliberation_coordinator = DeliberationCoordinator(
                llm_client=self.llm_client,
                preference_config=self.preference_config,
                max_rounds=self.config.deliberation.max_rounds,
                convergence_threshold=self.config.deliberation.convergence_threshold,
            )
            logger.info("Using basic DeliberationCoordinator")

        self.spec_extractor = SpecificationExtractor()
        self.mitre_mapper = MITREMapper()

    async def analyze(self, sample_hash: str) -> EnvironmentSpecification:
        """Run complete Stage I analysis on a sample.

        Args:
            sample_hash: SHA256 hash of the malware sample

        Returns:
            EnvironmentSpecification containing extracted requirements
        """
        start_time = time.time()
        task_logger = get_task_logger(f"stage1_{sample_hash[:8]}", self.config.log_dir)
        task_logger.info(f"Starting Stage I analysis for {sample_hash}")

        try:
            # Step 1: Fetch VT report
            task_logger.info("Step 1: Fetching VirusTotal report")
            vt_report = await self._fetch_vt_report(sample_hash)
            parsed_report = self.parser.parse(vt_report)
            task_logger.info(f"VT report parsed: {len(parsed_report.behavior_info)} sandbox reports")

            # Step 2: Initialize Evidence Graph
            task_logger.info("Step 2: Initializing Evidence Graph")
            graph = EvidenceGraph()

            # Step 3: Run parallel agent analysis
            task_logger.info("Step 3: Running agent analysis")
            await self._run_agent_analysis(parsed_report, graph, task_logger)

            # Step 4: Run deliberation
            task_logger.info("Step 4: Running adversarial deliberation")
            deliberation_result = await self.deliberation_coordinator.deliberate(graph)

            # Log results based on coordinator type
            if self.config.deliberation.use_adversarial_mode:
                task_logger.info(
                    f"Deliberation complete: {deliberation_result.total_debates_conducted} debates, "
                    f"{deliberation_result.total_conflicts_resolved} conflicts resolved, "
                    f"{deliberation_result.total_reasoning_nodes_created} reasoning nodes"
                )
            else:
                task_logger.info(
                    f"Deliberation complete: {len(deliberation_result.rounds)} rounds, "
                    f"{deliberation_result.total_conflicts_resolved} conflicts resolved"
                )

            # Step 5: Create conclusions from grounded extension
            task_logger.info("Step 5: Creating conclusions from grounded extension")
            # Both coordinator types support create_conclusions
            # We need to create an ExtensionResult-like object for AdversarialCoordinator
            from .argumentation.models import ExtensionResult

            if hasattr(deliberation_result, 'accepted_hypotheses') and deliberation_result.accepted_hypotheses:
                # Create a mock ExtensionResult from accepted_hypotheses
                extension = ExtensionResult(
                    accepted=set(deliberation_result.accepted_hypotheses),
                    rejected=set(),
                    undecided=set(),
                    iterations=0,
                )
                conclusions = self.deliberation_coordinator.create_conclusions(graph, extension)
                task_logger.info(f"Created {len(conclusions)} conclusions")
            elif hasattr(deliberation_result, 'final_extension') and deliberation_result.final_extension:
                conclusions = self.deliberation_coordinator.create_conclusions(
                    graph, deliberation_result.final_extension
                )
                task_logger.info(f"Created {len(conclusions)} conclusions")

            # Step 6: Extract MITRE mappings
            task_logger.info("Step 6: Extracting MITRE ATT&CK mappings")
            mitre_mappings = self.mitre_mapper.map_from_vt_report(parsed_report)
            behavior_mappings = self.mitre_mapper.map_from_behaviors(parsed_report.behavior_info)
            all_mappings = self._merge_mitre_mappings(mitre_mappings, behavior_mappings)
            task_logger.info(f"Extracted {len(all_mappings)} MITRE techniques")

            # Step 7: Build attack chain and threat profile
            attack_chain = self.mitre_mapper.build_attack_chain(all_mappings)
            threat_profile = self.mitre_mapper.infer_threat_profile(all_mappings, parsed_report)

            # Step 8: Extract environment specification
            task_logger.info("Step 7: Extracting environment specification")
            # Handle different result types
            if hasattr(deliberation_result, 'debates'):
                # AdversarialDeliberationResult
                deliberation_rounds = len(deliberation_result.debates)
            else:
                # Basic DeliberationResult
                deliberation_rounds = len(deliberation_result.rounds)

            spec = self.spec_extractor.extract(
                graph=graph,
                sample_hash=sample_hash,
                deliberation_rounds=deliberation_rounds,
                conflicts_resolved=deliberation_result.total_conflicts_resolved,
            )

            # Add MITRE and threat data
            spec.mitre_mapping = all_mappings
            spec.attack_chain = attack_chain
            spec.threat_profile = threat_profile

            # Record duration
            spec.analysis_duration_seconds = time.time() - start_time
            task_logger.info(f"Analysis complete in {spec.analysis_duration_seconds:.1f}s")

            # Save outputs
            await self._save_outputs(sample_hash, spec, graph)

            return spec

        except Exception as e:
            task_logger.error(f"Analysis failed: {type(e).__name__}: {e}")
            raise

        finally:
            await self._cleanup()

    async def _fetch_vt_report(self, sample_hash: str) -> Dict[str, Any]:
        """Fetch complete VT report."""
        async with self.vt_client:
            return await self.vt_client.get_full_report(sample_hash)

    async def _run_agent_analysis(
        self,
        parsed_report: ParsedVTReport,
        graph: EvidenceGraph,
        task_logger,
    ) -> None:
        """Run all agents in parallel."""
        # Prepare input data for each agent
        static_data = self.parser.extract_static_for_agent(parsed_report)
        behavior_data = self.parser.extract_behavior_for_agent(parsed_report)
        threat_intel_data = self.parser.extract_threat_intel_for_agent(parsed_report)

        # Run agents in parallel
        results = await asyncio.gather(
            self.static_agent.analyze(static_data, graph),
            self.behavior_agent.analyze(behavior_data, graph),
            self.threat_intel_agent.analyze(threat_intel_data, graph),
            return_exceptions=True,
        )

        # Log results
        for i, (agent_name, result) in enumerate([
            ("Static", results[0]),
            ("Behavior", results[1]),
            ("ThreatIntel", results[2]),
        ]):
            if isinstance(result, Exception):
                task_logger.error(f"{agent_name} agent failed: {result}")
            else:
                obs, hyps = result
                task_logger.info(f"{agent_name} agent: {len(obs)} observations, {len(hyps)} hypotheses")

    def _merge_mitre_mappings(
        self,
        mappings1: list,
        mappings2: list,
    ) -> list:
        """Merge MITRE mappings, deduplicating by technique ID."""
        seen = set()
        merged = []

        for m in mappings1 + mappings2:
            if m.technique_id not in seen:
                seen.add(m.technique_id)
                merged.append(m)

        return merged

    async def _save_outputs(
        self,
        sample_hash: str,
        spec: EnvironmentSpecification,
        graph: EvidenceGraph,
    ) -> None:
        """Save analysis outputs to files."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{sample_hash[:16]}_{timestamp}"

        # Save specification JSON
        spec_path = self.config.output_dir / f"{base_name}_spec.json"
        spec.save(str(spec_path))
        logger.info(f"Saved specification to {spec_path}")

        # Save graph JSON
        graph_path = self.config.output_dir / f"{base_name}_graph.json"
        with open(graph_path, 'w') as f:
            f.write(graph.to_json())
        logger.info(f"Saved evidence graph to {graph_path}")

    async def _cleanup(self) -> None:
        """Clean up resources."""
        await self.llm_client.close()


async def analyze_sample(sample_hash: str, config: Optional[Config] = None) -> EnvironmentSpecification:
    """Convenience function to analyze a sample.

    Args:
        sample_hash: SHA256 hash of the sample
        config: Optional configuration (uses default if not provided)

    Returns:
        EnvironmentSpecification with analysis results
    """
    orchestrator = Stage1Orchestrator(config)
    return await orchestrator.analyze(sample_hash)
