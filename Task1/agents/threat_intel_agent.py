"""Threat intelligence agent for Stage I."""

from typing import Any, Dict

from .base_agent import BaseAgent
from .prompts import THREAT_INTEL_PROMPT, THREAT_INTEL_HYPOTHESIS_PROMPT
from ..evidence_graph.models import SourceType


class ThreatIntelAgent(BaseAgent):
    """Agent for threat intelligence analysis.

    Analyzes VT verdicts, YARA rules, malware family information,
    and MITRE ATT&CK mappings.
    """

    agent_name = "ThreatIntelAgent"
    source_type = SourceType.AGENT_THREAT

    def get_analysis_prompt(self) -> str:
        return THREAT_INTEL_PROMPT

    def get_hypothesis_prompt(self) -> str:
        return THREAT_INTEL_HYPOTHESIS_PROMPT
