"""Behavior analysis agent for Stage I."""

from typing import Any, Dict

from .base_agent import BaseAgent
from .prompts import BEHAVIOR_ANALYSIS_PROMPT, BEHAVIOR_HYPOTHESIS_PROMPT
from ..evidence_graph.models import SourceType


class BehaviorAnalysisAgent(BaseAgent):
    """Agent for dynamic behavior analysis.

    Analyzes sandbox execution data to extract network, file system,
    and system interaction requirements.
    """

    agent_name = "BehaviorAnalysisAgent"
    source_type = SourceType.AGENT_BEHAVIOR

    def get_analysis_prompt(self) -> str:
        return BEHAVIOR_ANALYSIS_PROMPT

    def get_hypothesis_prompt(self) -> str:
        return BEHAVIOR_HYPOTHESIS_PROMPT
