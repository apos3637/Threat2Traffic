"""Static analysis agent for Stage I."""

from typing import Any, Dict

from .base_agent import BaseAgent
from .prompts import STATIC_ANALYSIS_PROMPT, STATIC_HYPOTHESIS_PROMPT
from ..evidence_graph.models import SourceType


class StaticAnalysisAgent(BaseAgent):
    """Agent for static analysis of malware samples.

    Analyzes PE headers, imports, strings, and other static artifacts
    to extract environment requirements.
    """

    agent_name = "StaticAnalysisAgent"
    source_type = SourceType.AGENT_STATIC

    def get_analysis_prompt(self) -> str:
        return STATIC_ANALYSIS_PROMPT

    def get_hypothesis_prompt(self) -> str:
        return STATIC_HYPOTHESIS_PROMPT
