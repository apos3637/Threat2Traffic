"""Preference function for hypothesis ranking in AAF.

Implements: π(h) = α·Conf(h) + β·Support(h)
where α = 0.7, β = 0.3 (default)
"""

from typing import List, Optional
from dataclasses import dataclass

from .models import Argument, ArgumentationFramework
from ..evidence_graph.graph import EvidenceGraph
from ..evidence_graph.models import EvidenceNode, NodeType


@dataclass
class PreferenceConfig:
    """Configuration for preference calculation."""
    alpha: float = 0.7  # Weight for confidence
    beta: float = 0.3   # Weight for support degree

    def __post_init__(self):
        # Normalize weights
        total = self.alpha + self.beta
        if total != 1.0:
            self.alpha = self.alpha / total
            self.beta = self.beta / total


class PreferenceCalculator:
    """Calculate preference scores for hypotheses/arguments.

    The preference function π(h) = α·Conf(h) + β·Support(h) determines
    which arguments should be preferred in case of conflicts.
    """

    def __init__(self, config: Optional[PreferenceConfig] = None):
        self.config = config or PreferenceConfig()

    def calculate_preference(
        self,
        confidence: float,
        support_degree: float,
    ) -> float:
        """Calculate preference score.

        Args:
            confidence: Conf(h) - confidence score of the hypothesis
            support_degree: Support(h) - normalized support from evidence

        Returns:
            π(h) = α·Conf(h) + β·Support(h)
        """
        return (
            self.config.alpha * confidence +
            self.config.beta * support_degree
        )

    def calculate_support_degree(
        self,
        hypothesis: EvidenceNode,
        graph: EvidenceGraph,
    ) -> float:
        """Calculate Support(h) - normalized support from observations.

        Support(h) = number of supporting observations / max observations for any hypothesis
        """
        supporting_obs = graph.get_supporting_observations(hypothesis.id)
        support_count = len(supporting_obs)

        # Get max support across all hypotheses for normalization
        max_support = 1  # Avoid division by zero
        for hyp in graph.get_hypotheses():
            count = len(graph.get_supporting_observations(hyp.id))
            max_support = max(max_support, count)

        return support_count / max_support

    def calculate_argument_preference(
        self,
        argument: Argument,
    ) -> float:
        """Calculate preference for an argument."""
        return self.calculate_preference(
            argument.confidence,
            argument.support_degree,
        )

    def update_preferences(
        self,
        framework: ArgumentationFramework,
        graph: Optional[EvidenceGraph] = None,
    ) -> None:
        """Update preference scores for all arguments in the framework.

        If graph is provided, recalculates support degrees from evidence.
        """
        for arg in framework.arguments.values():
            # Update support degree if graph is available
            if graph:
                hyp_node = graph.get_node(arg.hypothesis_id)
                if hyp_node:
                    arg.support_degree = self.calculate_support_degree(hyp_node, graph)

            # Calculate and update preference
            arg.preference = self.calculate_preference(
                arg.confidence,
                arg.support_degree,
            )

    def compare_arguments(self, arg1: Argument, arg2: Argument) -> int:
        """Compare two arguments by preference.

        Returns:
            1 if arg1 > arg2 (arg1 preferred)
            -1 if arg1 < arg2 (arg2 preferred)
            0 if equal
        """
        if arg1.preference > arg2.preference:
            return 1
        elif arg1.preference < arg2.preference:
            return -1
        return 0

    def get_stronger_argument(
        self,
        arg1: Argument,
        arg2: Argument,
    ) -> Argument:
        """Get the stronger of two arguments by preference."""
        return arg1 if arg1.preference >= arg2.preference else arg2

    def rank_arguments(
        self,
        arguments: List[Argument],
        descending: bool = True,
    ) -> List[Argument]:
        """Rank arguments by preference score.

        Args:
            arguments: List of arguments to rank
            descending: If True, highest preference first

        Returns:
            Sorted list of arguments
        """
        return sorted(
            arguments,
            key=lambda a: a.preference,
            reverse=descending,
        )


class PreferenceBasedAttackResolver:
    """Resolve attacks based on preference scores.

    In preference-based argumentation:
    - An attack from a to b is successful if π(a) > π(b)
    - Otherwise, the attack is "defeated" by the higher preference
    """

    def __init__(self, calculator: PreferenceCalculator):
        self.calculator = calculator

    def is_successful_attack(
        self,
        attacker: Argument,
        target: Argument,
    ) -> bool:
        """Check if an attack is successful based on preference.

        Attack from attacker to target succeeds if π(attacker) > π(target).
        """
        return attacker.preference > target.preference

    def filter_successful_attacks(
        self,
        framework: ArgumentationFramework,
    ) -> ArgumentationFramework:
        """Create a new framework with only successful attacks.

        This implements preference-based defeat: weaker arguments cannot
        successfully attack stronger ones.
        """
        filtered = ArgumentationFramework()

        # Copy all arguments
        for arg in framework.arguments.values():
            filtered.add_argument(arg)

        # Only keep attacks where attacker has higher preference
        for attack in framework.attacks:
            attacker = framework.arguments.get(attack.attacker_id)
            target = framework.arguments.get(attack.target_id)

            if attacker and target:
                if self.is_successful_attack(attacker, target):
                    filtered.add_attack(attack)

        return filtered
