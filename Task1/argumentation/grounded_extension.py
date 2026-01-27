"""Grounded Extension computation (Algorithm 1 from paper).

Implements fixed-point iteration to compute the grounded extension
of an Abstract Argumentation Framework.
"""

from typing import Optional, Set
from dataclasses import dataclass

from .models import (
    Argument,
    ArgumentationFramework,
    ArgumentStatus,
    ExtensionResult,
)
from .preference import PreferenceCalculator, PreferenceBasedAttackResolver


@dataclass
class GroundedExtensionConfig:
    """Configuration for grounded extension computation."""
    max_iterations: int = 100  # Safety limit
    use_preference_filtering: bool = True  # Filter attacks by preference


class GroundedExtensionSolver:
    """Computes the grounded extension of an AAF.

    Algorithm 1: Fixed-point iteration
    1. Initialize E_gr = {}
    2. Identify unattacked arguments -> add to E_gr
    3. Identify arguments defended by E_gr -> add to E_gr
    4. Repeat until convergence
    5. E_gr is the grounded extension

    The grounded extension is:
    - The minimal complete extension
    - Contains all skeptically accepted arguments
    - Unique for any AAF
    """

    def __init__(
        self,
        config: Optional[GroundedExtensionConfig] = None,
        preference_calculator: Optional[PreferenceCalculator] = None,
    ):
        self.config = config or GroundedExtensionConfig()
        self.preference_calculator = preference_calculator

    def compute(
        self,
        framework: ArgumentationFramework,
    ) -> ExtensionResult:
        """Compute the grounded extension.

        Returns ExtensionResult with:
        - accepted: arguments in E_gr
        - rejected: arguments attacked by E_gr members
        - undecided: remaining arguments
        """
        # Optionally filter attacks based on preference
        working_framework = framework
        if self.config.use_preference_filtering and self.preference_calculator:
            resolver = PreferenceBasedAttackResolver(self.preference_calculator)
            working_framework = resolver.filter_successful_attacks(framework)

        # Initialize
        accepted: Set[str] = set()
        rejected: Set[str] = set()
        all_args = set(working_framework.arguments.keys())

        iteration = 0
        changed = True

        while changed and iteration < self.config.max_iterations:
            changed = False
            iteration += 1

            # Find arguments that should be accepted
            for arg_id in all_args - accepted - rejected:
                attackers = working_framework.get_attackers(arg_id)

                # Check if all attackers are rejected (defended by accepted set)
                # or if there are no attackers
                all_attackers_defeated = all(
                    attacker_id in rejected
                    for attacker_id in attackers
                )

                if all_attackers_defeated:
                    accepted.add(arg_id)
                    changed = True

            # Find arguments that should be rejected
            for arg_id in all_args - accepted - rejected:
                attackers = working_framework.get_attackers(arg_id)

                # If any attacker is accepted, this argument is rejected
                if any(attacker_id in accepted for attacker_id in attackers):
                    rejected.add(arg_id)
                    changed = True

        # Update argument statuses
        for arg_id, arg in framework.arguments.items():
            if arg_id in accepted:
                arg.status = ArgumentStatus.IN
            elif arg_id in rejected:
                arg.status = ArgumentStatus.OUT
            else:
                arg.status = ArgumentStatus.UNDECIDED

        undecided = all_args - accepted - rejected

        return ExtensionResult(
            accepted=accepted,
            rejected=rejected,
            undecided=undecided,
            iterations=iteration,
        )

    def compute_characteristic_function(
        self,
        framework: ArgumentationFramework,
        argument_set: Set[str],
    ) -> Set[str]:
        """Compute F(S) = {a | S defends a}.

        The characteristic function returns all arguments defended by S.
        """
        return framework.get_defense_set(argument_set)

    def verify_grounded_extension(
        self,
        framework: ArgumentationFramework,
        extension: Set[str],
    ) -> bool:
        """Verify that a set is the grounded extension.

        The grounded extension is the least fixed point of F.
        F(E_gr) = E_gr and E_gr ⊆ E for all complete extensions E.
        """
        # Check conflict-free
        if not framework.is_conflict_free(extension):
            return False

        # Check fixed point: F(extension) = extension
        defended = framework.get_defense_set(extension)
        if defended != extension:
            return False

        return True


class IncrementalGroundedSolver:
    """Incremental grounded extension solver.

    Supports efficient updates when arguments or attacks are added/removed.
    """

    def __init__(self, base_solver: GroundedExtensionSolver):
        self.solver = base_solver
        self._cached_result: Optional[ExtensionResult] = None
        self._cached_framework: Optional[ArgumentationFramework] = None

    def compute(
        self,
        framework: ArgumentationFramework,
        force_recompute: bool = False,
    ) -> ExtensionResult:
        """Compute grounded extension, using cache if possible."""
        if force_recompute or self._needs_recompute(framework):
            self._cached_result = self.solver.compute(framework)
            self._cached_framework = framework

        return self._cached_result

    def _needs_recompute(self, framework: ArgumentationFramework) -> bool:
        """Check if recomputation is needed."""
        if self._cached_result is None or self._cached_framework is None:
            return True

        # Simple check: argument/attack count changed
        if framework.argument_count != self._cached_framework.argument_count:
            return True
        if framework.attack_count != self._cached_framework.attack_count:
            return True

        return False

    def add_argument_and_update(
        self,
        framework: ArgumentationFramework,
        argument: Argument,
    ) -> ExtensionResult:
        """Add argument and incrementally update extension."""
        framework.add_argument(argument)
        return self.compute(framework, force_recompute=True)

    def invalidate_cache(self) -> None:
        """Invalidate the cached result."""
        self._cached_result = None
        self._cached_framework = None
