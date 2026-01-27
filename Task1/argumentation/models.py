"""Dung's Abstract Argumentation Framework (AAF) data structures."""

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple
from enum import Enum


class ArgumentStatus(str, Enum):
    """Status of an argument in extension computation."""
    UNDECIDED = "undecided"
    IN = "in"       # Accepted (in grounded extension)
    OUT = "out"     # Rejected (attacked by accepted argument)
    MUST_OUT = "must_out"  # Definitely rejected


@dataclass
class Argument:
    """An argument in the AAF, corresponding to a hypothesis node."""
    id: str
    hypothesis_id: str  # Reference to EvidenceNode.id
    content: str
    confidence: float   # Conf(h) from paper
    support_degree: float = 0.0  # Support(h) from paper
    preference: float = 0.0  # π(h) = α·Conf + β·Support
    status: ArgumentStatus = ArgumentStatus.UNDECIDED

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if isinstance(other, Argument):
            return self.id == other.id
        return False


@dataclass
class Attack:
    """An attack relation in the AAF.

    Corresponds to DEBATE edge in Evidence Graph.
    In Dung's semantics: attacker defeats target if attacker has higher preference.
    """
    attacker_id: str
    target_id: str
    attack_type: str  # e.g., "contradiction", "subsumption", "rebuttal"
    strength: float = 1.0

    def __hash__(self):
        return hash((self.attacker_id, self.target_id))

    def __eq__(self, other):
        if isinstance(other, Attack):
            return (self.attacker_id == other.attacker_id and
                    self.target_id == other.target_id)
        return False


@dataclass
class ArgumentationFramework:
    """Dung's Abstract Argumentation Framework.

    AF = (Args, Attacks) where:
    - Args is a set of arguments
    - Attacks ⊆ Args × Args is a binary attack relation
    """
    arguments: Dict[str, Argument] = field(default_factory=dict)
    attacks: Set[Attack] = field(default_factory=set)

    # Precomputed for efficiency
    _attackers_of: Dict[str, Set[str]] = field(default_factory=dict)
    _attacked_by: Dict[str, Set[str]] = field(default_factory=dict)

    def add_argument(self, arg: Argument) -> None:
        """Add an argument to the framework."""
        self.arguments[arg.id] = arg
        if arg.id not in self._attackers_of:
            self._attackers_of[arg.id] = set()
        if arg.id not in self._attacked_by:
            self._attacked_by[arg.id] = set()

    def add_attack(self, attack: Attack) -> None:
        """Add an attack relation."""
        self.attacks.add(attack)
        if attack.target_id not in self._attackers_of:
            self._attackers_of[attack.target_id] = set()
        self._attackers_of[attack.target_id].add(attack.attacker_id)

        if attack.attacker_id not in self._attacked_by:
            self._attacked_by[attack.attacker_id] = set()
        self._attacked_by[attack.attacker_id].add(attack.target_id)

    def get_attackers(self, arg_id: str) -> Set[str]:
        """Get all arguments that attack the given argument."""
        return self._attackers_of.get(arg_id, set())

    def get_targets(self, arg_id: str) -> Set[str]:
        """Get all arguments attacked by the given argument."""
        return self._attacked_by.get(arg_id, set())

    def is_attacked_by(self, target_id: str, attacker_id: str) -> bool:
        """Check if target is attacked by attacker."""
        return attacker_id in self._attackers_of.get(target_id, set())

    def get_unattacked_arguments(self) -> Set[str]:
        """Get arguments with no attackers."""
        return {
            arg_id for arg_id, attackers in self._attackers_of.items()
            if len(attackers) == 0
        }

    def is_conflict_free(self, argument_set: Set[str]) -> bool:
        """Check if a set of arguments is conflict-free.

        A set S is conflict-free iff no argument in S attacks another in S.
        """
        for arg_id in argument_set:
            targets = self.get_targets(arg_id)
            if targets & argument_set:
                return False
        return True

    def defends(self, defended_id: str, defending_set: Set[str]) -> bool:
        """Check if defending_set defends defended_id.

        S defends a iff for each b attacking a, there exists c in S that attacks b.
        """
        attackers = self.get_attackers(defended_id)
        for attacker_id in attackers:
            # Check if any argument in defending_set attacks this attacker
            attacker_attackers = self.get_attackers(attacker_id)
            if not (attacker_attackers & defending_set):
                return False
        return True

    def get_defense_set(self, argument_set: Set[str]) -> Set[str]:
        """Get all arguments defended by argument_set.

        F(S) = {a | S defends a}
        """
        defended = set()
        for arg_id in self.arguments:
            if self.defends(arg_id, argument_set):
                defended.add(arg_id)
        return defended

    @property
    def argument_count(self) -> int:
        return len(self.arguments)

    @property
    def attack_count(self) -> int:
        return len(self.attacks)


@dataclass
class ExtensionResult:
    """Result of computing an argumentation extension."""
    accepted: Set[str]  # Arguments in the extension
    rejected: Set[str]  # Arguments attacked by accepted
    undecided: Set[str]  # Neither accepted nor rejected
    iterations: int  # Number of iterations to converge

    @property
    def is_complete(self) -> bool:
        """Check if all arguments are decided."""
        return len(self.undecided) == 0
