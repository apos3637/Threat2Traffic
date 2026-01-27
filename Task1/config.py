"""Configuration for Stage I: Dialectic Intent Arbitration."""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv


@dataclass
class VTConfig:
    """VirusTotal API configuration."""
    api_key: str
    api_base: str = "https://www.virustotal.com/api/v3"
    rate_limit_per_minute: int = 4
    timeout: int = 30


@dataclass
class LLMConfig:
    """LLM API configuration."""
    api_key: str
    base_url: str = "https://api.deepseek.com/v1"
    model: str = "deepseek-chat"
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: int = 180


@dataclass
class AAFConfig:
    """Abstract Argumentation Framework configuration.

    Preference function: π(h) = α·Conf(h) + β·Support(h)
    """
    alpha: float = 0.7  # Weight for confidence
    beta: float = 0.3   # Weight for support degree
    use_preference_filtering: bool = True  # Filter attacks by preference
    max_iterations: int = 100  # Max iterations for fixed-point


@dataclass
class DeliberationConfig:
    """Deliberation process configuration."""
    max_rounds: int = 1  # Maximum deliberation rounds (limited for performance)
    convergence_threshold: float = 0.9  # Stop when this % of hypotheses are decided
    ensemble_samples: int = 5  # Samples for conflict detection
    conflict_threshold: float = 0.7  # Min samples to confirm a conflict

    # Adversarial debate settings
    debate_rounds: int = 2              # Max rounds per individual debate (reduced from 3)
    debate_convergence_gap: float = 0.3  # Confidence gap to declare winner
    enable_cross_validation: bool = True  # Enable cross-agent validation
    cross_validation_weight: float = 0.2  # How much CV affects confidence
    min_challenge_severity: float = 0.3   # Min severity to accept challenge
    use_adversarial_mode: bool = True     # Use AdversarialCoordinator
    max_debates_per_round: int = 5       # Limit debates per round to control LLM calls
    min_conflict_severity: float = 0.6   # Only debate high-severity conflicts


@dataclass
class Config:
    """Main configuration for Stage I."""
    vt: VTConfig
    llm: LLMConfig
    aaf: AAFConfig = field(default_factory=AAFConfig)
    deliberation: DeliberationConfig = field(default_factory=DeliberationConfig)
    output_dir: Path = field(default_factory=lambda: Path("output"))
    log_dir: Path = field(default_factory=lambda: Path("logs"))

    def __post_init__(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_env(cls, env_path: Optional[Path] = None) -> "Config":
        """Load configuration from environment variables."""
        if env_path is None:
            env_path = Path(__file__).parent / ".env"

        if env_path.exists():
            load_dotenv(env_path)

        vt_api_key = os.getenv("VT_API_KEY", "")
        llm_api_key = os.getenv("LLM_API_KEY", "") or os.getenv("DEEPSEEK_API_KEY", "")
        llm_base_url = os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1")
        llm_model = os.getenv("LLM_MODEL", "deepseek-chat")

        if not vt_api_key:
            raise ValueError("VT_API_KEY not found in environment or .env file")
        if not llm_api_key:
            raise ValueError("LLM_API_KEY or DEEPSEEK_API_KEY not found in environment or .env file")

        vt_config = VTConfig(api_key=vt_api_key)
        llm_config = LLMConfig(
            api_key=llm_api_key,
            base_url=llm_base_url,
            model=llm_model,
        )

        # Load AAF parameters from env if available
        aaf_config = AAFConfig(
            alpha=float(os.getenv("AAF_ALPHA", "0.7")),
            beta=float(os.getenv("AAF_BETA", "0.3")),
        )

        # Load deliberation parameters from env if available
        deliberation_config = DeliberationConfig(
            max_rounds=int(os.getenv("DELIBERATION_ROUNDS", "1")),
            ensemble_samples=int(os.getenv("ENSEMBLE_SAMPLES", "5")),
            debate_rounds=int(os.getenv("DEBATE_ROUNDS", "2")),
            debate_convergence_gap=float(os.getenv("DEBATE_CONVERGENCE_GAP", "0.3")),
            enable_cross_validation=os.getenv("ENABLE_CROSS_VALIDATION", "true").lower() == "true",
            cross_validation_weight=float(os.getenv("CROSS_VALIDATION_WEIGHT", "0.2")),
            min_challenge_severity=float(os.getenv("MIN_CHALLENGE_SEVERITY", "0.3")),
            use_adversarial_mode=os.getenv("USE_ADVERSARIAL_MODE", "true").lower() == "true",
            max_debates_per_round=int(os.getenv("MAX_DEBATES_PER_ROUND", "5")),
            min_conflict_severity=float(os.getenv("MIN_CONFLICT_SEVERITY", "0.6")),
        )

        return cls(
            vt=vt_config,
            llm=llm_config,
            aaf=aaf_config,
            deliberation=deliberation_config,
            output_dir=Path(__file__).parent / "output",
            log_dir=Path(__file__).parent / "logs",
        )


_config: Optional[Config] = None


def get_config() -> Config:
    """Get or create the global configuration."""
    global _config
    if _config is None:
        _config = Config.from_env()
    return _config
