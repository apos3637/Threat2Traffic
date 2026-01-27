"""Configuration for Stage II: Invariant-Guided Synthesis."""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv


@dataclass
class LLMConfig:
    """LLM API configuration."""
    api_key: str
    base_url: str = "https://api.deepseek.com/v1"
    model: str = "deepseek-chat"
    temperature: float = 0.3  # Lower temperature for code generation
    max_tokens: int = 8192
    timeout: int = 180


@dataclass
class TencentCloudConfig:
    """Tencent Cloud provider configuration."""
    secret_id: Optional[str] = None
    secret_key: Optional[str] = None
    region: str = "ap-guangzhou"


@dataclass
class LibvirtConfig:
    """Libvirt provider configuration."""
    uri: str = "qemu:///system"
    storage_pool: str = "default"
    network_name: str = "default"


@dataclass
class AWSConfig:
    """AWS provider configuration."""
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    region: str = "us-east-1"


@dataclass
class Stage2Config:
    """Main configuration for Stage II."""
    llm: LLMConfig
    tencentcloud: TencentCloudConfig = field(default_factory=TencentCloudConfig)
    libvirt: LibvirtConfig = field(default_factory=LibvirtConfig)
    aws: AWSConfig = field(default_factory=AWSConfig)

    # Provider selection
    default_provider: str = "tencentcloud"

    # Synthesis parameters
    max_iterations: int = 8
    validate_only: bool = False

    # Output
    output_dir: Path = field(default_factory=lambda: Path("output"))

    def __post_init__(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_env(cls, env_path: Optional[Path] = None) -> "Stage2Config":
        """Load configuration from environment variables."""
        if env_path is None:
            # Try Task2/.env first, then Task1/.env
            task2_env = Path(__file__).parent / ".env"
            task1_env = Path(__file__).parent.parent / "Task1" / ".env"

            if task2_env.exists():
                env_path = task2_env
            elif task1_env.exists():
                env_path = task1_env

        if env_path and env_path.exists():
            load_dotenv(env_path)

        # LLM configuration (reuse from Stage I)
        llm_api_key = os.getenv("LLM_API_KEY", "") or os.getenv("DEEPSEEK_API_KEY", "")
        llm_base_url = os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1")
        llm_model = os.getenv("LLM_MODEL", "deepseek-chat")

        if not llm_api_key:
            raise ValueError("LLM_API_KEY or DEEPSEEK_API_KEY not found in environment")

        llm_config = LLMConfig(
            api_key=llm_api_key,
            base_url=llm_base_url,
            model=llm_model,
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.3")),
        )

        # Tencent Cloud configuration
        tencentcloud_config = TencentCloudConfig(
            secret_id=os.getenv("TENCENTCLOUD_SECRET_ID"),
            secret_key=os.getenv("TENCENTCLOUD_SECRET_KEY"),
            region=os.getenv("TENCENTCLOUD_REGION", "ap-guangzhou"),
        )

        # Libvirt configuration
        libvirt_config = LibvirtConfig(
            uri=os.getenv("LIBVIRT_URI", "qemu:///system"),
            storage_pool=os.getenv("LIBVIRT_STORAGE_POOL", "default"),
            network_name=os.getenv("LIBVIRT_NETWORK", "default"),
        )

        # AWS configuration
        aws_config = AWSConfig(
            access_key=os.getenv("AWS_ACCESS_KEY_ID"),
            secret_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region=os.getenv("AWS_REGION", "us-east-1"),
        )

        return cls(
            llm=llm_config,
            tencentcloud=tencentcloud_config,
            libvirt=libvirt_config,
            aws=aws_config,
            default_provider=os.getenv("DEFAULT_PROVIDER", "tencentcloud"),
            max_iterations=int(os.getenv("MAX_ITERATIONS", "8")),
            output_dir=Path(os.getenv("OUTPUT_DIR", str(Path(__file__).parent / "output"))),
        )


_config: Optional[Stage2Config] = None


def get_config() -> Stage2Config:
    """Get or create the global configuration."""
    global _config
    if _config is None:
        _config = Stage2Config.from_env()
    return _config


def reset_config() -> None:
    """Reset the global configuration (for testing)."""
    global _config
    _config = None
