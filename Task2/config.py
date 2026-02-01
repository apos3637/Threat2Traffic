"""Configuration for Stage II tools: Constraint Acquisition and Validation."""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv


@dataclass
class TencentCloudConfig:
    """Tencent Cloud provider configuration."""
    secret_id: Optional[str] = None
    secret_key: Optional[str] = None
    region: str = "ap-guangzhou"


@dataclass
class QemuConfig:
    """QEMU/KVM provider configuration."""
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
    """Main configuration for Stage II tools."""
    tencentcloud: TencentCloudConfig = field(default_factory=TencentCloudConfig)
    qemu: QemuConfig = field(default_factory=QemuConfig)
    aws: AWSConfig = field(default_factory=AWSConfig)

    # Provider selection
    default_provider: str = "tencentcloud"

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

        # Tencent Cloud configuration
        tencentcloud_config = TencentCloudConfig(
            secret_id=os.getenv("TENCENTCLOUD_SECRET_ID"),
            secret_key=os.getenv("TENCENTCLOUD_SECRET_KEY"),
            region=os.getenv("TENCENTCLOUD_REGION", "ap-guangzhou"),
        )

        # QEMU/KVM configuration
        qemu_config = QemuConfig(
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
            tencentcloud=tencentcloud_config,
            qemu=qemu_config,
            aws=aws_config,
            default_provider=os.getenv("DEFAULT_PROVIDER", "tencentcloud"),
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
