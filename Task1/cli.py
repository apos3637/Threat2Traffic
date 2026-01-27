"""Command-line interface for Stage I: Dialectic Intent Arbitration."""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

from .config import Config, VTConfig, LLMConfig, AAFConfig, DeliberationConfig
from .orchestrator import Stage1Orchestrator
from .utils.logger import get_logger

logger = get_logger("cli")


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m Task1.cli",
        description="Stage I: Dialectic Intent Arbitration - Extract malware environment requirements",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  python -m Task1.cli 0ae6570d9e659ffd5efc1e3f9faca696bd12b66b8d125b1159aee9e5251a4d79

  # Custom output directory
  python -m Task1.cli <sha256> --output ./results

  # Custom AAF parameters
  python -m Task1.cli <sha256> --alpha 0.5 --beta 0.5

  # Increase deliberation rounds
  python -m Task1.cli <sha256> --deliberation-rounds 5

  # Output only JSON
  python -m Task1.cli <sha256> --json-only
        """,
    )

    parser.add_argument(
        "hash",
        help="SHA256 hash of the malware sample to analyze",
    )

    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Output directory for results (default: Task1/output)",
    )

    parser.add_argument(
        "--alpha",
        type=float,
        default=0.4,
        help="AAF preference weight for confidence (default: 0.4)",
    )

    parser.add_argument(
        "--beta",
        type=float,
        default=0.6,
        help="AAF preference weight for support (default: 0.6)",
    )

    parser.add_argument(
        "--deliberation-rounds",
        type=int,
        default=3,
        help="Maximum deliberation rounds (default: 3)",
    )

    parser.add_argument(
        "--ensemble-samples",
        type=int,
        default=3,
        help="Ensemble samples for conflict detection (default: 3)",
    )

    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Output only JSON result (no progress messages)",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )

    return parser


def validate_hash(hash_str: str) -> bool:
    """Validate SHA256 hash format."""
    if len(hash_str) != 64:
        return False
    try:
        int(hash_str, 16)
        return True
    except ValueError:
        return False


async def run_analysis(args: argparse.Namespace) -> int:
    """Run the analysis."""
    # Validate hash
    if not validate_hash(args.hash):
        if not args.json_only:
            print(f"Error: Invalid SHA256 hash: {args.hash}", file=sys.stderr)
        return 1

    # Load base config from environment
    try:
        config = Config.from_env()
    except ValueError as e:
        if not args.json_only:
            print(f"Configuration error: {e}", file=sys.stderr)
        return 1

    # Override with CLI arguments
    config.aaf = AAFConfig(
        alpha=args.alpha,
        beta=args.beta,
    )
    config.deliberation = DeliberationConfig(
        max_rounds=args.deliberation_rounds,
        ensemble_samples=args.ensemble_samples,
    )

    if args.output:
        config.output_dir = args.output
        config.output_dir.mkdir(parents=True, exist_ok=True)

    # Run analysis
    orchestrator = Stage1Orchestrator(config)

    if not args.json_only:
        print(f"Analyzing sample: {args.hash}")
        print(f"Output directory: {config.output_dir}")
        print("-" * 60)

    try:
        spec = await orchestrator.analyze(args.hash)

        if args.json_only:
            print(spec.to_json())
        else:
            print_summary(spec)

        return 0

    except Exception as e:
        if args.json_only:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"\nError: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


def print_summary(spec) -> None:
    """Print human-readable summary."""
    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)

    print(f"\nSample: {spec.sample_hash}")
    print(f"Analysis Duration: {spec.analysis_duration_seconds:.1f}s")

    print("\n--- OS Requirements ---")
    os_req = spec.os_requirements
    print(f"  Family: {os_req.family.value}")
    print(f"  Architecture: {os_req.architecture.value}")
    if os_req.specific_versions:
        print(f"  Versions: {', '.join(os_req.specific_versions)}")
    if os_req.required_features:
        print(f"  Features: {', '.join(os_req.required_features)}")
    print(f"  Confidence: {os_req.confidence:.2f}")

    if spec.software_dependencies:
        print("\n--- Software Dependencies ---")
        for dep in spec.software_dependencies:
            print(f"  - {dep.name} ({dep.type}): {dep.purpose}")

    print("\n--- Network Constraints ---")
    net = spec.network_constraints
    print(f"  Requires Internet: {net.requires_internet}")
    if net.protocols:
        print(f"  Protocols: {', '.join(p.value for p in net.protocols)}")
    if net.ports:
        print(f"  Ports: {', '.join(map(str, net.ports))}")
    if net.domains:
        print(f"  Domains: {', '.join(net.domains[:5])}")
    if net.uses_tor:
        print("  Uses TOR: Yes")

    print("\n--- Hardware Profile ---")
    hw = spec.hardware_profile
    if hw.vm_detection:
        print("  VM Detection: Yes")
    if hw.sandbox_detection:
        print("  Sandbox Detection: Yes")
    if hw.min_memory_mb:
        print(f"  Min Memory: {hw.min_memory_mb} MB")

    if spec.threat_profile:
        print("\n--- Threat Profile ---")
        threat = spec.threat_profile
        print(f"  Category: {threat.primary_category.value}")
        if threat.family_name:
            print(f"  Family: {threat.family_name}")
        print(f"  Severity: {threat.severity}/10")
        if threat.capabilities:
            print(f"  Capabilities: {', '.join(threat.capabilities)}")

    if spec.mitre_mapping:
        print("\n--- MITRE ATT&CK Techniques ---")
        for mapping in spec.mitre_mapping[:10]:
            print(f"  - {mapping.technique_id}: {mapping.technique_name} ({mapping.tactic})")

    print("\n--- Deliberation Statistics ---")
    print(f"  Rounds: {spec.deliberation_rounds}")
    print(f"  Total Hypotheses: {spec.total_hypotheses}")
    print(f"  Accepted (Grounded Extension): {spec.grounded_extension_size}")
    print(f"  Conflicts Resolved: {spec.conflicts_resolved}")

    print("\n" + "=" * 60)
    print(f"Full results saved to: {spec.sample_hash[:16]}_*_spec.json")


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    return asyncio.run(run_analysis(args))


if __name__ == "__main__":
    sys.exit(main())
