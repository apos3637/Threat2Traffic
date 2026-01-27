#!/usr/bin/env python3
"""CLI interface for Stage II: Invariant-Guided Synthesis."""

import argparse
import asyncio
import sys
import json
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from Task2.config import Stage2Config, get_config, reset_config
from Task2.orchestrator import SynthesisOrchestrator, load_spec_from_file
from Task2.models import SynthesisResult


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Stage II: Invariant-Guided Synthesis - Generate Terraform from EnvironmentSpecification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate Terraform for TencentCloud
  python -m Task2.cli --spec output/sample_spec.json --provider tencentcloud

  # Generate for libvirt with custom output directory
  python -m Task2.cli --spec output/sample_spec.json --provider libvirt --output ./terraform/

  # Validate only (skip terraform plan)
  python -m Task2.cli --spec output/sample_spec.json --validate-only

  # Auto-select provider
  python -m Task2.cli --spec output/sample_spec.json
        """
    )

    parser.add_argument(
        "--spec",
        type=Path,
        required=True,
        help="Path to EnvironmentSpecification JSON file from Stage I",
    )

    parser.add_argument(
        "--provider",
        type=str,
        choices=["tencentcloud", "libvirt", "aws"],
        default=None,
        help="Provider to use (default: auto-select)",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output directory for Terraform files (default: Task2/output/)",
    )

    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only run syntax validation, skip terraform plan",
    )

    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip all terraform validation (just generate code)",
    )

    parser.add_argument(
        "--max-iterations",
        type=int,
        default=8,
        help="Maximum refinement iterations (default: 8)",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output result as JSON",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output",
    )

    return parser.parse_args()


def print_result(result: SynthesisResult, verbose: bool = False):
    """Print synthesis result to console."""
    if result.success:
        print("✓ Synthesis successful!")
        print(f"  Provider: {result.provider_used}")
        print(f"  Iterations: {result.iterations}")
        print(f"  Duration: {result.duration_seconds:.2f}s")
    else:
        print("✗ Synthesis failed!")
        print(f"  Error: {result.error_message}")
        if result.iterations > 0:
            print(f"  Iterations attempted: {result.iterations}")

    if verbose and result.validation_history:
        print("\nValidation history:")
        for i, val in enumerate(result.validation_history, 1):
            status = "✓" if val.valid else "✗"
            print(f"  {i}. [{val.tier.value}] {status} - {len(val.errors)} errors, {len(val.warnings)} warnings")
            if not val.valid:
                for issue in val.errors[:3]:  # Show first 3 errors
                    print(f"     - {issue.message[:80]}")


async def main():
    """Main entry point."""
    args = parse_args()

    # Validate spec file exists
    if not args.spec.exists():
        print(f"Error: Spec file not found: {args.spec}", file=sys.stderr)
        sys.exit(1)

    # Load configuration
    try:
        config = get_config()
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        print("Make sure LLM_API_KEY or DEEPSEEK_API_KEY is set.", file=sys.stderr)
        sys.exit(1)

    # Override max iterations if specified
    if args.max_iterations != 8:
        config.max_iterations = args.max_iterations

    # Set output directory
    if args.output:
        output_dir = args.output
    else:
        output_dir = config.output_dir

    # Load specification
    if args.verbose:
        print(f"Loading specification from {args.spec}...")

    try:
        spec = load_spec_from_file(args.spec)
    except Exception as e:
        print(f"Error loading spec file: {e}", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print(f"  Sample hash: {spec.sample_hash}")
        print(f"  OS: {spec.os_requirements.family.value}")
        print(f"  Dependencies: {len(spec.software_dependencies)}")

    # Check terraform availability
    from Task2.validators.syntax_validator import SyntaxValidator
    if not SyntaxValidator.is_available():
        print("Warning: terraform not found in PATH", file=sys.stderr)
        print("  Syntax/semantic validation will fail.", file=sys.stderr)
        print("  Install terraform or use --validate-only to skip validation.", file=sys.stderr)
        if not args.validate_only:
            print("\nContinuing anyway (will likely fail)...", file=sys.stderr)

    # Create orchestrator and run synthesis
    orchestrator = SynthesisOrchestrator(config, verbose=args.verbose)

    try:
        if args.verbose:
            print(f"\nStarting synthesis...")
            if args.provider:
                print(f"  Provider: {args.provider}")
            else:
                print(f"  Provider: auto-select")

        result = await orchestrator.synthesize(
            spec=spec,
            provider_name=args.provider,
            validate_only=args.validate_only,
            skip_validation=args.skip_validation,
        )

        # Output result
        if args.json:
            print(result.to_json())
        else:
            print_result(result, verbose=args.verbose)

            if result.success:
                # Save output files
                output_path = output_dir / spec.sample_hash[:16]
                result.save(output_path)
                print(f"\nOutput saved to: {output_path}")

                if args.verbose and result.terraform_code:
                    print("\n--- Generated Terraform ---")
                    print(result.terraform_code[:2000])
                    if len(result.terraform_code) > 2000:
                        print("... (truncated)")

        # Return appropriate exit code
        sys.exit(0 if result.success else 1)

    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        await orchestrator.close()


def cli_main():
    """Entry point for console script."""
    asyncio.run(main())


if __name__ == "__main__":
    cli_main()
