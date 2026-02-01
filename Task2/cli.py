#!/usr/bin/env python3
"""CLI interface for Stage II tools: Constraint Acquisition and Validation.

Two independent subcommands:
  constraint  - Compile platform constraints (LocalSchema) from a spec
  validate    - Run syntax/semantic validation on HCL files
"""

import argparse
import asyncio
import sys
import json
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from Task2.config import get_config
from Task2.models import ValidationResult


# ---------------------------------------------------------------------------
# Spec loader (moved from orchestrator.py)
# ---------------------------------------------------------------------------

def load_spec_from_file(filepath: Path):
    """Load an EnvironmentSpecification from a JSON file."""
    from Task1.spec_extractor.models import (
        EnvironmentSpecification,
        OSRequirement,
        SoftwareDependency,
        NetworkConstraint,
        NetworkEndpoint,
        HardwareProfile,
        MITREMapping,
        ThreatProfile,
        AttackChainStep,
        OSFamily,
        Architecture,
        NetworkProtocol,
        ThreatCategory,
    )

    with open(filepath, "r") as f:
        data = json.load(f)

    os_data = data.get("os_requirements", {})
    os_requirements = OSRequirement(
        family=OSFamily(os_data.get("family", "unknown")),
        min_version=os_data.get("min_version"),
        max_version=os_data.get("max_version"),
        specific_versions=os_data.get("specific_versions", []),
        architecture=Architecture(os_data.get("architecture", "unknown")),
        language=os_data.get("language"),
        required_features=os_data.get("required_features", []),
        confidence=os_data.get("confidence", 0.0),
    )

    software_dependencies = []
    for dep_data in data.get("software_dependencies", []):
        software_dependencies.append(SoftwareDependency(
            name=dep_data.get("name", ""),
            type=dep_data.get("type", ""),
            version_constraint=dep_data.get("version_constraint"),
            required=dep_data.get("required", True),
            purpose=dep_data.get("purpose"),
            confidence=dep_data.get("confidence", 0.0),
        ))

    net_data = data.get("network_constraints", {})
    endpoints = []
    for ep_data in net_data.get("endpoints", []):
        endpoints.append(NetworkEndpoint(
            type=ep_data.get("type", ""),
            value=ep_data.get("value", ""),
            port=ep_data.get("port"),
            protocol=NetworkProtocol(ep_data.get("protocol", "tcp")),
            purpose=ep_data.get("purpose"),
        ))

    network_constraints = NetworkConstraint(
        requires_internet=net_data.get("requires_internet", True),
        protocols=[NetworkProtocol(p) for p in net_data.get("protocols", [])],
        ports=net_data.get("ports", []),
        domains=net_data.get("domains", []),
        ip_addresses=net_data.get("ip_addresses", []),
        endpoints=endpoints,
        dns_servers=net_data.get("dns_servers", []),
        uses_tor=net_data.get("uses_tor", False),
        uses_proxy=net_data.get("uses_proxy", False),
        confidence=net_data.get("confidence", 0.0),
    )

    hw_data = data.get("hardware_profile", {})
    hardware_profile = HardwareProfile(
        min_memory_mb=hw_data.get("min_memory_mb"),
        min_disk_mb=hw_data.get("min_disk_mb"),
        cpu_features=hw_data.get("cpu_features", []),
        requires_gpu=hw_data.get("requires_gpu", False),
        vm_detection=hw_data.get("vm_detection", False),
        sandbox_detection=hw_data.get("sandbox_detection", False),
        confidence=hw_data.get("confidence", 0.0),
    )

    mitre_mapping = []
    for mitre_data in data.get("mitre_mapping", []):
        mitre_mapping.append(MITREMapping(
            technique_id=mitre_data.get("technique_id", ""),
            technique_name=mitre_data.get("technique_name", ""),
            tactic=mitre_data.get("tactic", ""),
            description=mitre_data.get("description"),
            evidence=mitre_data.get("evidence", []),
            confidence=mitre_data.get("confidence", 0.0),
        ))

    threat_profile = None
    threat_data = data.get("threat_profile")
    if threat_data:
        threat_profile = ThreatProfile(
            primary_category=ThreatCategory(threat_data.get("primary_category", "unknown")),
            secondary_categories=[ThreatCategory(c) for c in threat_data.get("secondary_categories", [])],
            family_name=threat_data.get("family_name"),
            variant=threat_data.get("variant"),
            aliases=threat_data.get("aliases", []),
            severity=threat_data.get("severity", 0.0),
            capabilities=threat_data.get("capabilities", []),
            target_sectors=threat_data.get("target_sectors", []),
            attribution=threat_data.get("attribution"),
            first_seen=threat_data.get("first_seen"),
            confidence=threat_data.get("confidence", 0.0),
        )

    attack_chain = []
    for step_data in data.get("attack_chain", []):
        attack_chain.append(AttackChainStep(
            order=step_data.get("order", 0),
            phase=step_data.get("phase", ""),
            action=step_data.get("action", ""),
            technique_id=step_data.get("technique_id"),
            artifacts=step_data.get("artifacts", []),
            network_activity=step_data.get("network_activity", []),
        ))

    metadata = data.get("metadata", {})

    return EnvironmentSpecification(
        sample_hash=data.get("sample_hash", ""),
        os_requirements=os_requirements,
        software_dependencies=software_dependencies,
        network_constraints=network_constraints,
        hardware_profile=hardware_profile,
        mitre_mapping=mitre_mapping,
        threat_profile=threat_profile,
        attack_chain=attack_chain,
        grounded_extension_size=metadata.get("grounded_extension_size", 0),
        deliberation_rounds=metadata.get("deliberation_rounds", 0),
        total_hypotheses=metadata.get("total_hypotheses", 0),
        conflicts_resolved=metadata.get("conflicts_resolved", 0),
    )


# ---------------------------------------------------------------------------
# Subcommand: constraint
# ---------------------------------------------------------------------------

def cmd_constraint(args):
    """Compile platform constraints from spec, or dump full provider schema."""
    provider = args.provider or get_config().default_provider

    # --prompt requires --spec
    if getattr(args, 'prompt', False) and args.spec is None:
        print("Error: --prompt requires --spec", file=sys.stderr)
        sys.exit(1)

    # No --spec: dump the raw provider schema YAML
    if args.spec is None:
        from Task2.schema.registry import SchemaRegistry
        registry = SchemaRegistry()
        schema = registry.get_schema(provider)
        if schema is None:
            print(f"Error: No schema found for provider '{provider}'", file=sys.stderr)
            sys.exit(1)

        yaml_file = registry.mappings_dir / f"{provider}.yaml"
        if yaml_file.exists():
            print(yaml_file.read_text(), end="")
        else:
            print(f"Error: Mapping file not found: {yaml_file}", file=sys.stderr)
            sys.exit(1)
        return

    # With --spec: compile filtered constraints
    if not args.spec.exists():
        print(f"Error: Spec file not found: {args.spec}", file=sys.stderr)
        sys.exit(1)

    try:
        spec = load_spec_from_file(args.spec)
    except Exception as e:
        print(f"Error loading spec file: {e}", file=sys.stderr)
        sys.exit(1)

    from Task2.schema.compiler import ConstraintCompiler
    compiler = ConstraintCompiler()
    local_schema = compiler.compile(spec, provider)

    # --prompt mode: assemble adaptive LLM prompt and write to file
    if args.prompt:
        from Task2.schema.prompt_builder import PromptBuilder

        prompt_text = PromptBuilder(spec, local_schema).build()

        output_dir = Path(__file__).parent / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{spec.sample_hash[:12]}_prompt.txt"
        output_path = output_dir / filename

        output_path.write_text(prompt_text, encoding="utf-8")
        print(f"Prompt saved to {output_path}")
        return

    output = json.dumps(local_schema.to_dict(), indent=2, ensure_ascii=False)

    if args.json:
        print(output)
    else:
        print(f"Provider: {local_schema.provider}")
        print(f"Required resources: {len(local_schema.required_resources)}")
        for r in local_schema.required_resources:
            print(f"  - {r}")
        print(f"Valid images: {len(local_schema.valid_images)}")
        print(f"Valid instance types: {len(local_schema.valid_instance_types)}")
        print(f"Valid regions: {len(local_schema.valid_regions)}")
        print()
        print(output)


# ---------------------------------------------------------------------------
# Subcommand: validate
# ---------------------------------------------------------------------------

def cmd_validate(args):
    """Run syntax and/or semantic validation on an HCL file."""
    if not args.hcl.exists():
        print(f"Error: HCL file not found: {args.hcl}", file=sys.stderr)
        sys.exit(1)

    hcl_code = args.hcl.read_text()

    from Task2.validators.syntax_validator import SyntaxValidator
    from Task2.validators.semantic_validator import SemanticValidator

    if not SyntaxValidator.is_available():
        print("Error: terraform not found in PATH", file=sys.stderr)
        sys.exit(1)

    results: list[dict] = []

    async def run_validation():
        # V_Γ: Syntax validation
        syntax_validator = SyntaxValidator()
        syntax_result = await syntax_validator.validate(hcl_code)
        results.append(syntax_result.to_dict())

        if not args.syntax_only and syntax_result.valid:
            # V_Φ: Semantic validation (only if syntax passes)
            semantic_validator = SemanticValidator()

            # Optionally load provider for provider-specific checks
            provider = None
            if args.provider:
                try:
                    provider = _get_provider(args.provider)
                except Exception:
                    pass  # proceed without provider-specific checks

            semantic_result = await semantic_validator.validate(
                hcl_code, provider=provider,
            )
            results.append(semantic_result.to_dict())

    asyncio.run(run_validation())

    combined = {
        "file": str(args.hcl),
        "tiers": results,
        "valid": all(r["valid"] for r in results) if results else False,
    }

    if args.json:
        print(json.dumps(combined, indent=2, ensure_ascii=False))
    else:
        for tier_result in results:
            status = "PASS" if tier_result["valid"] else "FAIL"
            tier = tier_result["tier"].upper()
            errors = tier_result["error_count"]
            warnings = tier_result["warning_count"]
            print(f"[{tier}] {status}  errors={errors} warnings={warnings}")
            for issue in tier_result.get("issues", []):
                sev = issue["severity"].upper()
                msg = issue["message"]
                loc = ""
                if issue.get("file"):
                    loc = f" at {issue['file']}"
                    if issue.get("line"):
                        loc += f":{issue['line']}"
                print(f"  [{sev}]{loc}: {msg}")
                if issue.get("suggestion"):
                    print(f"    Suggestion: {issue['suggestion']}")

        print()
        overall = "PASS" if combined["valid"] else "FAIL"
        print(f"Overall: {overall}")

    sys.exit(0 if combined["valid"] else 1)


def _get_provider(provider_name: str):
    """Instantiate an IaCProvider by name."""
    from Task2.providers.tencentcloud import TencentCloudProvider
    from Task2.providers.qemu import QemuProvider

    providers = {
        "tencentcloud": TencentCloudProvider,
        "qemu": QemuProvider,
    }

    cls = providers.get(provider_name)
    if cls is None:
        raise ValueError(f"Unknown provider: {provider_name}")
    return cls()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Stage II Tools: Constraint Acquisition and Validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dump full provider schema (YAML)
  python -m Task2.cli constraint --provider tencentcloud

  # Compile constraints for a spec
  python -m Task2.cli constraint --spec output/sample_spec.json --provider tencentcloud

  # Validate an HCL file (syntax + semantic)
  python -m Task2.cli validate --hcl main.tf --provider tencentcloud

  # Syntax-only validation
  python -m Task2.cli validate --hcl main.tf --syntax-only

  # JSON output
  python -m Task2.cli constraint --spec output/sample_spec.json --json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- constraint subcommand ---
    p_constraint = subparsers.add_parser(
        "constraint",
        help="Compile platform constraints (LocalSchema) from a spec",
    )
    p_constraint.add_argument(
        "--spec", type=Path, default=None,
        help="Path to EnvironmentSpecification JSON file (omit to dump full provider schema)",
    )
    p_constraint.add_argument(
        "--provider", type=str, choices=["tencentcloud", "qemu", "aws"],
        default=None, help="Target provider (default: from config)",
    )
    p_constraint.add_argument(
        "--json", action="store_true", help="Output as JSON only",
    )
    p_constraint.add_argument(
        "--prompt", action="store_true",
        help="Assemble an adaptive LLM prompt and save to Task2/output/ (requires --spec)",
    )

    # --- validate subcommand ---
    p_validate = subparsers.add_parser(
        "validate",
        help="Run syntax/semantic validation on a Terraform HCL file",
    )
    p_validate.add_argument(
        "--hcl", type=Path, required=True,
        help="Path to Terraform HCL file to validate",
    )
    p_validate.add_argument(
        "--provider", type=str, choices=["tencentcloud", "qemu", "aws"],
        default=None, help="Provider for provider-specific checks",
    )
    p_validate.add_argument(
        "--syntax-only", action="store_true",
        help="Skip semantic validation (V_Phi), only run syntax (V_Gamma)",
    )
    p_validate.add_argument(
        "--json", action="store_true", help="Output as JSON only",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def cli_main():
    args = parse_args()
    if args.command == "constraint":
        cmd_constraint(args)
    elif args.command == "validate":
        cmd_validate(args)


if __name__ == "__main__":
    cli_main()
