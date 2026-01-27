"""Main orchestrator for Stage II: Invariant-Guided Synthesis."""

import asyncio
import time
import json
from pathlib import Path
from typing import Dict, Optional, Type, Callable
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from Task1.spec_extractor.models import EnvironmentSpecification
from Task2.models import SynthesisResult, ValidationResult, GeneratedScript
from Task2.config import Stage2Config, get_config
from Task2.providers.base_provider import IaCProvider
from Task2.providers.tencentcloud import TencentCloudProvider
from Task2.providers.libvirt import LibvirtProvider
from Task2.generator.terraform_generator import TerraformGenerator
from Task2.generator.script_generator import ScriptGenerator
from Task2.validators.syntax_validator import SyntaxValidator
from Task2.validators.semantic_validator import SemanticValidator
from Task2.refinement.refiner import LLMRefiner
from Task2.schema.registry import SchemaRegistry
from Task2.schema.compiler import ConstraintCompiler, LocalSchema


class SynthesisOrchestrator:
    """Orchestrator for the Invariant-Guided Synthesis loop.

    Implements Algorithm 2 from the paper:
    1. Select provider based on specification
    2. Generate initial Terraform code
    3. Iteratively validate and refine until valid or max iterations
    """

    # Registry of available providers
    PROVIDERS: Dict[str, Type[IaCProvider]] = {
        "tencentcloud": TencentCloudProvider,
        "libvirt": LibvirtProvider,
    }

    def __init__(
        self,
        config: Optional[Stage2Config] = None,
        verbose: bool = False,
        log_callback: Optional[Callable[[str], None]] = None,
    ):
        self.config = config or get_config()
        self.verbose = verbose
        self.log_callback = log_callback or (lambda msg: None)

        # Initialize schema registry and constraint compiler
        self.schema_registry = SchemaRegistry()
        self.constraint_compiler = ConstraintCompiler(self.schema_registry)

        # Initialize components with constraint compiler
        self.script_generator = ScriptGenerator()
        self.terraform_generator = TerraformGenerator(
            self.script_generator,
            self.constraint_compiler,
        )
        self.syntax_validator = SyntaxValidator()
        self.semantic_validator = SemanticValidator()
        self.refiner = LLMRefiner()

        # Provider instances (lazy loaded)
        self._providers: Dict[str, IaCProvider] = {}

    def _log(self, message: str, level: str = "info") -> None:
        """Log a message with optional callback."""
        if self.verbose:
            prefix = {"info": "→", "success": "✓", "error": "✗", "warn": "⚠"}
            print(f"  {prefix.get(level, '→')} {message}")
        self.log_callback(message)

    def get_provider(self, name: str) -> IaCProvider:
        """Get or create a provider instance.

        Args:
            name: Provider name (e.g., "tencentcloud", "libvirt")

        Returns:
            Provider instance

        Raises:
            ValueError: If provider not found
        """
        if name not in self._providers:
            if name not in self.PROVIDERS:
                raise ValueError(
                    f"Unknown provider: {name}. Available: {list(self.PROVIDERS.keys())}"
                )
            self._providers[name] = self.PROVIDERS[name]()

        return self._providers[name]

    def select_provider(self, spec: EnvironmentSpecification) -> Optional[str]:
        """Auto-select best provider for a specification.

        Args:
            spec: Environment specification

        Returns:
            Provider name or None if none suitable
        """
        # Try default provider first
        default = self.config.default_provider
        if default in self.PROVIDERS:
            provider = self.get_provider(default)
            if provider.check_availability(spec):
                return default

        # Try other providers
        for name in self.PROVIDERS:
            if name == default:
                continue
            provider = self.get_provider(name)
            if provider.check_availability(spec):
                return name

        return None

    async def synthesize(
        self,
        spec: EnvironmentSpecification,
        provider_name: Optional[str] = None,
        validate_only: bool = False,
        skip_validation: bool = False,
    ) -> SynthesisResult:
        """Run the Invariant-Guided Synthesis loop.

        Args:
            spec: Environment specification from Stage I
            provider_name: Provider to use (auto-selects if None)
            validate_only: If True, skip semantic validation (terraform plan)
            skip_validation: If True, skip all validation (just generate)

        Returns:
            SynthesisResult with generated Terraform code or error
        """
        start_time = time.time()
        validation_history = []

        # Step 1: Select provider
        self._log("Step 1: Selecting provider...")
        if provider_name is None:
            provider_name = self.select_provider(spec)

        if provider_name is None:
            self._log("No suitable provider found", "error")
            return SynthesisResult.failure(
                "No suitable provider found for specification",
                duration_seconds=time.time() - start_time,
            )

        try:
            provider = self.get_provider(provider_name)
            self._log(f"Using provider: {provider_name}", "success")
        except ValueError as e:
            self._log(f"Provider error: {e}", "error")
            return SynthesisResult.failure(
                str(e),
                duration_seconds=time.time() - start_time,
            )

        # Validate provider can handle spec
        validation_errors = provider.validate_spec(spec)
        if validation_errors:
            self._log(f"Provider validation failed: {validation_errors}", "error")
            return SynthesisResult.failure(
                f"Provider validation failed: {'; '.join(validation_errors)}",
                provider_used=provider_name,
                duration_seconds=time.time() - start_time,
            )

        # Step 2: Compile schema constraints (Phi_plat^local)
        self._log("Step 2: Compiling schema constraints...")
        try:
            local_schema = self.constraint_compiler.compile(spec, provider_name)
            self._log(
                f"Compiled schema: {len(local_schema.required_resources)} resources, "
                f"{len(local_schema.valid_images)} images, "
                f"{len(local_schema.valid_instance_types)} instance types",
                "success"
            )
        except Exception as e:
            self._log(f"Schema compilation warning: {e}", "warn")
            local_schema = None

        # Step 3: Initial generation
        self._log("Step 3: Generating initial Terraform code...")
        try:
            hcl_code, user_data, local_schema = await self.terraform_generator.generate(
                spec, provider, local_schema
            )
            self._log(f"Generated {len(hcl_code)} chars of HCL", "success")
        except Exception as e:
            self._log(f"Generation failed: {e}", "error")
            return SynthesisResult.failure(
                f"Initial generation failed: {str(e)}",
                provider_used=provider_name,
                duration_seconds=time.time() - start_time,
            )

        # If skip_validation, return immediately
        if skip_validation:
            self._log("Skipping all validation (--skip-validation)", "info")
            return SynthesisResult.from_success(
                terraform_code=hcl_code,
                iterations=0,
                provider=provider_name,
                validation_history=[],
                user_data_script=user_data,
                duration=time.time() - start_time,
            )

        # Step 4: Iterative refinement loop
        self._log(f"Step 4: Validation loop (max {self.config.max_iterations} iterations)...")

        for iteration in range(1, self.config.max_iterations + 1):
            self._log(f"Iteration {iteration}/{self.config.max_iterations}")

            # Tier 1: Syntax validation (V_Γ)
            self._log("  V_Γ: Running syntax validation (terraform validate)...")
            syntax_result = await self.syntax_validator.validate(hcl_code)
            validation_history.append(syntax_result)

            if not syntax_result.valid:
                self._log(f"  Syntax errors: {len(syntax_result.errors)}", "warn")
                self._log("  Refining code with LLM (schema-guided)...")
                hcl_code = await self.refiner.refine(
                    hcl_code,
                    syntax_result.feedback,
                    local_schema=local_schema,
                )
                self._log("  Refinement complete", "success")
                continue

            self._log("  Syntax validation passed", "success")

            # If validate_only mode, skip semantic validation
            if validate_only:
                self._log("Skipping semantic validation (--validate-only)", "info")
                return SynthesisResult.from_success(
                    terraform_code=hcl_code,
                    iterations=iteration,
                    provider=provider_name,
                    validation_history=validation_history,
                    user_data_script=user_data,
                    duration=time.time() - start_time,
                )

            # Tier 2: Semantic validation (V_Φ)
            self._log("  V_Φ: Running semantic validation (terraform plan)...")
            semantic_result = await self.semantic_validator.validate(hcl_code, provider)
            validation_history.append(semantic_result)

            if not semantic_result.valid:
                self._log(f"  Semantic errors: {len(semantic_result.errors)}", "warn")

                # Check if errors are fixable
                if self._has_unfixable_errors(semantic_result):
                    self._log("  Unfixable errors detected (credentials/permissions)", "error")
                    return SynthesisResult.failure(
                        f"Unfixable semantic errors: {semantic_result.feedback}",
                        terraform_code=hcl_code,
                        iterations=iteration,
                        provider_used=provider_name,
                        validation_history=validation_history,
                        user_data_script=user_data,
                        duration_seconds=time.time() - start_time,
                    )

                # Refine based on semantic errors
                self._log("  Refining code with LLM (schema-guided)...")
                hcl_code = await self.refiner.refine(
                    hcl_code,
                    semantic_result.feedback,
                    local_schema=local_schema,
                )
                self._log("  Refinement complete", "success")
                continue

            # Both validations passed!
            self._log("All validations passed!", "success")
            return SynthesisResult.from_success(
                terraform_code=hcl_code,
                iterations=iteration,
                provider=provider_name,
                validation_history=validation_history,
                user_data_script=user_data,
                duration=time.time() - start_time,
            )

        # Max iterations exceeded
        self._log(f"Max iterations ({self.config.max_iterations}) exceeded", "error")
        return SynthesisResult.failure(
            f"Max iterations ({self.config.max_iterations}) exceeded",
            terraform_code=hcl_code,
            iterations=self.config.max_iterations,
            provider_used=provider_name,
            validation_history=validation_history,
            user_data_script=user_data,
            duration_seconds=time.time() - start_time,
        )

    def _has_unfixable_errors(self, result: ValidationResult) -> bool:
        """Check if validation result contains unfixable errors."""
        unfixable_patterns = [
            "UnauthorizedAccess",
            "Access Denied",
            "credentials",
            "authentication",
            "permission denied",
        ]

        for issue in result.errors:
            for pattern in unfixable_patterns:
                if pattern.lower() in issue.message.lower():
                    return True

        return False

    async def close(self):
        """Clean up resources."""
        await self.script_generator.close()
        await self.refiner.close()


def load_spec_from_file(filepath: Path) -> EnvironmentSpecification:
    """Load an EnvironmentSpecification from a JSON file.

    Args:
        filepath: Path to the JSON file

    Returns:
        EnvironmentSpecification object
    """
    with open(filepath, "r") as f:
        data = json.load(f)

    # Import all necessary models
    from Task1.spec_extractor.models import (
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

    # Parse OS requirements
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

    # Parse software dependencies
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

    # Parse network constraints
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

    # Parse hardware profile
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

    # Parse MITRE mapping
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

    # Parse threat profile
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

    # Parse attack chain
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

    # Get metadata
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
