"""Adaptive Prompt Builder for LLM-based Terraform HCL generation.

Implements the paper's adaptive prompt assembly: each section is
conditionally included based on the content of the EnvironmentSpecification
and LocalSchema, so different specs produce structurally different prompts.
"""

from typing import List

from Task1.spec_extractor.models import EnvironmentSpecification
from Task2.schema.compiler import LocalSchema


class PromptBuilder:
    """Assemble a complete LLM prompt from spec and local schema.

    Each ``_section_*`` method inspects the spec and returns a formatted
    string when the relevant data exists, or ``""`` when it does not.
    The ``build()`` method joins all non-empty sections, producing an
    adaptive prompt whose structure mirrors the available information.
    """

    def __init__(self, spec: EnvironmentSpecification, local_schema: LocalSchema):
        self.spec = spec
        self.schema = local_schema

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self) -> str:
        """Assemble the full prompt with conditional sections."""
        sections: List[str] = [
            self._section_role(),
            self._section_task(),
            self._section_target_env(),
            self._section_software_deps(),
            self._section_network(),
            self._section_hardware(),
            self._section_threat_context(),
            self._section_attack_chain(),
            self._section_platform_constraints(),
            self._section_output_format(),
        ]
        return "\n\n".join(s for s in sections if s)

    # ------------------------------------------------------------------
    # Fixed sections (always present)
    # ------------------------------------------------------------------

    def _section_role(self) -> str:
        return (
            "## System Role\n"
            "You are an expert Terraform engineer. Your task is to generate "
            "a complete, syntactically valid `main.tf` file that provisions "
            "the environment described below."
        )

    def _section_task(self) -> str:
        return (
            "## Task Instruction\n"
            f"Generate a Terraform configuration targeting the **{self.schema.provider}** "
            f"provider for sample `{self.spec.sample_hash}`.\n"
            "The configuration must satisfy ALL constraints listed in the sections that follow."
        )

    def _section_target_env(self) -> str:
        os_req = self.spec.os_requirements
        lines = ["## Target Environment"]
        lines.append(f"- OS family: {os_req.family.value}")
        if os_req.min_version:
            lines.append(f"- Minimum version: {os_req.min_version}")
        if os_req.max_version:
            lines.append(f"- Maximum version: {os_req.max_version}")
        if os_req.specific_versions:
            lines.append(f"- Specific versions: {', '.join(os_req.specific_versions)}")
        if os_req.architecture.value != "unknown":
            lines.append(f"- Architecture: {os_req.architecture.value}")
        if os_req.language:
            lines.append(f"- Language/locale: {os_req.language}")
        if os_req.required_features:
            lines.append(f"- Required OS features: {', '.join(os_req.required_features)}")
        return "\n".join(lines)

    def _section_output_format(self) -> str:
        return (
            "## Output Format\n"
            "- Output ONLY valid Terraform HCL code.\n"
            "- Do NOT wrap the code in markdown fences (no ```hcl or ```).\n"
            "- The output must be a single, self-contained `main.tf` file.\n"
            "- Include all required `terraform { required_providers { ... } }` blocks.\n"
            "- Use only values that appear in the Platform Constraints section above."
        )

    def _section_platform_constraints(self) -> str:
        return self.schema.format_for_prompt()

    # ------------------------------------------------------------------
    # Conditional sections (included only when data is present)
    # ------------------------------------------------------------------

    def _section_software_deps(self) -> str:
        deps = [d for d in self.spec.software_dependencies if d.confidence > 0.5]
        if not deps:
            return ""
        lines = ["## Software Dependencies"]
        for dep in deps:
            entry = f"- **{dep.name}** ({dep.type})"
            if dep.version_constraint:
                entry += f" version {dep.version_constraint}"
            if dep.purpose:
                entry += f" — {dep.purpose}"
            lines.append(entry)
        return "\n".join(lines)

    def _section_network(self) -> str:
        net = self.spec.network_constraints
        has_content = (
            net.protocols
            or net.ports
            or net.domains
            or net.ip_addresses
            or net.endpoints
            or net.uses_tor
            or net.uses_proxy
        )
        if not has_content:
            return ""
        lines = ["## Network Requirements"]
        if net.protocols:
            lines.append(f"- Protocols: {', '.join(p.value for p in net.protocols)}")
        if net.ports:
            lines.append(f"- Ports: {', '.join(str(p) for p in net.ports)}")
        if net.domains:
            lines.append(f"- Domains: {', '.join(net.domains)}")
        if net.ip_addresses:
            lines.append(f"- IP addresses: {', '.join(net.ip_addresses)}")
        if net.endpoints:
            lines.append("- Endpoints:")
            for ep in net.endpoints:
                desc = f"  - {ep.type} {ep.value}"
                if ep.port:
                    desc += f":{ep.port}"
                desc += f" ({ep.protocol.value})"
                if ep.purpose:
                    desc += f" — {ep.purpose}"
                lines.append(desc)
        if net.uses_tor:
            lines.append("- Uses TOR: yes")
        if net.uses_proxy:
            lines.append("- Uses proxy: yes")
        return "\n".join(lines)

    def _section_hardware(self) -> str:
        hw = self.spec.hardware_profile
        has_content = (
            hw.min_memory_mb
            or hw.min_disk_mb
            or hw.cpu_features
            or hw.requires_gpu
            or hw.vm_detection
            or hw.sandbox_detection
        )
        if not has_content:
            return ""
        lines = ["## Hardware Requirements"]
        if hw.min_memory_mb:
            lines.append(f"- Minimum memory: {hw.min_memory_mb} MB")
        if hw.min_disk_mb:
            lines.append(f"- Minimum disk: {hw.min_disk_mb} MB")
        if hw.cpu_features:
            lines.append(f"- CPU features: {', '.join(hw.cpu_features)}")
        if hw.requires_gpu:
            lines.append("- Requires GPU: yes")
        if hw.vm_detection:
            lines.append("- VM detection: the sample detects virtual machines")
        if hw.sandbox_detection:
            lines.append("- Sandbox detection: the sample detects sandboxes")
        return "\n".join(lines)

    def _section_threat_context(self) -> str:
        tp = self.spec.threat_profile
        if tp is None:
            return ""
        lines = ["## Threat Context"]
        lines.append(f"- Primary category: {tp.primary_category.value}")
        if tp.secondary_categories:
            lines.append(
                f"- Secondary categories: {', '.join(c.value for c in tp.secondary_categories)}"
            )
        if tp.family_name:
            lines.append(f"- Family: {tp.family_name}")
        if tp.variant:
            lines.append(f"- Variant: {tp.variant}")
        if tp.aliases:
            lines.append(f"- Aliases: {', '.join(tp.aliases)}")
        if tp.severity:
            lines.append(f"- Severity: {tp.severity}/10")
        if tp.capabilities:
            lines.append(f"- Capabilities: {', '.join(tp.capabilities)}")
        if tp.target_sectors:
            lines.append(f"- Target sectors: {', '.join(tp.target_sectors)}")
        if tp.attribution:
            lines.append(f"- Attribution: {tp.attribution}")
        return "\n".join(lines)

    def _section_attack_chain(self) -> str:
        chain = self.spec.attack_chain
        if not chain:
            return ""
        lines = ["## Attack Chain"]
        sorted_chain = sorted(chain, key=lambda s: s.order)
        for step in sorted_chain:
            entry = f"{step.order}. **{step.phase}**: {step.action}"
            if step.technique_id:
                entry += f" [{step.technique_id}]"
            lines.append(entry)
            if step.artifacts:
                lines.append(f"   Artifacts: {', '.join(step.artifacts)}")
            if step.network_activity:
                lines.append(f"   Network: {', '.join(step.network_activity)}")
        return "\n".join(lines)
