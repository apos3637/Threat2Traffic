"""MITRE ATT&CK mapping from VT data and agent analysis."""

from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass

from ..vt_client.parser import ParsedVTReport, BehaviorInfo
from ..evidence_graph.graph import EvidenceGraph
from ..evidence_graph.models import EvidenceNode, NodeType
from .models import MITREMapping, ThreatProfile, ThreatCategory, AttackChainStep
from ..utils.logger import get_logger

logger = get_logger("mitre_mapper")


# MITRE ATT&CK technique to tactic mapping (common techniques)
TECHNIQUE_TACTICS = {
    # Initial Access
    "T1566": "Initial Access",
    "T1566.001": "Initial Access",
    "T1566.002": "Initial Access",
    "T1189": "Initial Access",
    "T1190": "Initial Access",

    # Execution
    "T1059": "Execution",
    "T1059.001": "Execution",
    "T1059.003": "Execution",
    "T1059.005": "Execution",
    "T1059.006": "Execution",
    "T1059.007": "Execution",
    "T1204": "Execution",
    "T1204.001": "Execution",
    "T1204.002": "Execution",
    "T1047": "Execution",
    "T1053": "Execution",
    "T1053.005": "Execution",
    "T1569": "Execution",
    "T1569.002": "Execution",

    # Persistence
    "T1547": "Persistence",
    "T1547.001": "Persistence",
    "T1053.005": "Persistence",
    "T1543": "Persistence",
    "T1543.003": "Persistence",
    "T1546": "Persistence",
    "T1546.001": "Persistence",
    "T1546.003": "Persistence",
    "T1136": "Persistence",
    "T1098": "Persistence",

    # Privilege Escalation
    "T1548": "Privilege Escalation",
    "T1548.002": "Privilege Escalation",
    "T1134": "Privilege Escalation",
    "T1134.001": "Privilege Escalation",

    # Defense Evasion
    "T1027": "Defense Evasion",
    "T1027.002": "Defense Evasion",
    "T1055": "Defense Evasion",
    "T1055.001": "Defense Evasion",
    "T1055.012": "Defense Evasion",
    "T1140": "Defense Evasion",
    "T1562": "Defense Evasion",
    "T1562.001": "Defense Evasion",
    "T1070": "Defense Evasion",
    "T1070.004": "Defense Evasion",
    "T1497": "Defense Evasion",
    "T1497.001": "Defense Evasion",

    # Credential Access
    "T1003": "Credential Access",
    "T1003.001": "Credential Access",
    "T1555": "Credential Access",
    "T1555.003": "Credential Access",
    "T1552": "Credential Access",
    "T1056": "Credential Access",
    "T1056.001": "Credential Access",

    # Discovery
    "T1082": "Discovery",
    "T1083": "Discovery",
    "T1057": "Discovery",
    "T1012": "Discovery",
    "T1518": "Discovery",
    "T1518.001": "Discovery",
    "T1016": "Discovery",
    "T1033": "Discovery",
    "T1007": "Discovery",
    "T1049": "Discovery",

    # Lateral Movement
    "T1021": "Lateral Movement",
    "T1021.001": "Lateral Movement",
    "T1021.002": "Lateral Movement",
    "T1570": "Lateral Movement",

    # Collection
    "T1005": "Collection",
    "T1039": "Collection",
    "T1113": "Collection",
    "T1115": "Collection",
    "T1119": "Collection",
    "T1074": "Collection",
    "T1074.001": "Collection",

    # Command and Control
    "T1071": "Command and Control",
    "T1071.001": "Command and Control",
    "T1071.004": "Command and Control",
    "T1095": "Command and Control",
    "T1573": "Command and Control",
    "T1573.001": "Command and Control",
    "T1105": "Command and Control",
    "T1132": "Command and Control",
    "T1571": "Command and Control",

    # Exfiltration
    "T1041": "Exfiltration",
    "T1048": "Exfiltration",
    "T1567": "Exfiltration",
    "T1567.002": "Exfiltration",

    # Impact
    "T1486": "Impact",
    "T1490": "Impact",
    "T1489": "Impact",
    "T1529": "Impact",
}

# Technique ID to name mapping
TECHNIQUE_NAMES = {
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.005": "Visual Basic",
    "T1059.006": "Python",
    "T1059.007": "JavaScript",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1053.005": "Scheduled Task",
    "T1543.003": "Windows Service",
    "T1027": "Obfuscated Files or Information",
    "T1027.002": "Software Packing",
    "T1055": "Process Injection",
    "T1055.001": "Dynamic-link Library Injection",
    "T1055.012": "Process Hollowing",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1497.001": "System Checks",
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1555.003": "Credentials from Web Browsers",
    "T1056.001": "Keylogging",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1057": "Process Discovery",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1105": "Ingress Tool Transfer",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
}


class MITREMapper:
    """Map behaviors and evidence to MITRE ATT&CK techniques."""

    def __init__(self):
        self.technique_tactics = TECHNIQUE_TACTICS
        self.technique_names = TECHNIQUE_NAMES

    def map_from_vt_report(
        self,
        parsed_report: ParsedVTReport,
    ) -> List[MITREMapping]:
        """Extract MITRE mappings from VT report."""
        mappings = []
        seen_techniques = set()

        # Extract from behavior reports
        for behavior in parsed_report.behavior_info:
            for technique in behavior.mitre_attack_techniques:
                tech_id = technique.get("id", "")
                if tech_id and tech_id not in seen_techniques:
                    seen_techniques.add(tech_id)
                    mappings.append(MITREMapping(
                        technique_id=tech_id,
                        technique_name=technique.get("name", self.technique_names.get(tech_id, "Unknown")),
                        tactic=self.technique_tactics.get(tech_id, "Unknown"),
                        evidence=[technique.get("description", "VT sandbox observation")],
                        confidence=0.8,
                    ))

        # Extract from threat intel
        for technique in parsed_report.threat_intel_info.mitre_attack_techniques:
            tech_id = technique.get("id", "")
            if tech_id and tech_id not in seen_techniques:
                seen_techniques.add(tech_id)
                mappings.append(MITREMapping(
                    technique_id=tech_id,
                    technique_name=technique.get("name", self.technique_names.get(tech_id, "Unknown")),
                    tactic=self.technique_tactics.get(tech_id, "Unknown"),
                    evidence=["VT threat intelligence"],
                    confidence=0.7,
                ))

        return mappings

    def map_from_behaviors(
        self,
        behaviors: List[BehaviorInfo],
    ) -> List[MITREMapping]:
        """Infer MITRE techniques from observed behaviors."""
        mappings = []
        seen_techniques = set()

        for behavior in behaviors:
            # Command execution -> T1059.x
            for cmd in behavior.command_executions:
                cmd_lower = cmd.lower()
                if "powershell" in cmd_lower and "T1059.001" not in seen_techniques:
                    seen_techniques.add("T1059.001")
                    mappings.append(MITREMapping(
                        technique_id="T1059.001",
                        technique_name="PowerShell",
                        tactic="Execution",
                        evidence=[f"PowerShell command: {cmd[:100]}..."],
                        confidence=0.9,
                    ))
                elif "cmd" in cmd_lower and "T1059.003" not in seen_techniques:
                    seen_techniques.add("T1059.003")
                    mappings.append(MITREMapping(
                        technique_id="T1059.003",
                        technique_name="Windows Command Shell",
                        tactic="Execution",
                        evidence=[f"CMD command: {cmd[:100]}..."],
                        confidence=0.9,
                    ))

            # Registry persistence
            for reg_key in behavior.registry_keys_set:
                key_path = reg_key.get("key", "").lower() if isinstance(reg_key, dict) else str(reg_key).lower()
                if ("run" in key_path or "startup" in key_path) and "T1547.001" not in seen_techniques:
                    seen_techniques.add("T1547.001")
                    mappings.append(MITREMapping(
                        technique_id="T1547.001",
                        technique_name="Registry Run Keys / Startup Folder",
                        tactic="Persistence",
                        evidence=[f"Registry modification: {key_path}"],
                        confidence=0.85,
                    ))

            # Service creation
            if behavior.services_created and "T1543.003" not in seen_techniques:
                seen_techniques.add("T1543.003")
                mappings.append(MITREMapping(
                    technique_id="T1543.003",
                    technique_name="Windows Service",
                    tactic="Persistence",
                    evidence=[f"Services created: {behavior.services_created}"],
                    confidence=0.85,
                ))

            # Network communications
            if behavior.http_conversations and "T1071.001" not in seen_techniques:
                seen_techniques.add("T1071.001")
                mappings.append(MITREMapping(
                    technique_id="T1071.001",
                    technique_name="Web Protocols",
                    tactic="Command and Control",
                    evidence=["HTTP/HTTPS traffic observed"],
                    confidence=0.7,
                ))

            if behavior.dns_lookups and "T1071.004" not in seen_techniques:
                seen_techniques.add("T1071.004")
                domains = [d.get("hostname", "") for d in behavior.dns_lookups[:5]]
                mappings.append(MITREMapping(
                    technique_id="T1071.004",
                    technique_name="DNS",
                    tactic="Command and Control",
                    evidence=[f"DNS queries: {domains}"],
                    confidence=0.7,
                ))

        return mappings

    def build_attack_chain(
        self,
        mappings: List[MITREMapping],
    ) -> List[AttackChainStep]:
        """Build attack chain from MITRE mappings."""
        # Order tactics by typical attack progression
        tactic_order = [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact",
        ]

        # Group mappings by tactic
        tactics_seen = {}
        for mapping in mappings:
            tactic = mapping.tactic
            if tactic not in tactics_seen:
                tactics_seen[tactic] = []
            tactics_seen[tactic].append(mapping)

        # Build ordered chain
        chain = []
        order = 1

        for tactic in tactic_order:
            if tactic in tactics_seen:
                tactic_mappings = tactics_seen[tactic]
                techniques = [m.technique_id for m in tactic_mappings]
                artifacts = []
                network_activity = []

                for m in tactic_mappings:
                    artifacts.extend(m.evidence)

                chain.append(AttackChainStep(
                    order=order,
                    phase=tactic,
                    action=f"Uses {', '.join(techniques)}",
                    technique_id=techniques[0] if techniques else None,
                    artifacts=artifacts[:5],
                    network_activity=network_activity,
                ))
                order += 1

        return chain

    def infer_threat_profile(
        self,
        mappings: List[MITREMapping],
        vt_report: Optional[ParsedVTReport] = None,
    ) -> ThreatProfile:
        """Infer threat profile from MITRE mappings and VT data."""
        # Default values
        primary_category = ThreatCategory.UNKNOWN
        secondary_categories = []
        family_name = None
        severity = 5.0
        capabilities = []
        confidence = 0.5

        # Infer from MITRE techniques
        tactics = set(m.tactic for m in mappings)

        # Ransomware indicators
        if "Impact" in tactics:
            for m in mappings:
                if m.technique_id in ("T1486", "T1490"):
                    primary_category = ThreatCategory.RANSOMWARE
                    severity = 9.0
                    capabilities.append("encryption")
                    capabilities.append("recovery inhibition")
                    break

        # RAT/Backdoor indicators
        if "Command and Control" in tactics and "Persistence" in tactics:
            if primary_category == ThreatCategory.UNKNOWN:
                primary_category = ThreatCategory.RAT
            else:
                secondary_categories.append(ThreatCategory.RAT)
            capabilities.append("remote access")
            severity = max(severity, 7.0)

        # Infostealer indicators
        if "Credential Access" in tactics or "Collection" in tactics:
            for m in mappings:
                if m.technique_id in ("T1003", "T1003.001", "T1555", "T1555.003", "T1056.001"):
                    if primary_category == ThreatCategory.UNKNOWN:
                        primary_category = ThreatCategory.INFOSTEALER
                    else:
                        secondary_categories.append(ThreatCategory.INFOSTEALER)
                    capabilities.append("credential theft")
                    severity = max(severity, 7.5)
                    break

        # Downloader indicators
        if "Command and Control" in tactics and len(tactics) <= 3:
            for m in mappings:
                if m.technique_id == "T1105":
                    if primary_category == ThreatCategory.UNKNOWN:
                        primary_category = ThreatCategory.DOWNLOADER
                    else:
                        secondary_categories.append(ThreatCategory.DOWNLOADER)
                    capabilities.append("payload delivery")
                    severity = max(severity, 5.0)
                    break

        # Get family from VT if available
        if vt_report and vt_report.threat_intel_info.threat_label:
            family_name = vt_report.threat_intel_info.threat_label
            confidence = 0.8

            # Try to infer category from label
            label_lower = family_name.lower()
            if "ransom" in label_lower:
                primary_category = ThreatCategory.RANSOMWARE
            elif "trojan" in label_lower:
                primary_category = ThreatCategory.TROJAN
            elif "backdoor" in label_lower:
                primary_category = ThreatCategory.BACKDOOR
            elif "worm" in label_lower:
                primary_category = ThreatCategory.WORM
            elif "miner" in label_lower or "coin" in label_lower:
                primary_category = ThreatCategory.CRYPTOMINER
            elif "steal" in label_lower or "spy" in label_lower:
                primary_category = ThreatCategory.INFOSTEALER

        # If still unknown, default to trojan
        if primary_category == ThreatCategory.UNKNOWN:
            primary_category = ThreatCategory.TROJAN

        return ThreatProfile(
            primary_category=primary_category,
            secondary_categories=secondary_categories,
            family_name=family_name,
            severity=severity,
            capabilities=list(set(capabilities)),
            confidence=confidence,
        )
