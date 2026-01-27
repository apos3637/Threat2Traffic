from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class StaticInfo:
    file_hash: str
    type_description: Optional[str] = None
    magic: Optional[str] = None
    size: Optional[int] = None
    names: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    signature_info: Optional[Dict[str, Any]] = None
    pe_info: Optional[Dict[str, Any]] = None
    elf_info: Optional[Dict[str, Any]] = None
    import_list: List[str] = field(default_factory=list)
    export_list: List[str] = field(default_factory=list)


@dataclass
class BehaviorInfo:
    sandbox_name: str
    processes: List[Dict[str, Any]] = field(default_factory=list)
    process_tree: List[Dict[str, Any]] = field(default_factory=list)
    dns_lookups: List[Dict[str, Any]] = field(default_factory=list)
    ip_traffic: List[Dict[str, Any]] = field(default_factory=list)
    http_conversations: List[Dict[str, Any]] = field(default_factory=list)
    registry_keys_set: List[Dict[str, Any]] = field(default_factory=list)
    registry_keys_deleted: List[str] = field(default_factory=list)
    files_written: List[str] = field(default_factory=list)
    files_deleted: List[str] = field(default_factory=list)
    files_opened: List[str] = field(default_factory=list)
    command_executions: List[str] = field(default_factory=list)
    modules_loaded: List[str] = field(default_factory=list)
    services_created: List[str] = field(default_factory=list)
    mitre_attack_techniques: List[Dict[str, Any]] = field(default_factory=list)
    sigma_analysis_results: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ThreatIntelInfo:
    file_hash: str
    threat_label: Optional[str] = None
    popular_threat_classification: Optional[Dict[str, Any]] = None
    yara_rules: List[Dict[str, Any]] = field(default_factory=list)
    sandbox_verdicts: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    last_analysis_stats: Optional[Dict[str, int]] = None
    total_votes: Optional[Dict[str, int]] = None
    mitre_attack_techniques: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ParsedVTReport:
    file_hash: str
    static_info: StaticInfo
    behavior_info: List[BehaviorInfo]
    threat_intel_info: ThreatIntelInfo
    raw_report: Dict[str, Any]


class VTReportParser:

    def parse(self, raw_report: Dict[str, Any]) -> ParsedVTReport:
        file_report = raw_report.get("file_report", {})
        behaviors_data = raw_report.get("behaviors")

        file_data = file_report.get("data", {})
        attributes = file_data.get("attributes", {})
        file_hash = file_data.get("id", "")

        static_info = self._parse_static_info(file_hash, attributes)
        behavior_info = self._parse_behavior_info(behaviors_data)
        threat_intel_info = self._parse_threat_intel_info(file_hash, attributes)

        return ParsedVTReport(
            file_hash=file_hash,
            static_info=static_info,
            behavior_info=behavior_info,
            threat_intel_info=threat_intel_info,
            raw_report=raw_report,
        )

    def _parse_static_info(
        self, file_hash: str, attributes: Dict[str, Any]
    ) -> StaticInfo:
        pe_info = attributes.get("pe_info")
        import_list = []
        export_list = []

        if pe_info:
            for imp in pe_info.get("import_list", []):
                lib_name = imp.get("library_name", "")
                for func in imp.get("imported_functions", []):
                    import_list.append(f"{lib_name}:{func}")

            export_list = pe_info.get("exports", [])

        return StaticInfo(
            file_hash=file_hash,
            type_description=attributes.get("type_description"),
            magic=attributes.get("magic"),
            size=attributes.get("size"),
            names=attributes.get("names", [])[:20],
            tags=attributes.get("tags", []),
            signature_info=attributes.get("signature_info"),
            pe_info=pe_info,
            elf_info=attributes.get("elf_info"),
            import_list=import_list[:100],
            export_list=export_list[:50],
        )

    def _parse_behavior_info(
        self, behaviors_data: Optional[Dict[str, Any]]
    ) -> List[BehaviorInfo]:
        if not behaviors_data:
            return []

        behaviors = []
        for behavior in behaviors_data.get("data", []):
            attrs = behavior.get("attributes", {})
            sandbox_name = attrs.get("sandbox_name", "unknown")

            behavior_info = BehaviorInfo(
                sandbox_name=sandbox_name,
                processes=attrs.get("processes", []),
                process_tree=attrs.get("processes_tree", []),
                dns_lookups=attrs.get("dns_lookups", []),
                ip_traffic=attrs.get("ip_traffic", []),
                http_conversations=attrs.get("http_conversations", []),
                registry_keys_set=attrs.get("registry_keys_set", []),
                registry_keys_deleted=attrs.get("registry_keys_deleted", []),
                files_written=attrs.get("files_written", []),
                files_deleted=attrs.get("files_deleted", []),
                files_opened=attrs.get("files_opened", []),
                command_executions=attrs.get("command_executions", []),
                modules_loaded=attrs.get("modules_loaded", []),
                services_created=attrs.get("services_created", []),
                mitre_attack_techniques=attrs.get("mitre_attack_techniques", []),
                sigma_analysis_results=attrs.get("sigma_analysis_results", []),
            )
            behaviors.append(behavior_info)

        return behaviors

    def _parse_threat_intel_info(
        self, file_hash: str, attributes: Dict[str, Any]
    ) -> ThreatIntelInfo:
        yara_rules = []
        for rule in attributes.get("crowdsourced_yara_results", []):
            yara_rules.append({
                "rule_name": rule.get("rule_name"),
                "ruleset_name": rule.get("ruleset_name"),
                "description": rule.get("description"),
                "source": rule.get("source"),
            })

        sandbox_verdicts = {}
        for verdict in attributes.get("sandbox_verdicts", {}).values():
            if isinstance(verdict, dict):
                sandbox_name = verdict.get("sandbox_name", "unknown")
                sandbox_verdicts[sandbox_name] = {
                    "category": verdict.get("category"),
                    "confidence": verdict.get("confidence"),
                    "malware_classification": verdict.get("malware_classification", []),
                }

        mitre_techniques = []
        for sandbox_data in attributes.get("sandbox_verdicts", {}).values():
            if isinstance(sandbox_data, dict):
                techniques = sandbox_data.get("mitre_attack_techniques", [])
                for tech in techniques:
                    mitre_techniques.append(tech)

        return ThreatIntelInfo(
            file_hash=file_hash,
            threat_label=attributes.get("popular_threat_classification", {}).get(
                "suggested_threat_label"
            ),
            popular_threat_classification=attributes.get(
                "popular_threat_classification"
            ),
            yara_rules=yara_rules,
            sandbox_verdicts=sandbox_verdicts,
            last_analysis_stats=attributes.get("last_analysis_stats"),
            total_votes=attributes.get("total_votes"),
            mitre_attack_techniques=mitre_techniques,
        )

    def extract_static_for_agent(self, parsed: ParsedVTReport) -> Dict[str, Any]:
        static = parsed.static_info
        return {
            "file_hash": static.file_hash,
            "type_description": static.type_description,
            "magic": static.magic,
            "size": static.size,
            "names": static.names,
            "tags": static.tags,
            "signature_info": static.signature_info,
            "pe_info": static.pe_info,
            "elf_info": static.elf_info,
            "import_list": static.import_list,
            "export_list": static.export_list,
        }

    def extract_behavior_for_agent(self, parsed: ParsedVTReport) -> Dict[str, Any]:
        all_processes = []
        all_dns = []
        all_ip = []
        all_http = []
        all_registry_set = []
        all_files_written = []
        all_commands = []
        all_mitre = []
        all_sigma = []

        for behavior in parsed.behavior_info:
            all_processes.extend(behavior.process_tree)
            all_dns.extend(behavior.dns_lookups)
            all_ip.extend(behavior.ip_traffic)
            all_http.extend(behavior.http_conversations)
            all_registry_set.extend(behavior.registry_keys_set)
            all_files_written.extend(behavior.files_written)
            all_commands.extend(behavior.command_executions)
            all_mitre.extend(behavior.mitre_attack_techniques)
            all_sigma.extend(behavior.sigma_analysis_results)

        return {
            "sandbox_count": len(parsed.behavior_info),
            "sandbox_names": [b.sandbox_name for b in parsed.behavior_info],
            "process_tree": all_processes[:50],
            "dns_lookups": all_dns[:50],
            "ip_traffic": all_ip[:50],
            "http_conversations": all_http[:30],
            "registry_keys_set": all_registry_set[:50],
            "files_written": all_files_written[:50],
            "command_executions": all_commands[:30],
            "mitre_attack_techniques": all_mitre,
            "sigma_analysis_results": all_sigma[:30],
        }

    def extract_threat_intel_for_agent(self, parsed: ParsedVTReport) -> Dict[str, Any]:
        intel = parsed.threat_intel_info
        return {
            "file_hash": intel.file_hash,
            "threat_label": intel.threat_label,
            "popular_threat_classification": intel.popular_threat_classification,
            "yara_rules": intel.yara_rules,
            "sandbox_verdicts": intel.sandbox_verdicts,
            "last_analysis_stats": intel.last_analysis_stats,
            "total_votes": intel.total_votes,
            "mitre_attack_techniques": intel.mitre_attack_techniques,
        }
