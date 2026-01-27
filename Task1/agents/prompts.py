"""Prompt templates for Stage I agents.

All prompts are focused on extracting environment-specific information
needed for malware execution requirements.

All prompts use one-shot prompting with demonstration examples to establish
the expected reasoning pattern and output structure.
"""

# ============================================================================
# STATIC ANALYSIS PROMPTS
# ============================================================================

STATIC_ANALYSIS_PROMPT = """You are a malware static analysis expert.

## Task
Analyze the provided static information and extract observations about the malware's
environment requirements, dependencies, and execution constraints.

## Input Data
{input_data}

## Analysis Focus
1. **File Format**: PE32/PE64/ELF/script - determine target OS and architecture
2. **Import Analysis**: Analyze DLL imports and API calls for OS/dependency hints
3. **String Analysis**: Extract URLs, IPs, domains, configuration data, paths
4. **Packing/Obfuscation**: Detect packers and obfuscation techniques
5. **Dependencies**: Infer runtime requirements (.NET, Python, Java, etc.)
6. **OS Indicators**: Registry paths, file paths, API patterns indicating target OS

## Output Format (JSON)
{{
    "observations": [
        {{
            "content": "Specific observed fact",
            "category": "os_version|os_architecture|software_dependency|runtime_dependency|network_domain|network_ip|file_system|registry|anti_analysis",
            "evidence_type": "pe_header|imports|strings|packing|signature",
            "raw_data": {{"key": "value"}}
        }}
    ],
    "os_indicators": {{
        "target_os": "windows|linux|macos|unknown",
        "architecture": "x86|x64|arm|unknown",
        "min_version": "specific version if determinable",
        "evidence": ["list of supporting observations"]
    }},
    "dependencies": [
        {{"name": "dependency name", "type": "runtime|library|framework", "evidence": "why needed"}}
    ],
    "anti_analysis_features": [
        {{"type": "packing|obfuscation|anti_debug|anti_vm", "evidence": "supporting observation"}}
    ]
}}

## Example

### Example Input:
- File: WindowsUpdate.exe (PE32+ x86-64, 1.4MB)
- Imports: kernel32.dll (IsDebuggerPresent, CreateProcessW, VirtualProtect),
          advapi32.dll (RegOpenKeyExA, RegSetValueExA),
          ws2_32.dll (WSASocketW, connect, send, recv)
- Tags: detect-debug-environment, persistence, 64bits

### Example Output:
{{
    "observations": [
        {{
            "content": "64-bit Windows PE executable (PE32+ x86-64)",
            "category": "os_version",
            "evidence_type": "pe_header",
            "raw_data": {{"magic": "PE32+ executable", "arch": "x86-64"}}
        }},
        {{
            "content": "Imports IsDebuggerPresent for anti-debug detection",
            "category": "anti_analysis",
            "evidence_type": "imports",
            "raw_data": {{"dll": "kernel32.dll", "function": "IsDebuggerPresent"}}
        }},
        {{
            "content": "Registry manipulation via advapi32.dll APIs",
            "category": "registry",
            "evidence_type": "imports",
            "raw_data": {{"dll": "advapi32.dll", "functions": ["RegOpenKeyExA", "RegSetValueExA"]}}
        }},
        {{
            "content": "Network socket operations via ws2_32.dll",
            "category": "network_protocol",
            "evidence_type": "imports",
            "raw_data": {{"dll": "ws2_32.dll", "functions": ["WSASocketW", "connect", "send", "recv"]}}
        }}
    ],
    "os_indicators": {{
        "target_os": "windows",
        "architecture": "x64",
        "min_version": "Windows 7",
        "evidence": ["PE32+ format", "64-bit imports"]
    }},
    "dependencies": [],
    "anti_analysis_features": [
        {{"type": "anti_debug", "evidence": "IsDebuggerPresent import"}}
    ]
}}
"""

STATIC_HYPOTHESIS_PROMPT = """Based on the static analysis observations, generate hypotheses
about the malware's environment requirements.

## Observations
{observations}

## Analysis Summary
{analysis_summary}

## Generate hypotheses for:
1. **OS Requirements**: What OS version/architecture is required?
2. **Software Dependencies**: What software must be installed?
3. **Runtime Dependencies**: What runtimes are needed?
4. **Anti-Analysis**: What evasion techniques are used?
5. **File System**: What paths/files are required?

## Output Format (JSON)
{{
    "hypotheses": [
        {{
            "content": "Specific environment hypothesis",
            "category": "os_version|os_architecture|software_dependency|runtime_dependency|file_system|registry|anti_analysis",
            "confidence": 0.0-1.0,
            "reasoning": "Why this hypothesis is supported",
            "supporting_observations": ["list of observation IDs or categories"]
        }}
    ]
}}

## Example

### Example Observations:
- 64-bit Windows PE executable (PE32+ x86-64)
- Imports IsDebuggerPresent for anti-debug detection
- Registry manipulation via advapi32.dll APIs
- Network socket operations via ws2_32.dll

### Example Output:
{{
    "hypotheses": [
        {{
            "content": "Targets 64-bit Windows systems (Windows 7 or later)",
            "category": "os_version",
            "confidence": 0.95,
            "reasoning": "PE32+ format and x86-64 architecture indicate 64-bit Windows requirement",
            "supporting_observations": ["os_version"]
        }},
        {{
            "content": "Implements anti-debugging techniques",
            "category": "anti_analysis",
            "confidence": 0.9,
            "reasoning": "IsDebuggerPresent import indicates anti-debug capability",
            "supporting_observations": ["anti_analysis"]
        }},
        {{
            "content": "Requires network connectivity for C2 communication",
            "category": "network_protocol",
            "confidence": 0.85,
            "reasoning": "Socket APIs imported suggest network communication capability",
            "supporting_observations": ["network_protocol"]
        }}
    ]
}}
"""

# ============================================================================
# BEHAVIOR ANALYSIS PROMPTS
# ============================================================================

BEHAVIOR_ANALYSIS_PROMPT = """You are a malware behavior analysis expert.

## Task
Analyze the provided sandbox behavior data to extract observations about
network requirements, system interactions, and execution dependencies.

## Input Data
{input_data}

## Analysis Focus
1. **Network Behavior**: C2 communications, DNS queries, protocols, ports
2. **Process Behavior**: Process creation, injection, privilege escalation
3. **File Operations**: Files created/modified/deleted, persistence paths
4. **Registry Activity**: Persistence keys, configuration storage
5. **Command Execution**: Shell commands, PowerShell scripts
6. **API Calls**: System calls indicating capabilities and requirements

## Output Format (JSON)
{{
    "observations": [
        {{
            "content": "Specific observed behavior",
            "category": "network_protocol|network_port|network_domain|network_ip|file_system|registry|permission|software_dependency",
            "evidence_type": "dns_lookup|http_traffic|process_creation|file_write|registry_write|command_execution",
            "raw_data": {{"key": "value"}}
        }}
    ],
    "network_requirements": {{
        "requires_internet": true|false,
        "protocols": ["list of protocols used"],
        "ports": [list of ports],
        "domains": ["list of contacted domains"],
        "ips": ["list of contacted IPs"]
    }},
    "system_requirements": {{
        "requires_admin": true|false,
        "required_services": ["list of services"],
        "required_features": ["list of Windows features or system capabilities"]
    }},
    "persistence_mechanisms": [
        {{"type": "registry|scheduled_task|service|startup", "location": "specific path/key"}}
    ],
    "mitre_techniques": [
        {{"technique_id": "T1059.001", "technique_name": "PowerShell", "evidence": "observed behavior"}}
    ]
}}

## Example

### Example Input:
- Process: Creates scheduled task 'WindowsUpdateTask' via schtasks
- Registry: Writes to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- Network: DNS query to api.ipify.org, HTTPS to discord.com webhook
- Command: vssadmin delete shadows /all /quiet

### Example Output:
{{
    "observations": [
        {{
            "content": "Creates scheduled task 'WindowsUpdateTask' for persistence",
            "category": "software_dependency",
            "evidence_type": "command_execution",
            "raw_data": {{"command": "schtasks /create /tn WindowsUpdateTask..."}}
        }},
        {{
            "content": "Writes to Registry Run key for startup persistence",
            "category": "registry",
            "evidence_type": "registry_write",
            "raw_data": {{"key": "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"}}
        }},
        {{
            "content": "Queries external IP via api.ipify.org",
            "category": "network_domain",
            "evidence_type": "dns_lookup",
            "raw_data": {{"domain": "api.ipify.org", "purpose": "IP reconnaissance"}}
        }},
        {{
            "content": "Deletes volume shadow copies to prevent recovery",
            "category": "file_system",
            "evidence_type": "command_execution",
            "raw_data": {{"command": "vssadmin delete shadows /all /quiet"}}
        }}
    ],
    "network_requirements": {{
        "requires_internet": true,
        "protocols": ["HTTPS", "DNS"],
        "ports": [443, 53],
        "domains": ["api.ipify.org", "discord.com"],
        "ips": []
    }},
    "system_requirements": {{
        "requires_admin": true,
        "required_services": ["Task Scheduler"],
        "required_features": []
    }},
    "persistence_mechanisms": [
        {{"type": "scheduled_task", "location": "WindowsUpdateTask"}},
        {{"type": "registry", "location": "HKCU\\\\...\\\\Run"}}
    ],
    "mitre_techniques": [
        {{"technique_id": "T1053.005", "technique_name": "Scheduled Task", "evidence": "schtasks command"}},
        {{"technique_id": "T1547.001", "technique_name": "Registry Run Keys", "evidence": "Run key write"}},
        {{"technique_id": "T1490", "technique_name": "Inhibit System Recovery", "evidence": "vssadmin delete shadows"}}
    ]
}}
"""

BEHAVIOR_HYPOTHESIS_PROMPT = """Based on the behavior analysis observations, generate hypotheses
about the malware's network and system requirements.

## Observations
{observations}

## Analysis Summary
{analysis_summary}

## Generate hypotheses for:
1. **Network Requirements**: What network access is needed?
2. **System Requirements**: What permissions/features are required?
3. **Software Dependencies**: What software is invoked or required?
4. **Hardware/VM Detection**: Any VM/sandbox detection observed?

## Output Format (JSON)
{{
    "hypotheses": [
        {{
            "content": "Specific environment hypothesis",
            "category": "network_protocol|network_port|network_domain|network_ip|permission|software_dependency|hardware_cpu|hardware_memory|anti_analysis",
            "confidence": 0.0-1.0,
            "reasoning": "Why this hypothesis is supported by behavior",
            "supporting_observations": ["list of observation IDs or categories"]
        }}
    ]
}}

## Example

### Example Observations:
- Creates scheduled task 'WindowsUpdateTask' for persistence
- Writes to Registry Run key for startup persistence
- Queries external IP via api.ipify.org
- Deletes volume shadow copies to prevent recovery

### Example Output:
{{
    "hypotheses": [
        {{
            "content": "Requires administrator privileges for persistence and recovery inhibition",
            "category": "permission",
            "confidence": 0.95,
            "reasoning": "Scheduled task creation and shadow copy deletion require admin rights",
            "supporting_observations": ["software_dependency", "file_system"]
        }},
        {{
            "content": "Requires Task Scheduler service to be running",
            "category": "software_dependency",
            "confidence": 0.9,
            "reasoning": "Uses schtasks for persistence mechanism",
            "supporting_observations": ["software_dependency"]
        }},
        {{
            "content": "Requires outbound HTTPS access to external services",
            "category": "network_protocol",
            "confidence": 0.85,
            "reasoning": "Communicates with api.ipify.org and discord.com via HTTPS",
            "supporting_observations": ["network_domain"]
        }}
    ]
}}
"""

# ============================================================================
# THREAT INTELLIGENCE PROMPTS
# ============================================================================

THREAT_INTEL_PROMPT = """You are a threat intelligence analysis expert.

## Task
Analyze the provided threat intelligence data to extract observations about
the malware family, capabilities, and typical environment requirements.

## Input Data
{input_data}

## Analysis Focus
1. **Detection Analysis**: Interpret detection rates, vendor verdicts
2. **YARA Rules**: Analyze matched rules and their implications
3. **Malware Family**: Identify family and known characteristics
4. **Threat Classification**: Determine threat type and severity
5. **MITRE ATT&CK**: Map to ATT&CK techniques and tactics
6. **Known IOCs**: Extract indicators of compromise

## Confidence Rules
- HIGH (0.8-1.0): VT detection >= 20/70 with family consensus
- MEDIUM (0.5-0.8): VT detection 10-20/70 or mixed verdicts
- LOW (0.0-0.5): VT detection < 10/70 or significant disagreement

## Output Format (JSON)
{{
    "observations": [
        {{
            "content": "Specific threat intelligence observation",
            "category": "os_version|software_dependency|network_domain|network_ip|anti_analysis",
            "evidence_type": "vt_verdict|yara_match|malware_family|sandbox_verdict",
            "raw_data": {{"key": "value"}}
        }}
    ],
    "threat_profile": {{
        "malware_family": "family name or unknown",
        "threat_category": "trojan|ransomware|infostealer|backdoor|worm|rat|downloader|other",
        "severity": "critical|high|medium|low",
        "aliases": ["list of known aliases"],
        "confidence": 0.0-1.0
    }},
    "mitre_mapping": [
        {{
            "tactic": "tactic name",
            "technique_id": "T1xxx",
            "technique_name": "technique name",
            "evidence": "supporting evidence"
        }}
    ],
    "known_requirements": {{
        "target_os": ["list of known target OS"],
        "target_sectors": ["list of targeted sectors"],
        "known_c2": ["list of known C2 infrastructure"]
    }}
}}

## Example

### Example Input:
- VT Detection: 54/70 vendors flagged as malicious
- Classification: ransomware.oslockcrypt/rents
- Sandbox: Zenbox (RANSOM, 88% confidence), VMRay (RANSOM)
- YARA: INDICATOR_SUSPICIOUS_Binary_References_Browsers

### Example Output:
{{
    "observations": [
        {{
            "content": "High detection rate: 54/70 vendors classify as malicious",
            "category": "anti_analysis",
            "evidence_type": "vt_verdict",
            "raw_data": {{"malicious": 54, "total": 70, "rate": "77%"}}
        }},
        {{
            "content": "Classified as ransomware.oslockcrypt family",
            "category": "software_dependency",
            "evidence_type": "malware_family",
            "raw_data": {{"family": "oslockcrypt", "category": "ransomware"}}
        }},
        {{
            "content": "Multiple sandbox verdicts confirm ransomware behavior",
            "category": "anti_analysis",
            "evidence_type": "sandbox_verdict",
            "raw_data": {{"Zenbox": "RANSOM", "VMRay": "RANSOM"}}
        }}
    ],
    "threat_profile": {{
        "malware_family": "oslockcrypt",
        "threat_category": "ransomware",
        "severity": "critical",
        "aliases": ["rents", "locker"],
        "confidence": 0.95
    }},
    "mitre_mapping": [
        {{
            "tactic": "Impact",
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "evidence": "Ransomware classification"
        }}
    ],
    "known_requirements": {{
        "target_os": ["Windows 7", "Windows 10", "Windows 11"],
        "target_sectors": [],
        "known_c2": []
    }}
}}
"""

THREAT_INTEL_HYPOTHESIS_PROMPT = """Based on the threat intelligence observations, generate hypotheses
about the malware's environment requirements based on known family characteristics.

## Observations
{observations}

## Analysis Summary
{analysis_summary}

## Generate hypotheses for:
1. **OS Requirements**: What OS does this family typically target?
2. **Network Infrastructure**: Known C2 patterns and requirements
3. **Evasion Techniques**: Known anti-analysis capabilities
4. **Attack Chain**: Typical execution flow requirements

## Output Format (JSON)
{{
    "hypotheses": [
        {{
            "content": "Specific environment hypothesis based on threat intel",
            "category": "os_version|os_architecture|network_protocol|network_domain|network_ip|anti_analysis",
            "confidence": 0.0-1.0,
            "reasoning": "Why this hypothesis is supported by threat intel",
            "supporting_observations": ["list of observation IDs or categories"]
        }}
    ]
}}

## Example

### Example Observations:
- High detection rate: 54/70 vendors classify as malicious
- Classified as ransomware.oslockcrypt family
- Multiple sandbox verdicts confirm ransomware behavior

### Example Output:
{{
    "hypotheses": [
        {{
            "content": "Targets Windows desktop systems for ransomware deployment",
            "category": "os_version",
            "confidence": 0.9,
            "reasoning": "Ransomware families typically target Windows desktop environments",
            "supporting_observations": ["software_dependency", "anti_analysis"]
        }},
        {{
            "content": "May employ sandbox/VM detection to evade analysis",
            "category": "anti_analysis",
            "confidence": 0.8,
            "reasoning": "High-profile ransomware commonly includes anti-analysis capabilities",
            "supporting_observations": ["anti_analysis"]
        }}
    ]
}}
"""

# ============================================================================
# DELIBERATION PROMPTS
# ============================================================================

CONFLICT_DETECTION_PROMPT = """You are a conflict detection expert in an argumentation framework.

## Task
Identify conflicts between hypotheses from different agents.

## Hypotheses from Static Agent:
{static_hypotheses}

## Hypotheses from Behavior Agent:
{behavior_hypotheses}

## Hypotheses from Threat Intel Agent:
{threat_intel_hypotheses}

## Identify conflicts:
1. **Contradictions**: Hypotheses that directly contradict each other
2. **Subsumptions**: One hypothesis subsumes/generalizes another
3. **Incompatibilities**: Hypotheses that cannot both be true

## Output Format (JSON)
{{
    "conflicts": [
        {{
            "hypothesis_a_id": "ID of first hypothesis",
            "hypothesis_b_id": "ID of second hypothesis",
            "conflict_type": "contradiction|subsumption|incompatibility",
            "description": "Description of the conflict",
            "severity": 0.0-1.0
        }}
    ]
}}

## Example

### Example Hypotheses:
- Static Agent: "Requires Windows 10 or later (confidence: 0.8)"
- Behavior Agent: "Requires Windows 7 SP1 or later (confidence: 0.9)"
- Threat Intel Agent: "Targets Windows XP through Windows 11 (confidence: 0.7)"

### Example Output:
{{
    "conflicts": [
        {{
            "hypothesis_a_id": "static_h1",
            "hypothesis_b_id": "behavior_h1",
            "conflict_type": "subsumption",
            "description": "Static agent claims Windows 10+ while Behavior agent claims Windows 7+. The Windows 7+ requirement subsumes Windows 10+.",
            "severity": 0.6
        }},
        {{
            "hypothesis_a_id": "static_h1",
            "hypothesis_b_id": "threat_intel_h1",
            "conflict_type": "contradiction",
            "description": "Static agent claims Windows 10+ but threat intel suggests XP compatibility, which contradicts the minimum version requirement.",
            "severity": 0.8
        }}
    ]
}}
"""

DELIBERATION_PROMPT = """You are a deliberation coordinator resolving conflicts between hypotheses.

## Conflicting Hypotheses
Hypothesis A: {hypothesis_a}
Hypothesis B: {hypothesis_b}

## Conflict Type: {conflict_type}
## Conflict Description: {conflict_description}

## Supporting Evidence for A:
{evidence_a}

## Supporting Evidence for B:
{evidence_b}

## Task
Analyze the conflict and determine:
1. Which hypothesis is better supported by evidence?
2. Can the hypotheses be merged or refined?
3. What is the resolution reasoning?

## Output Format (JSON)
{{
    "resolution": "accept_a|accept_b|merge|both_valid|neither",
    "reasoning": "Detailed reasoning for the resolution",
    "merged_hypothesis": {{
        "content": "Merged hypothesis if applicable",
        "confidence": 0.0-1.0
    }},
    "modifications": [
        {{
            "target_hypothesis_id": "ID to modify",
            "new_content": "Modified content",
            "new_confidence": 0.0-1.0
        }}
    ]
}}

## Example

### Example Conflict:
- Hypothesis A: "Requires Windows 10 or later" (Static Agent, confidence: 0.8)
- Hypothesis B: "Requires Windows 7 SP1 or later" (Behavior Agent, confidence: 0.9)
- Conflict Type: subsumption
- Evidence A: PE header indicates Win10 SDK compilation
- Evidence B: Observed execution on Windows 7 sandbox, uses APIs available since Win7

### Example Output:
{{
    "resolution": "accept_b",
    "reasoning": "Behavioral evidence of successful execution on Windows 7 is stronger than static compilation hints. The malware demonstrably runs on Windows 7, so requiring Windows 10+ is incorrect. The PE compilation target does not preclude backward compatibility.",
    "merged_hypothesis": null,
    "modifications": [
        {{
            "target_hypothesis_id": "static_h1",
            "new_content": "Compiled with Windows 10 SDK but compatible with Windows 7+",
            "new_confidence": 0.7
        }}
    ]
}}
"""

# ============================================================================
# ADVERSARIAL DEBATE PROMPTS
# ============================================================================

CHALLENGE_HYPOTHESIS_PROMPT = """You are {agent_name}, an expert in {domain}.

## Your Task
Challenge the following hypothesis proposed by another agent. Identify weaknesses,
gaps in evidence, or logical flaws based on YOUR domain expertise and observations.

## Hypothesis to Challenge
- **ID**: {hypothesis_id}
- **Source Agent**: {hypothesis_source}
- **Content**: {hypothesis_content}
- **Confidence**: {hypothesis_confidence}
- **Category**: {hypothesis_category}

## Supporting Evidence for This Hypothesis
{supporting_evidence}

## Your Observations (from your domain that may contradict or undermine this hypothesis)
{your_observations}

## Challenge Instructions
1. Identify specific weaknesses in the hypothesis from YOUR domain's perspective
2. Cite your observations that contradict or complicate the hypothesis
3. Explain WHY your evidence undermines the hypothesis
4. Suggest how the hypothesis should be modified or rejected
5. Rate the severity of your challenge (0.0 = minor, 1.0 = fatal flaw)

## Output Format (JSON)
{{
    "challenge_type": "evidence_gap|logical_flaw|contradiction|insufficient_support|overgeneralization",
    "challenge_content": "Your detailed challenge explaining the weakness",
    "counter_evidence": ["list of your observation IDs that support your challenge"],
    "severity": 0.0-1.0,
    "suggested_modification": "How the hypothesis should be changed, or null if it should be rejected",
    "reasoning": "Step-by-step reasoning for your challenge"
}}

## Example

### Example Hypothesis to Challenge:
- ID: static_h2
- Source Agent: Static Analysis Agent
- Content: "Malware does not require network connectivity"
- Confidence: 0.75
- Category: network_protocol
- Supporting Evidence: "No network-related imports found in static analysis"

### Example Your Observations (Behavior Agent):
- Observed DNS queries to api.ipify.org during execution
- HTTPS connections to discord.com webhook endpoint
- Network traffic on ports 443 and 53

### Example Output:
{{
    "challenge_type": "contradiction",
    "challenge_content": "The hypothesis that malware does not require network connectivity is contradicted by observed runtime behavior. During sandbox execution, the malware made DNS queries to api.ipify.org for IP reconnaissance and established HTTPS connections to discord.com, indicating clear network dependency for C2 communication.",
    "counter_evidence": ["behavior_obs_dns_ipify", "behavior_obs_https_discord"],
    "severity": 0.95,
    "suggested_modification": "Requires network connectivity for C2 communication via HTTPS to external services",
    "reasoning": "1. Static analysis may miss dynamically resolved imports or obfuscated network code. 2. Runtime behavior definitively shows network activity. 3. Multiple network observations across different protocols (DNS, HTTPS) confirm network dependency. 4. The original hypothesis should be rejected in favor of network requirement."
}}
"""

REBUTTAL_PROMPT = """You are {agent_name}, defending your hypothesis against a challenge.

## Your Hypothesis Under Attack
- **ID**: {hypothesis_id}
- **Content**: {hypothesis_content}
- **Current Confidence**: {hypothesis_confidence}

## Challenge from {challenger_name}
- **Challenge Type**: {challenge_type}
- **Challenge**: {challenge_content}
- **Counter-Evidence Cited**: {counter_evidence}
- **Severity**: {challenge_severity}
- **Suggested Modification**: {suggested_modification}

## Your Supporting Evidence
{your_evidence}

## Rebuttal Instructions
1. Address the specific weaknesses identified in the challenge
2. Explain why your evidence is still valid despite the counter-evidence
3. Identify any flaws in the challenger's reasoning
4. Decide whether to:
   - Fully defend your hypothesis (no modification needed)
   - Accept the modification (challenger had valid points)
   - Propose a refined hypothesis that addresses the concerns
5. Adjust your confidence based on the challenge validity

## Output Format (JSON)
{{
    "rebuttal_content": "Your detailed defense of the hypothesis",
    "supporting_evidence": ["observation IDs that support your rebuttal"],
    "accepts_modification": true|false,
    "proposed_refinement": "Refined hypothesis content if you accept partial criticism, or null if unchanged",
    "confidence_adjustment": -0.5 to +0.5,
    "reasoning": "Step-by-step reasoning for your rebuttal decision"
}}

## Example

### Example Hypothesis Under Attack:
- ID: static_h2
- Content: "Malware does not require network connectivity"
- Current Confidence: 0.75

### Example Challenge from Behavior Agent:
- Challenge Type: contradiction
- Challenge: "Runtime behavior shows DNS queries and HTTPS connections"
- Counter-Evidence: DNS to api.ipify.org, HTTPS to discord.com
- Severity: 0.95
- Suggested Modification: "Requires network connectivity for C2 communication"

### Example Your Supporting Evidence:
- No network-related imports in IAT
- No hardcoded URLs/IPs in strings

### Example Output:
{{
    "rebuttal_content": "I accept the challenge. While static analysis did not reveal network imports or strings, this was likely due to dynamic API resolution or obfuscation techniques that hide network capabilities. The behavioral evidence of actual network communication is definitive and overrides the static analysis findings.",
    "supporting_evidence": ["static_obs_no_network_imports"],
    "accepts_modification": true,
    "proposed_refinement": "Requires network connectivity for C2 communication; network APIs may be dynamically resolved or obfuscated",
    "confidence_adjustment": -0.5,
    "reasoning": "1. Static analysis has known limitations with obfuscated/packed malware. 2. Behavioral evidence of network activity is concrete proof. 3. The absence of evidence in static analysis is not evidence of absence. 4. Accept modification while noting static analysis limitations."
}}
"""

CROSS_VALIDATION_PROMPT = """You are {agent_name}, reviewing hypotheses from other agents.

## Your Domain Expertise
{domain_description}

## Your Observations
{your_observations}

## Hypotheses to Validate
{hypotheses_to_validate}

## Validation Instructions
For each hypothesis from other agents:
1. Does your evidence SUPPORT, remain NEUTRAL toward, or OPPOSE this hypothesis?
2. What specific observations support your verdict?
3. How should this affect the hypothesis confidence?

Be objective - even if a hypothesis conflicts with your own, evaluate it fairly based on evidence.

## Output Format (JSON)
{{
    "validations": [
        {{
            "hypothesis_id": "ID being validated",
            "verdict": "support|neutral|oppose",
            "reasoning": "Why your evidence leads to this verdict",
            "confidence_modifier": -0.3 to +0.3,
            "relevant_observations": ["your observation IDs relevant to this validation"]
        }}
    ]
}}

## Example

### Example Your Domain (Threat Intel Agent):
You specialize in malware family attribution, known TTPs, and threat landscape knowledge.

### Example Your Observations:
- Classified as ransomware.oslockcrypt family
- 54/70 VT detection rate
- Known to target Windows desktop systems
- Family documented to use shadow copy deletion

### Example Hypotheses to Validate:
1. behavior_h1: "Requires administrator privileges" (Behavior Agent, confidence: 0.95)
2. static_h1: "Targets 64-bit Windows systems" (Static Agent, confidence: 0.9)

### Example Output:
{{
    "validations": [
        {{
            "hypothesis_id": "behavior_h1",
            "verdict": "support",
            "reasoning": "The oslockcrypt ransomware family is documented to require admin privileges for shadow copy deletion and system modifications. This aligns with known family behavior.",
            "confidence_modifier": 0.15,
            "relevant_observations": ["ti_obs_family_oslockcrypt", "ti_obs_shadow_copy_ttp"]
        }},
        {{
            "hypothesis_id": "static_h1",
            "verdict": "support",
            "reasoning": "Threat intelligence indicates oslockcrypt primarily targets modern Windows desktop systems (Windows 7-11), which are predominantly 64-bit. This supports the 64-bit targeting hypothesis.",
            "confidence_modifier": 0.1,
            "relevant_observations": ["ti_obs_target_windows_desktop"]
        }}
    ]
}}
"""

REFINEMENT_SYNTHESIS_PROMPT = """You are {agent_name}, refining your hypothesis based on debate feedback.

## Original Hypothesis
- **ID**: {hypothesis_id}
- **Content**: {original_content}
- **Original Confidence**: {original_confidence}

## Debate Summary

### Challenges Received:
{challenges_summary}

### Your Rebuttals:
{rebuttals_summary}

### Cross-Validation Results:
{validation_summary}

## Refinement Task
Synthesize ALL feedback into a refined hypothesis that:
1. Addresses valid criticisms from challengers
2. Incorporates supporting evidence from validators
3. Maintains consistency with your original domain observations
4. Has an appropriate confidence level based on the debate outcome

## Output Format (JSON)
{{
    "refined_content": "The refined hypothesis content",
    "refined_confidence": 0.0-1.0,
    "incorporated_feedback": ["list of feedback items you incorporated"],
    "rejected_feedback": [
        {{
            "feedback": "feedback item",
            "reason": "why you rejected it"
        }}
    ],
    "changes_made": "Summary of how the hypothesis changed",
    "reasoning": "How you arrived at this refinement"
}}
"""

DEBATE_SUMMARY_PROMPT = """Summarize the debate outcome between two hypotheses.

## Hypothesis A
- **ID**: {hypothesis_a_id}
- **Content**: {hypothesis_a_content}
- **Initial Confidence**: {hypothesis_a_initial_conf}
- **Final Confidence**: {hypothesis_a_final_conf}

## Hypothesis B
- **ID**: {hypothesis_b_id}
- **Content**: {hypothesis_b_content}
- **Initial Confidence**: {hypothesis_b_initial_conf}
- **Final Confidence**: {hypothesis_b_final_conf}

## Debate Rounds
{debate_rounds_summary}

## Task
Provide a concise summary of:
1. The core conflict
2. Key arguments from each side
3. What evidence was most persuasive
4. The final resolution

## Output Format (JSON)
{{
    "conflict_summary": "One sentence describing the core conflict",
    "key_arguments_a": ["main arguments for hypothesis A"],
    "key_arguments_b": ["main arguments for hypothesis B"],
    "decisive_evidence": "What evidence was most persuasive",
    "resolution": "accept_a|accept_b|merge|both_valid",
    "resolution_reasoning": "Why this resolution was reached"
}}
"""
