"""Installation script generator using LLM."""

from typing import List, Optional, Dict, Any
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from Task1.spec_extractor.models import SoftwareDependency
from Task1.utils.llm_client import LLMClient
from Task2.config import get_config, LLMConfig
from Task2.models import GeneratedScript


# Prompt templates for script generation
LINUX_SCRIPT_PROMPT = """Generate a cloud-init compatible bash script that installs the following software dependencies on a Linux system.

Requirements:
1. The script should be idempotent (safe to run multiple times)
2. Use appropriate package managers (apt, yum, dnf) based on the distro
3. Include error handling
4. Do NOT include interactive prompts
5. The script will run as root via cloud-init

Dependencies to install:
{dependencies}

Output ONLY the bash script, starting with #!/bin/bash
Do not include any explanations or markdown formatting."""


WINDOWS_SCRIPT_PROMPT = """Generate a PowerShell script that installs the following software dependencies on Windows.

Requirements:
1. The script should be idempotent (safe to run multiple times)
2. Use Chocolatey or direct downloads where appropriate
3. Include error handling with try/catch
4. Do NOT include interactive prompts
5. The script will run as SYSTEM during first boot

Dependencies to install:
{dependencies}

Output ONLY the PowerShell script, starting with #Requires -RunAsAdministrator
Do not include any explanations or markdown formatting."""


class ScriptGenerator:
    """Generate installation scripts using LLM."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        if llm_client:
            self.llm_client = llm_client
        else:
            config = get_config()
            llm_config = LLMConfig(
                api_key=config.llm.api_key,
                base_url=config.llm.base_url,
                model=config.llm.model,
                temperature=0.2,  # Lower temperature for code generation
            )
            from Task1.utils.llm_client import LLMClient
            self.llm_client = LLMClient(llm_config)

    async def generate_user_data(
        self,
        os_family: str,
        dependencies: List[SoftwareDependency],
    ) -> GeneratedScript:
        """Generate cloud-init/user_data script for installing dependencies.

        Args:
            os_family: OS family ("windows", "linux")
            dependencies: List of software dependencies to install

        Returns:
            GeneratedScript with content and metadata
        """
        description = f"Install {len(dependencies)} dependencies"

        if not dependencies:
            script = self._generate_minimal_script(os_family)
            if os_family == "windows":
                return GeneratedScript.powershell(script, "Minimal setup script")
            else:
                return GeneratedScript.bash(script, "Minimal setup script")

        # Format dependencies for prompt
        dep_text = self._format_dependencies(dependencies)

        # Select appropriate prompt template
        if os_family == "windows":
            prompt = WINDOWS_SCRIPT_PROMPT.format(dependencies=dep_text)
        else:
            prompt = LINUX_SCRIPT_PROMPT.format(dependencies=dep_text)

        # Generate script via LLM
        messages = [{"role": "user", "content": prompt}]

        try:
            response = await self.llm_client.chat(messages, temperature=0.2)
            script = response.content.strip()

            # Clean up any markdown formatting
            script = self._clean_script(script)

            # Validate script syntax
            if os_family == "windows":
                self._validate_powershell(script)
                return GeneratedScript.powershell(script, description)
            else:
                self._validate_bash(script)
                return GeneratedScript.bash(script, description)

        except Exception as e:
            # Fall back to minimal script on error
            script = self._generate_fallback_script(os_family, dependencies, str(e))
            if os_family == "windows":
                return GeneratedScript.powershell(script, f"Fallback: {description}")
            else:
                return GeneratedScript.bash(script, f"Fallback: {description}")

    def _format_dependencies(self, dependencies: List[SoftwareDependency]) -> str:
        """Format dependencies list for LLM prompt."""
        lines = []
        for dep in dependencies:
            line = f"- {dep.name}"
            if dep.type:
                line += f" (type: {dep.type})"
            if dep.version_constraint:
                line += f" version {dep.version_constraint}"
            if dep.purpose:
                line += f" - {dep.purpose}"
            lines.append(line)
        return "\n".join(lines)

    def _clean_script(self, script: str) -> str:
        """Remove markdown formatting from script."""
        # Remove code block markers
        if script.startswith("```"):
            lines = script.split("\n")
            # Remove first line (```bash or ```powershell)
            lines = lines[1:]
            # Remove last line if it's ```
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            script = "\n".join(lines)

        return script.strip()

    def _validate_bash(self, script: str) -> None:
        """Basic validation for bash script."""
        if not script.startswith("#!"):
            # Add shebang if missing
            pass  # We'll add it in fallback

        # Check for obviously dangerous patterns
        dangerous_patterns = ["rm -rf /", "dd if=/dev/zero", "> /dev/sda"]
        for pattern in dangerous_patterns:
            if pattern in script:
                raise ValueError(f"Dangerous pattern detected in script: {pattern}")

    def _validate_powershell(self, script: str) -> None:
        """Basic validation for PowerShell script."""
        # Check for obviously dangerous patterns
        dangerous_patterns = ["Format-Volume", "Remove-Item -Recurse -Force C:\\"]
        for pattern in dangerous_patterns:
            if pattern in script:
                raise ValueError(f"Dangerous pattern detected in script: {pattern}")

    def _generate_minimal_script(self, os_family: str) -> str:
        """Generate minimal script when no dependencies specified."""
        if os_family == "windows":
            return """#Requires -RunAsAdministrator
# Minimal setup script - no additional dependencies specified
Write-Host "Environment initialization complete"
"""
        else:
            return """#!/bin/bash
# Minimal setup script - no additional dependencies specified
echo "Environment initialization complete"
"""

    def _generate_fallback_script(
        self,
        os_family: str,
        dependencies: List[SoftwareDependency],
        error: str,
    ) -> str:
        """Generate fallback script when LLM fails."""
        dep_names = [dep.name for dep in dependencies]

        if os_family == "windows":
            # Basic PowerShell fallback
            choco_installs = " ".join(dep_names)
            return f"""#Requires -RunAsAdministrator
# Fallback script (LLM generation failed: {error})

# Install Chocolatey if not present
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {{
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}}

# Install dependencies
$packages = @({', '.join(f'"{n}"' for n in dep_names)})
foreach ($pkg in $packages) {{
    try {{
        choco install $pkg -y --no-progress
    }} catch {{
        Write-Warning "Failed to install $pkg"
    }}
}}

Write-Host "Setup complete"
"""
        else:
            # Basic bash fallback
            apt_installs = " ".join(dep_names)
            return f"""#!/bin/bash
# Fallback script (LLM generation failed: {error})
set -e

# Detect package manager
if command -v apt-get &> /dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y {apt_installs} || true
elif command -v yum &> /dev/null; then
    yum install -y {apt_installs} || true
elif command -v dnf &> /dev/null; then
    dnf install -y {apt_installs} || true
fi

echo "Setup complete"
"""

    async def close(self):
        """Close the LLM client."""
        if self.llm_client:
            await self.llm_client.close()
