# Threat2Traffic

## Overview
This repo contains the core source code of the two-stage framework of Threat2Traffic

Threat2Traffic addresses the data scarcity problem in cybersecurity research by automatically synthesizing tailored execution environments that trigger authentic malware behaviors. This dataset comprises PCAP files capturing real malware network traffic across 8 malware families.

## Repository Structure

```
.
├── Task1/
├── Task2/
└── pcap/
    ├── adware/
    │   ├── 1.pcap
    │   └── ...
    ├── coinminer/
    │   ├── 1.pcap
    │   └── ...
    ├── downloader/
    │   ├── 1.pcap
    │   └── ...
    ├── infostealer/
    │   ├── 1.pcap
    │   └── ...
    ├── ransomware/
    │   ├── 1.pcap
    │   └── ...
    ├── rat/
    │   ├── 1.pcap
    │   └── ...
    ├── spyware/
    │   ├── 1.pcap
    │   └── ...
    └── vidar/
        ├── 1.pcap
        └── ...
```

## Installation

### Prerequisites

- We recommand using [uv](https://github.com/astral-sh/uv) for virtual environment and 

### Setup

1. Clone the repository:
```bash
git clone https://github.com/apos3637/Threat2Traffic.git
cd Threat2Traffic
```

2. Install dependencies using uv:
```bash
uv sync
```

Or using pip:
```bash
pip install -r requirements.txt
```

### Dependencies

| Package | Version | Description |
|---------|---------|-------------|
| httpx | 0.28.1 | Async HTTP client |
| python-dotenv | 1.2.1 | Environment variable management |
| pyyaml | 6.0.3 | YAML parsing |
| numpy | 2.4.1 | Numerical computing |
| matplotlib | 3.10.8 | Visualization |
| pytest | 9.0.2 | Testing framework (dev) |

## Configuration

### Environment Variables

Copy the example files and configure your API keys:

```bash
cp Task1/.env.example Task1/.env
cp Task2/.env.example Task2/.env
```

#### Task1 Configuration (`Task1/.env`)

| Variable | Required | Description |
|----------|----------|-------------|
| `VT_API_KEY` | Yes | VirusTotal API key for malware analysis |
| `LLM_API_KEY` | Yes | LLM API key (e.g., DeepSeek, OpenAI) |
| `LLM_BASE_URL` | No | LLM API base URL (default: DeepSeek, (Openai competitable format) )|
| `LLM_MODEL` | No | LLM model name (default: deepseek-chat) |

#### Task2 Configuration (`Task2/.env`)

| Variable | Required | Description |
|----------|----------|-------------|
| `LLM_API_KEY` | Yes | LLM API key |
| `LLM_BASE_URL` | No | LLM API base URL |
| `LLM_MODEL` | No | LLM model name |


## Usage

### Task1: Environment Specification Extraction

```bash
uv run python -m Task1.main <malware_sample_path>
```

### Task2: Constraint Acquisition, Prompt Assembly and Validation

> **Note:** Task2 provides constraint compilation, adaptive prompt assembly, and syntax/semantic validation. It does **not** include an LLM generation function — users need to supply their own LLM calling logic to consume the assembled prompt and produce Terraform HCL.

#### Compile platform constraints

```bash
# Dump full provider schema (YAML)
uv run python -m Task2.cli constraint --provider qemu

# Compile filtered constraints from a spec
uv run python -m Task2.cli constraint --spec <spec.json> --provider qemu

# JSON-only output
uv run python -m Task2.cli constraint --spec <spec.json> --provider qemu --json
```

#### Adaptive prompt assembly

Assemble a complete LLM prompt whose sections are conditionally included based on the spec content (OS, software dependencies, network, hardware, threat profile, attack chain, platform constraints). Different specs produce structurally different prompts.

```bash
uv run python -m Task2.cli constraint --spec <spec.json> --provider qemu --prompt
# → Prompt saved to Task2/output/<hash>_prompt.txt
```

#### Validate Terraform HCL

```bash
# Syntax + semantic validation
uv run python -m Task2.cli validate --hcl main.tf --provider qemu

# Syntax-only
uv run python -m Task2.cli validate --hcl main.tf --syntax-only
```

