# Skill Scanner

A Python tool for scanning Agent Skills packages for potential security findings. The Skill Analyzer combines pattern-based detection (YAML + YARA), LLM-as-a-judge, and behavioral dataflow analysis to detect malicious skills. Supports Anthropic Claude Skills, OpenAI Codex Skills, and Cursor Agent Skills formats, which follow the [Agent Skills specification](https://agentskills.io).

## Documentation

- **[Quick Start Guide](docs/quickstart.md)** - Get started in 5 minutes
- **[Architecture](docs/architecture.md)** - System design and components
- **[Threat Taxonomy](docs/threat-taxonomy.md)** - Complete AITech threat taxonomy with examples
- **[LLM Analyzer](docs/llm-analyzer.md)** - LLM configuration and usage
- **[Meta-Analyzer](docs/meta-analyzer.md)** - False positive filtering and finding prioritization
- **[Behavioral Analyzer](docs/behavioral-analyzer.md)** - Dataflow analysis details
- **[API Reference](docs/api-server.md)** - REST API documentation
- **[Binary Handling](docs/binary-handling.md)** - How binary files are handled
- **[Development Guide](docs/developing.md)** - Contributing and development setup

## Installation

### Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- LLM Provider API Key (optional, for LLM analyzer)

### Using UV (Recommended)

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Core installation (includes CLI + API server)
uv pip install cisco-ai-skill-scanner

# With LLM support (adds Anthropic, OpenAI, LiteLLM, Google GenAI)
uv pip install cisco-ai-skill-scanner[llm]

# With AWS Bedrock support
uv pip install cisco-ai-skill-scanner[bedrock]

# With Google Vertex AI support
uv pip install cisco-ai-skill-scanner[vertex]

# With Azure OpenAI support
uv pip install cisco-ai-skill-scanner[azure]

# All features (core + LLM + all cloud providers)
uv pip install cisco-ai-skill-scanner[all]
```

### Using pip

```bash
# Core installation
pip install cisco-ai-skill-scanner

# With all features
pip install cisco-ai-skill-scanner[all]
```

## Quick Start

### Environment Setup (Optional)

```bash
# For LLM analyzer and Meta-analyzer
export SKILL_SCANNER_LLM_API_KEY="your_api_key"
export SKILL_SCANNER_LLM_MODEL="claude-3-5-sonnet-20241022"

# For Azure OpenAI (optional)
export SKILL_SCANNER_LLM_BASE_URL="https://your-resource.openai.azure.com/"
export SKILL_SCANNER_LLM_API_VERSION="2025-01-01-preview"

# For VirusTotal binary scanning
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"

# For Cisco AI Defense
export AI_DEFENSE_API_KEY="your_aidefense_api_key"
```

### CLI Usage

```bash
# Scan a single skill (static analyzer only)
skill-analyzer scan /path/to/skill

# Scan with behavioral analyzer (dataflow analysis)
skill-analyzer scan /path/to/skill --use-behavioral

# Scan with all engines
skill-analyzer scan /path/to/skill --use-behavioral --use-llm --use-aidefense --use-virustotal

# Scan with meta-analyzer for false positive filtering (requires --use-llm)
skill-analyzer scan /path/to/skill --use-llm --enable-meta

# Scan multiple skills recursively
skill-analyzer scan-all /path/to/skills --recursive --use-behavioral

# Save results to file
skill-analyzer scan /path/to/skill --format json --output results.json

# Fail CI build if threats found
skill-analyzer scan-all ./skills --fail-on-findings --use-behavioral
```

### Python SDK Usage

```python
from skillanalyzer import SkillScanner, Config
from skillanalyzer.core.analyzers import StaticAnalyzer, BehavioralAnalyzer, LLMAnalyzer

# Create scanner with analyzers
analyzers = [
    StaticAnalyzer(),
    BehavioralAnalyzer(use_static_analysis=True),
]

scanner = SkillScanner(analyzers=analyzers)

# Scan a skill
result = scanner.scan_skill("/path/to/skill")

# Check results
print(f"Skill: {result.skill_name}")
print(f"Safe: {result.is_safe}")
print(f"Findings: {len(result.findings)}")
```

## CLI Options

| Option | Description |
|--------|-------------|
| `--use-behavioral` | Enable behavioral analyzer (dataflow analysis) |
| `--use-llm` | Enable LLM analyzer (requires API key) |
| `--use-virustotal` | Enable VirusTotal binary file scanner |
| `--use-aidefense` | Enable Cisco AI Defense analyzer |
| `--enable-meta` | Enable meta-analyzer for false positive filtering (requires `--use-llm`) |
| `--format {summary,json,markdown,table,sarif}` | Output format |
| `--output PATH` | Save report to file |
| `--fail-on-findings` | Exit with error if HIGH/CRITICAL found |
| `--check-overlap` | Enable cross-skill overlap detection |

## Security Analyzers

| Analyzer | Detection Method | Scope | Requirements |
|----------|------------------|-------|--------------|
| **Static** | YAML + YARA patterns | All files | None |
| **Behavioral** | AST dataflow analysis | Python files | None |
| **LLM** | Semantic analysis | SKILL.md + scripts | API key |
| **Meta** | False positive filtering | All findings | API key + `--use-llm` |
| **VirusTotal** | Hash-based malware | Binary files | API key |
| **AI Defense** | Cloud-based AI | Text content | API key |

> **Note:** The Meta-Analyzer performs a second-pass analysis to filter false positives and prioritize findings. In testing, it achieves ~65% noise reduction while maintaining 100% threat detection rate.

## Output Formats

- **`summary`** - Concise overview (default)
- **`json`** - Machine-readable JSON
- **`markdown`** - Human-readable reports
- **`table`** - Clean tabular format
- **`sarif`** - GitHub Code Scanning integration

## Example Output

```bash
$ skill-analyzer scan evals/test_skills/safe/simple-formatter
============================================================
Skill: safe-calculator
============================================================
Status: [OK] SAFE
Max Severity: SAFE
Total Findings: 0
Scan Duration: 0.15s
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Distributed under the `Apache 2.0` License. See [LICENSE](LICENSE) for more information.

Copyright 2026 Cisco Systems, Inc. and its affiliates

Project Link: https://github.com/cisco-ai-defense/skill-scanner
