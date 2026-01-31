# Context Protector

[![PyPI version](https://img.shields.io/pypi/v/context-protector.svg)](https://pypi.org/project/context-protector/)
[![Python](https://img.shields.io/pypi/pyversions/context-protector.svg)](https://pypi.org/project/context-protector/)
[![License](https://img.shields.io/github/license/ottosulin/context-protector.svg)](https://github.com/ottosulin/context-protector/blob/main/LICENSE)
[![CI](https://github.com/ottosulin/context-protector/actions/workflows/test.yml/badge.svg)](https://github.com/ottosulin/context-protector/actions/workflows/test.yml)

Protect AI coding agents from prompt injection attacks. Works with **Claude Code** and other AI coding tools.

## Features

- **Prompt Injection Detection** - Block malicious inputs before tool execution
- **Output Scanning** - Detect threats in tool outputs (file reads, API responses)
- **Multiple Backends** - LlamaFirewall (default), NeMo Guardrails, GCP Model Armor
- **Fully Local** - No cloud dependencies required (optional Ollama support)

## Installation

```bash
# Using uv (recommended)
uv tool install context-protector

# Using pip
pip install context-protector

# Using pipx
pipx install context-protector
```

## Quick Start (Claude Code)

**1. Install and initialize:**

```bash
context-protector init
```

**2. Add to Claude Code settings** (`~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [{"type": "command", "command": "context-protector"}]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [{"type": "command", "command": "context-protector"}]
      }
    ]
  }
}
```

**3. Done!** Context Protector will now scan all tool inputs and outputs.

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                      Claude Code                            │
│                                                             │
│  Tool Request ──► PreToolUse Hook ──► context-protector     │
│                        │                    │               │
│                   [ALLOW/BLOCK]        Scan Input           │
│                        │                    │               │
│  Tool Response ◄── PostToolUse Hook ◄── context-protector   │
│                        │                    │               │
│                   [WARN/BLOCK]         Scan Output          │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

Config file: `~/.config/context-protector/config.yaml`

```yaml
general:
  response_mode: warn    # warn (default) or block

llama_firewall:
  scanner_mode: auto     # auto, basic, or full
```

Run `context-protector init` to create a config file with all options.

### Environment Variables

All settings can be overridden with environment variables (prefix: `CONTEXT_PROTECTOR_`):

```bash
export CONTEXT_PROTECTOR_RESPONSE_MODE=block
export CONTEXT_PROTECTOR_SCANNER_MODE=basic
```

## Providers

### LlamaFirewall (Default)

Meta's LlamaFirewall for ML-based prompt injection detection.

| Mode | Description |
|------|-------------|
| `auto` | Tries ML detection, falls back to pattern-based if auth fails |
| `basic` | Pattern-based only (no HuggingFace auth required) |
| `full` | Full ML detection (requires [HuggingFace auth](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)) |

### NeMo Guardrails

NVIDIA's guardrails toolkit with multiple detection modes.

| Mode | Description |
|------|-------------|
| `all` | Heuristics + injection detection (default) |
| `heuristics` | Perplexity-based jailbreak detection |
| `injection` | YARA-based SQL/XSS/code injection |
| `local` | LLM-based via Ollama (fully local) |

```yaml
nemo_guardrails:
  mode: local
  ollama_model: mistral:7b
```

### GCP Model Armor

Enterprise-grade content safety via Google Cloud.

```yaml
gcp_model_armor:
  enabled: true
  project_id: your-project
  location: us-central1
  template_id: your-template
```

## Response Modes

| Mode | Behavior |
|------|----------|
| `warn` | Log threats, inject warnings (default) |
| `block` | Block malicious content entirely |

## CLI Reference

```bash
context-protector              # Run as Claude Code hook (reads stdin)
context-protector init         # Create config file
context-protector --check      # Check content from stdin JSON
context-protector --help       # Show help
context-protector --version    # Show version
```

### Standalone Check Mode

For integration with other tools:

```bash
echo '{"content": "test input", "type": "tool_input"}' | context-protector --check
```

Output:
```json
{"safe": true, "alert": null}
```

## Development

```bash
git clone https://github.com/ottosulin/context-protector.git
cd context-protector
uv sync --all-groups
uv run pytest
```

## License

MIT
