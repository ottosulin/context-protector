# Context Protector

[![PyPI version](https://img.shields.io/pypi/v/context-protector.svg)](https://pypi.org/project/context-protector/)
[![Python](https://img.shields.io/pypi/pyversions/context-protector.svg)](https://pypi.org/project/context-protector/)
[![License](https://img.shields.io/github/license/ottosulin/context-protector.svg)](https://github.com/ottosulin/context-protector/blob/main/LICENSE)
[![CI](https://github.com/ottosulin/context-protector/actions/workflows/test.yml/badge.svg)](https://github.com/ottosulin/context-protector/actions/workflows/test.yml)

Protect AI coding agents from prompt injection attacks. Works with **Claude Code**, **OpenCode**, and other AI coding tools.

TL;DR: below screenshot of `context-protector` in action.
<img width="1068" height="261" alt="context-guard" src="https://github.com/user-attachments/assets/d5b221a8-54ef-4df4-a4d9-3376e78d665f" />

## Features

- **Prompt Injection Detection** - Block malicious inputs before tool execution
- **Output Scanning** - Detect threats in tool outputs (file reads, API responses)
- **Multiple Backends** - LlamaFirewall (default), NeMo Guardrails, GCP Model Armor
- **Multi-Platform** - Native support for Claude Code and OpenCode
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

## Quick Start

### OpenCode

**1. Install the plugin:**

```bash
pip install context-protector
```

**2. Add to your `opencode.json`:**

```json
{
  "plugin": ["opencode-context-protector"]
}
```

**3. Done!** The plugin will scan all tool inputs and outputs.

### Claude Code

**1. Install and initialize:**

```bash
context-protector init
```

**2. Add to Claude Code settings** (`~/.claude/settings.json`):

Use `"matcher": "*"` to [inspect all tool calls](https://code.claude.com/docs/en/hooks#matcher-patterns) - limiting to MCP will save on tokens and focus more on where it matters.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp*",
        "hooks": [{"type": "command", "command": "context-protector"}]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "mcp*",
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
│                   Claude Code / OpenCode                     │
│                                                              │
│  Tool Request ──► PreToolUse Hook ──► context-protector      │
│                        │                    │                │
│                   [ALLOW/BLOCK]        Scan Input            │
│                        │                    │                │
│  Tool Response ◄── PostToolUse Hook ◄── context-protector    │
│                        │                    │                │
│                   [WARN/BLOCK]         Scan Output           │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

Config file: `~/.config/context-protector/config.yaml`

```yaml
# Which provider to use
provider: LlamaFirewall       # LlamaFirewall, NeMoGuardrails, GCPModelArmor

# Response mode when threats detected
response_mode: warn           # warn (default) or block

# Provider-specific settings
llama_firewall:
  scanner_mode: auto          # auto, basic, or full

nemo_guardrails:
  mode: all                   # heuristics, injection, self_check, local, all
  ollama_model: mistral:7b
  ollama_base_url: http://localhost:11434

gcp_model_armor:
  project_id: null
  location: null
  template_id: null
```

Run `context-protector init` to create a config file with all options.

### Environment Variables

All settings can be overridden with environment variables (prefix: `CONTEXT_PROTECTOR_`):

```bash
export CONTEXT_PROTECTOR_PROVIDER=NeMoGuardrails
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
provider: GCPModelArmor

gcp_model_armor:
  project_id: your-project
  location: us-central1
  template_id: your-template
```

## Response Modes

| Mode | Behavior |
|------|----------|
| `warn` | Log threats, inject warnings (default) |
| `block` | Block malicious content entirely |

## Temporarily Disabling Protection

If you encounter false positives and need to temporarily disable protection:

```bash
# Disable protection
context-protector --disable

# Re-enable when done
context-protector --enable
```

This modifies your config file and takes effect immediately on the next tool call - no Claude Code restart needed.

You can also edit the config file directly:

```yaml
enabled: false  # Set to true to re-enable
```

## OpenCode Plugin

The OpenCode plugin (`opencode-context-protector`) provides:

- **Pre-execution scanning** via `tool.execute.before` hook
- **Post-execution scanning** via `tool.execute.after` hook
- **Built-in .env protection** - Blocks reading `.env`, `*.pem`, `*.key`, `credentials.json`
- **Configurable skip list** - Exclude specific tools from scanning

### OpenCode Plugin Configuration

```bash
# Response mode
export CONTEXT_PROTECTOR_RESPONSE_MODE=block

# Disable .env protection
export CONTEXT_PROTECTOR_ENV_PROTECTION=false

# Skip certain tools
export CONTEXT_PROTECTOR_SKIP_TOOLS=glob,find

# Debug logging
export CONTEXT_PROTECTOR_DEBUG=true
```

See [`opencode-plugin/README.md`](opencode-plugin/README.md) for full documentation.

## CLI Reference

```bash
context-protector                     # Run as Claude Code hook (reads stdin)
context-protector init                # Create config file
context-protector --check             # Check content from stdin JSON
context-protector --config <path>     # Use custom config file
context-protector --help              # Show help
context-protector --version           # Show version
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

## Project Structure

```
context-protector/
├── src/context_protector/     # Python package (PyPI)
│   ├── __init__.py            # CLI entry point
│   ├── config.py              # Configuration system
│   ├── hook_handler.py        # Claude Code hook processing
│   └── providers/             # Detection backends
├── opencode-plugin/           # OpenCode plugin (npm)
│   ├── src/index.ts           # Plugin entry point
│   ├── src/backend.ts         # Python backend wrapper
│   └── tests/                 # Plugin tests
├── tests/                     # Python tests
└── pyproject.toml
```

## Development

### Contributing

Contributions very welcome for new guardrail providers and support for other agentic tools!

Please create an issue first before submitting a PR.

### Python Package

```bash
git clone https://github.com/ottosulin/context-protector.git
cd context-protector
uv sync --all-groups
uv run pytest
```

### OpenCode Plugin

```bash
cd opencode-plugin
bun install
bun test
bun run build
```

## License

MIT
