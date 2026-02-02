# opencode-context-protector

Prompt injection protection plugin for [OpenCode](https://opencode.ai) - guards AI coding agents against malicious content in tool inputs and outputs.

## Features

- **Pre-execution scanning** - Checks tool inputs before execution, can block malicious content
- **Post-execution scanning** - Checks tool outputs for injected instructions
- **Multiple detection backends** - LlamaFirewall, NeMo Guardrails, GCP Model Armor
- **Built-in .env protection** - Prevents reading sensitive files (.env, *.pem, *.key)
- **Configurable response modes** - Warn (log only) or Block (prevent execution)

## Installation

### 1. Install the Python backend

```bash
pip install context-protector
```

Or with uv:

```bash
uv tool install context-protector
```

### 2. Add the plugin to OpenCode

Add to your `opencode.json`:

```json
{
  "plugin": ["opencode-context-protector"]
}
```

Or install globally:

```bash
npm install -g opencode-context-protector
```

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                        OpenCode                              │
│                                                              │
│  Tool Request ──► tool.execute.before ──► context-protector  │
│                        │                       │             │
│                   [ALLOW/BLOCK]           Scan Input         │
│                        │                       │             │
│  Tool Response ◄── tool.execute.after ◄── context-protector  │
│                        │                       │             │
│                   [LOG WARNING]           Scan Output        │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CONTEXT_PROTECTOR_RESPONSE_MODE` | `warn` or `block` | `warn` |
| `CONTEXT_PROTECTOR_PROVIDER` | Detection backend | `LlamaFirewall` |
| `CONTEXT_PROTECTOR_ENV_PROTECTION` | Block .env files | `true` |
| `CONTEXT_PROTECTOR_BLOCKED_FILE_PATTERNS` | Comma-separated patterns | `.env,.env.*,*.pem,*.key,credentials.json` |
| `CONTEXT_PROTECTOR_SKIP_TOOLS` | Tools to skip checking | (empty) |
| `CONTEXT_PROTECTOR_DEBUG` | Enable debug logging | `false` |

### Examples

**Block mode** (recommended for production):
```bash
export CONTEXT_PROTECTOR_RESPONSE_MODE=block
```

**Skip certain tools**:
```bash
export CONTEXT_PROTECTOR_SKIP_TOOLS=glob,find
```

**Disable .env protection**:
```bash
export CONTEXT_PROTECTOR_ENV_PROTECTION=false
```

## Response Modes

### Warn Mode (default)

Logs warnings but allows execution to continue. Good for:
- Testing and development
- Understanding what would be blocked
- Low-risk environments

### Block Mode

Throws an error to prevent tool execution. Good for:
- Production environments
- High-security codebases
- When you want strict protection

## Built-in Protections

### Sensitive File Protection

By default, the plugin blocks reading these file patterns:
- `.env` - Environment files
- `.env.*` - Environment variants (.env.local, .env.production)
- `*.pem` - SSL certificates
- `*.key` - Private keys
- `credentials.json` - Cloud credentials

This protection works **without** the Python backend installed.

## Detection Backends

The Python backend supports multiple detection engines:

| Provider | Description |
|----------|-------------|
| **LlamaFirewall** | Meta's ML-based prompt injection detection (default) |
| **NeMoGuardrails** | NVIDIA's heuristics + injection detection |
| **GCPModelArmor** | Google Cloud's enterprise content safety |

Configure via the Python backend:
```bash
export CONTEXT_PROTECTOR_PROVIDER=NeMoGuardrails
```

## Development

```bash
# Install dependencies
bun install

# Run tests
bun test

# Build
bun run build

# Type check
bun run typecheck
```

## Local Plugin Installation

For development, copy the plugin to your project:

```bash
mkdir -p .opencode/plugins
cp dist/index.js .opencode/plugins/context-protector.js
```

Or to install globally:

```bash
mkdir -p ~/.config/opencode/plugins
cp dist/index.js ~/.config/opencode/plugins/context-protector.js
```

## Troubleshooting

### "Python backend not available"

Install the Python package:
```bash
pip install context-protector
```

Verify installation:
```bash
context-protector --version
```

### Plugin not loading

Check that the plugin is listed in your `opencode.json`:
```json
{
  "plugin": ["opencode-context-protector"]
}
```

### Too many warnings

Adjust sensitivity or skip noisy tools:
```bash
export CONTEXT_PROTECTOR_SKIP_TOOLS=read,glob
```

## License

MIT

## Links

- [Context Protector](https://github.com/ottosulin/context-protector) - Main project
- [OpenCode Plugins](https://opencode.ai/docs/plugins) - Plugin documentation
- [OpenCode Ecosystem](https://opencode.ai/docs/ecosystem) - Community plugins
