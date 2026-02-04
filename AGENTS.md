# AGENTS.md - AI Agent Instructions

Instructions for AI agents working on the Context Protector codebase.

## Project Overview

**Context Protector** is a guardrails toolkit that protects AI coding agents from prompt injection attacks. It scans tool inputs (PreToolUse) and outputs (PostToolUse) using multiple detection backends.

### Supported Platforms
- **Claude Code** - via hook protocol
- **OpenCode** - via `--check` CLI mode (planned)

### Technology Stack
- **Python**: 3.12+
- **Package Manager**: uv
- **Build System**: uv_build
- **Linting**: ruff
- **Type Checking**: mypy (strict mode)
- **Testing**: pytest

## Project Structure

```
context-protector/
├── src/context_protector/
│   ├── __init__.py              # CLI entry point, main()
│   ├── __main__.py              # python -m support
│   ├── config.py                # Configuration system
│   ├── guardrail_types.py       # Data classes and enums
│   ├── guardrails.py            # Provider registry
│   ├── hook_handler.py          # Hook event processing
│   └── providers/
│       ├── base.py              # GuardrailProvider ABC
│       ├── llama_firewall.py    # LlamaFirewall provider
│       ├── nemo_guardrails.py   # NeMo Guardrails provider
│       ├── gcpmodelarmor_provider.py  # GCP Model Armor
│       ├── apriel_guard.py      # AprielGuard (disabled)
│       └── mock_provider.py     # Test providers
├── tests/
│   ├── test_check_mode.py       # --check CLI tests
│   ├── test_config.py           # Configuration tests
│   ├── test_guardrail_types.py  # Data class tests
│   ├── test_hook_handler.py     # Hook processing tests
│   ├── test_integration.py      # Integration tests
│   ├── test_llama_firewall.py   # LlamaFirewall tests
│   ├── test_nemo_guardrails.py  # NeMo tests
│   ├── test_gcp_model_armor.py  # GCP tests
│   └── test_providers.py        # Provider registry tests
├── scripts/
│   └── smoke_test_check_mode.py # E2E smoke tests
├── .github/workflows/
│   ├── test.yml                 # CI testing
│   └── release.yml              # PyPI publishing
├── pyproject.toml
├── README.md
└── LICENSE
```

## Development Commands

```bash
# Install dependencies
uv sync --all-groups

# Run tests
uv run pytest tests/ -v

# Run tests excluding provider-specific (no external deps)
uv run pytest tests/ -v \
  --ignore=tests/test_llama_firewall.py \
  --ignore=tests/test_nemo_guardrails.py \
  --ignore=tests/test_gcp_model_armor.py \
  --ignore=tests/test_apriel_guard.py

# Linting and type checking (MUST RUN BEFORE COMMITTING)
uv run ruff check src tests
uv run mypy src

# Run smoke tests
PYTHONPATH=src python3 scripts/smoke_test_check_mode.py
```

## Architecture

### CLI Modes

1. **Hook Mode** (default): Reads Claude Code hook JSON from stdin
2. **Check Mode** (`--check`): Standalone content checking, JSON in/out
3. **Init Mode** (`init`): Creates config file

### Processing Flow

```
Input → Provider.check_content() → GuardrailAlert | None → Output
```

### Provider Interface

```python
class GuardrailProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def check_content(self, content: ContentToCheck) -> GuardrailAlert | None: ...
```

## Providers

| Provider | Status | Description |
|----------|--------|-------------|
| LlamaFirewall | Active | Default. ML + pattern-based detection |
| NeMoGuardrails | Active | Heuristics, injection, LLM-based modes |
| GCPModelArmor | Active | Enterprise cloud option |
| AprielGuard | Disabled | 8B model, not production-ready |

## Configuration

Config file: `~/.config/context-protector/config.yaml`

### Config Structure (v1.0.1+)

```yaml
# Top-level settings
provider: LlamaFirewall       # LlamaFirewall, NeMoGuardrails, GCPModelArmor
response_mode: warn           # warn or block
log_level: WARNING            # DEBUG, INFO, WARNING, ERROR
log_file: null                # Optional log file path

# Provider-specific settings
llama_firewall:
  scanner_mode: auto          # auto, basic, full

nemo_guardrails:
  mode: all                   # heuristics, injection, self_check, local, all
  ollama_model: mistral:7b
  ollama_base_url: http://localhost:11434

gcp_model_armor:
  project_id: null
  location: null
  template_id: null
```

### CLI Flags

- `--config <path>` - Use custom config file path
- `--check` - Standalone content checking mode
- `--version` - Show version
- `--help` - Show help

### Environment Variables (prefix `CONTEXT_PROTECTOR_`)

| Variable | Description |
|----------|-------------|
| `PROVIDER` | Provider name |
| `RESPONSE_MODE` | `warn` or `block` |
| `LOG_LEVEL` | Logging level |
| `LOG_FILE` | Log file path |
| `SCANNER_MODE` | LlamaFirewall mode |
| `NEMO_MODE` | NeMo detection mode |
| `OLLAMA_MODEL` | Ollama model for NeMo local mode |
| `OLLAMA_BASE_URL` | Ollama server URL |
| `GCP_PROJECT_ID` | GCP project ID |
| `GCP_LOCATION` | GCP region |
| `GCP_TEMPLATE_ID` | Model Armor template ID |

## Coding Standards

- Python 3.12+ type hints (`str | None` not `Optional[str]`)
- All functions typed
- ruff for linting (100 char line length)
- mypy strict mode
- Dataclasses for data containers
- Never log sensitive content at INFO or higher

## Testing

- Provider tests require external dependencies (skipped in CI)
- Core tests run without external deps
- Mock providers: `MockGuardrailProvider`, `AlwaysAlertProvider`, `NeverAlertProvider`

## Adding a Provider

1. Create `src/context_protector/providers/new_provider.py`
2. Implement `GuardrailProvider` interface
3. Register in `guardrails.py` PROVIDER_REGISTRY
4. Add tests in `tests/test_new_provider.py`
5. Update README.md

## Security Notes

- Never log content at INFO level or higher
- Validate all inputs before processing
- Return safe defaults on errors (allow execution)
- Test with known prompt injection examples

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
