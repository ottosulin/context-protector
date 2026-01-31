# Context Protector - Roadmap

## Current State (v1.0.0)

**Released:**
- Core hook processing for Claude Code (PreToolUse, PostToolUse)
- `--check` CLI mode for standalone content checking
- Configuration system (YAML + environment variables)
- 4 guardrail providers:
  - LlamaFirewall (default)
  - NeMo Guardrails
  - GCP Model Armor
  - AprielGuard (disabled)
- Response modes (warn/block)
- GitHub CI/CD workflows
- PyPI publishing

---

## Phase 2.5: Configuration Improvements (v1.0.1)
**Goal:** Simplify configuration and add `--config` flag
**Priority:** Before OpenCode support

### Tasks

1. **Add `--config` flag**
   - Allow specifying config file path: `context-protector --config /path/to/config.yaml`
   - Works with all commands (hook mode, `--check`, `init`)

2. **Simplify config format**
   - Reduce nesting where possible
   - Make provider selection more intuitive
   - Review default values

3. **Config validation**
   - Validate config on load
   - Clear error messages for invalid config

---

## Phase 3: OpenCode Plugin (v1.1.0)
**Goal:** Ship context-protector as an OpenCode plugin

### Tasks

1. Create TypeScript plugin (`opencode-context-protector`)
2. Publish to npm
3. Update documentation
4. Submit to OpenCode ecosystem

---

## Phase 4: Performance (v1.2.0)
**Goal:** HTTP server mode for lower latency

### Tasks

1. Add `context-protector serve` command
2. `/check` endpoint matching CLI interface
3. Update TypeScript plugin for HTTP mode

---

## Phase 5: Enhanced Features (v1.3.0)

- Per-tool configuration
- Result caching
- Metrics and logging
