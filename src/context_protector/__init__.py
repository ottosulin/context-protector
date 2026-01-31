"""Context Protector - Guardrail-based security for AI coding agents.

This package provides protection against prompt injection attacks for:
- Claude Code: via stdin/stdout hook protocol
- OpenCode: via --check mode called from TypeScript plugin

It checks tool inputs and outputs for potential security threats using
configurable guardrail providers (LlamaFirewall, NeMo, GCP Model Armor, etc.).
"""

import json
import logging
import sys
from dataclasses import dataclass
from typing import Any

from context_protector.config import get_config, init_config
from context_protector.hook_handler import HookHandler, process_hook

__version__ = "0.1.0"

__all__ = ["CheckResult", "HookHandler", "check_content", "main", "process_hook"]


@dataclass
class CheckResult:
    """Result from content check operation.

    Attributes:
        safe: True if content passed all checks
        alert: Alert details if content was flagged, None otherwise
    """

    safe: bool
    alert: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "safe": self.safe,
            "alert": self.alert,
        }


def check_content(
    content: str,
    content_type: str = "tool_input",
    tool_name: str | None = None,
) -> CheckResult:
    """Check content for prompt injection and security threats.

    This is the primary API for checking content. Used by:
    - --check CLI mode (for OpenCode integration)
    - Direct Python API usage

    Args:
        content: The text content to check
        content_type: Type of content - "tool_input" or "tool_output"
        tool_name: Optional name of the tool being checked

    Returns:
        CheckResult with safe=True if content passed, or alert details if flagged
    """
    from context_protector.guardrail_types import ContentToCheck
    from context_protector.guardrails import get_provider

    provider = get_provider()
    content_to_check = ContentToCheck(
        content=content,
        content_type=content_type,
        tool_name=tool_name,
    )

    alert = provider.check_content(content_to_check)

    if alert:
        return CheckResult(
            safe=False,
            alert={
                "explanation": alert.explanation,
                "provider": provider.name,
                "data": alert.data if alert.data else None,
            },
        )

    return CheckResult(safe=True)


def _handle_check_command() -> None:
    """Handle --check mode for OpenCode integration.

    Reads JSON from stdin with format:
    {
        "content": "text to check",
        "type": "tool_input" | "tool_output",
        "tool_name": "optional tool name"
    }

    Outputs JSON result:
    {
        "safe": true/false,
        "alert": { "explanation": "...", "provider": "..." } | null
    }
    """
    _configure_logging()

    input_data_str = sys.stdin.read().strip()
    if not input_data_str:
        error_result = {"error": "No input provided", "safe": True, "alert": None}
        print(json.dumps(error_result))
        sys.exit(0)

    try:
        input_data = json.loads(input_data_str)
    except json.JSONDecodeError as e:
        error_result = {"error": f"Invalid JSON: {e}", "safe": True, "alert": None}
        print(json.dumps(error_result))
        sys.exit(0)

    content = input_data.get("content", "")
    content_type = input_data.get("type", "tool_input")
    tool_name = input_data.get("tool_name")

    if not content:
        result = CheckResult(safe=True)
        print(json.dumps(result.to_dict()))
        sys.exit(0)

    try:
        result = check_content(content, content_type, tool_name)
        print(json.dumps(result.to_dict()))
    except Exception as e:
        logging.getLogger(__name__).exception("Error during content check")
        error_result = {"error": str(e), "safe": True, "alert": None}
        print(json.dumps(error_result))

    sys.exit(0)


def _configure_logging() -> None:
    """Configure logging based on configuration."""
    config = get_config()

    handlers: list[logging.Handler] = []
    if config.general.log_file:
        handlers.append(logging.FileHandler(config.general.log_file))

    logging.basicConfig(
        level=getattr(logging, config.general.log_level.upper(), logging.WARNING),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers if handlers else None,
    )


def _print_help() -> None:
    print(f"""Context Protector v{__version__}

Guardrail-based security for AI coding agents (Claude Code, OpenCode).

Usage:
  context-protector              Run as Claude Code hook (reads hook JSON from stdin)
  context-protector --check      Check content for threats (reads JSON from stdin)
  context-protector init         Create default config file
  context-protector init --force Overwrite existing config file
  context-protector --help       Show this help message
  context-protector --version    Show version

--check mode (for OpenCode integration):
  Input:  {{"content": "text", "type": "tool_input|tool_output", "tool_name": "opt"}}
  Output: {{"safe": true|false, "alert": {{"explanation": "...", "provider": "..."}}}}

Config file: ~/.config/context-protector/config.yaml
Environment variables override config file settings.
""")


def _handle_init_command() -> None:
    """Handle the init subcommand."""
    force = "--force" in sys.argv or "-f" in sys.argv

    try:
        config_path = init_config(force=force)
        print(f"Created config file: {config_path}")
        print()
        print("Default configuration:")
        print("  - Mode: default (multi-provider)")
        print("  - LlamaFirewall: auto mode (PROMPT_GUARD if auth available)")
        print("  - NeMo Guardrails: all mode (heuristics + injection)")
        print("  - AprielGuard: disabled")
        print()
        print(f"Edit {config_path} to customize.")
    except FileExistsError:
        from context_protector.config import get_config_path

        print(f"Config file already exists: {get_config_path()}")
        print("Use --force to overwrite.")
        sys.exit(1)


def main() -> None:
    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "--check":
            _handle_check_command()
            return

        if command == "init":
            _handle_init_command()
            return

        if command in ("--help", "-h"):
            _print_help()
            return

        if command in ("--version", "-v"):
            print(f"context-protector {__version__}")
            return

    _configure_logging()
    process_hook()
