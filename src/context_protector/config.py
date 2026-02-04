"""Configuration management for Context Protector.

Provides YAML-based configuration with environment variable overrides.
Config file location: ~/.config/context-protector/config.yaml
"""

import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Default config file template with comments
DEFAULT_CONFIG_TEMPLATE = """\
# Context Protector Configuration
# Location: ~/.config/context-protector/config.yaml
#
# Environment variables override this file (prefix: CONTEXT_PROTECTOR_)
# Run 'context-protector init' to regenerate defaults.

# Enable/disable protection (use 'context-protector --disable' to toggle)
enabled: true

# Which provider to use: LlamaFirewall, NeMoGuardrails, GCPModelArmor
provider: LlamaFirewall

# Response mode when threats detected: warn or block
# - warn: Log threat and inject warning message (default)
# - block: Block malicious content entirely
response_mode: warn

# Logging
log_level: WARNING    # DEBUG, INFO, WARNING, ERROR
log_file: null        # Optional log file path

# LlamaFirewall provider settings
llama_firewall:
  # Scanner mode: auto, basic, or full
  # - auto: Try full, fall back to basic on auth error (recommended)
  # - basic: No auth required (HIDDEN_ASCII, REGEX, CODE_SHIELD)
  # - full: Requires HuggingFace auth (includes PROMPT_GUARD)
  scanner_mode: auto

# NeMo Guardrails provider settings
nemo_guardrails:
  # Detection mode: heuristics, injection, self_check, local, or all
  # - heuristics: Perplexity-based jailbreak detection (local, no API)
  # - injection: YARA-based SQL/XSS/code injection detection (local)
  # - self_check: LLM-based validation (requires OpenAI API)
  # - local: LLM-based validation using Ollama (fully local)
  # - all: heuristics + injection combined
  mode: all

  # Ollama settings for local mode
  ollama_model: mistral:7b
  ollama_base_url: http://localhost:11434

# GCP Model Armor provider settings
# Requires: google-cloud-modelarmor package and GCP authentication
gcp_model_armor:
  project_id: null      # Your GCP project ID
  location: null        # GCP region (e.g., us-central1)
  template_id: null     # Model Armor template ID
"""


@dataclass
class LlamaFirewallConfig:
    """LlamaFirewall provider configuration."""

    scanner_mode: str = "auto"


@dataclass
class NeMoGuardrailsConfig:
    """NeMo Guardrails provider configuration."""

    mode: str = "all"
    ollama_model: str = "mistral:7b"
    ollama_base_url: str = "http://localhost:11434"


@dataclass
class GCPModelArmorConfig:
    """GCP Model Armor provider configuration."""

    project_id: str | None = None
    location: str | None = None
    template_id: str | None = None


@dataclass
class Config:
    """Complete configuration."""

    enabled: bool = True
    provider: str = "LlamaFirewall"
    response_mode: str = "warn"
    log_level: str = "WARNING"
    log_file: str | None = None
    llama_firewall: LlamaFirewallConfig = field(default_factory=LlamaFirewallConfig)
    nemo_guardrails: NeMoGuardrailsConfig = field(default_factory=NeMoGuardrailsConfig)
    gcp_model_armor: GCPModelArmorConfig = field(default_factory=GCPModelArmorConfig)


# Global config path override (set via --config flag)
_config_path_override: Path | None = None


def set_config_path(path: Path | None) -> None:
    """Set a custom config file path.

    Args:
        path: Custom config file path, or None to use default
    """
    global _config_path_override
    _config_path_override = path


def get_config_path() -> Path:
    """Get the config file path.

    Returns the custom path if set via set_config_path() or CONTEXT_PROTECTOR_CONFIG
    environment variable, otherwise uses XDG_CONFIG_HOME or ~/.config.

    Returns:
        Path to the config file
    """
    if _config_path_override is not None:
        return _config_path_override

    # Check environment variable for config path
    if config_env := os.environ.get("CONTEXT_PROTECTOR_CONFIG"):
        return Path(config_env)

    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg_config) if xdg_config else Path.home() / ".config"
    return base / "context-protector" / "config.yaml"


def _merge_dict_into_dataclass(dc: Any, data: dict[str, Any]) -> None:
    """Merge dictionary values into a dataclass instance.

    Args:
        dc: Dataclass instance to update
        data: Dictionary with values to merge
    """
    for key, value in data.items():
        if hasattr(dc, key) and value is not None:
            setattr(dc, key, value)


def _load_config_from_file(config_path: Path) -> dict[str, Any]:
    """Load configuration from YAML file.

    Args:
        config_path: Path to the config file

    Returns:
        Dictionary with configuration data, empty dict if file doesn't exist
    """
    if not config_path.exists():
        return {}

    try:
        with open(config_path) as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
    except yaml.YAMLError as e:
        logger.warning("Invalid YAML in config file %s: %s", config_path, e)
        return {}
    except OSError as e:
        logger.warning("Error reading config file %s: %s", config_path, e)
        return {}


def _apply_env_overrides(config: Config) -> Config:
    """Apply environment variable overrides to configuration.

    Environment variables take precedence over config file values.

    Args:
        config: Configuration to update

    Returns:
        Updated configuration
    """
    # Top-level settings
    if enabled := os.environ.get("CONTEXT_PROTECTOR_ENABLED"):
        config.enabled = enabled.lower() in ("true", "1", "yes")

    if provider := os.environ.get("CONTEXT_PROTECTOR_PROVIDER"):
        config.provider = provider

    if response_mode := os.environ.get("CONTEXT_PROTECTOR_RESPONSE_MODE"):
        config.response_mode = response_mode.lower()

    if log_level := os.environ.get("CONTEXT_PROTECTOR_LOG_LEVEL"):
        config.log_level = log_level.upper()

    if log_file := os.environ.get("CONTEXT_PROTECTOR_LOG_FILE"):
        config.log_file = log_file

    # LlamaFirewall settings
    if scanner_mode := os.environ.get("CONTEXT_PROTECTOR_SCANNER_MODE"):
        config.llama_firewall.scanner_mode = scanner_mode.lower()

    # NeMo Guardrails settings
    if nemo_mode := os.environ.get("CONTEXT_PROTECTOR_NEMO_MODE"):
        config.nemo_guardrails.mode = nemo_mode.lower()

    if ollama_model := os.environ.get("CONTEXT_PROTECTOR_OLLAMA_MODEL"):
        config.nemo_guardrails.ollama_model = ollama_model

    if ollama_base_url := os.environ.get("CONTEXT_PROTECTOR_OLLAMA_BASE_URL"):
        config.nemo_guardrails.ollama_base_url = ollama_base_url

    # GCP Model Armor settings
    if gcp_project_id := os.environ.get("CONTEXT_PROTECTOR_GCP_PROJECT_ID"):
        config.gcp_model_armor.project_id = gcp_project_id

    if gcp_location := os.environ.get("CONTEXT_PROTECTOR_GCP_LOCATION"):
        config.gcp_model_armor.location = gcp_location

    if gcp_template_id := os.environ.get("CONTEXT_PROTECTOR_GCP_TEMPLATE_ID"):
        config.gcp_model_armor.template_id = gcp_template_id

    return config


def load_config() -> Config:
    """Load configuration from file and environment.

    Priority: Environment variables > Config file > Defaults

    Returns:
        Complete configuration
    """
    config = Config()

    # Load from file if exists
    config_path = get_config_path()
    file_data = _load_config_from_file(config_path)

    if file_data:
        logger.debug("Loaded config from %s", config_path)

        # Merge top-level settings
        if "enabled" in file_data:
            config.enabled = bool(file_data["enabled"])
        if "provider" in file_data:
            config.provider = file_data["provider"]
        if "response_mode" in file_data:
            config.response_mode = file_data["response_mode"]
        if "log_level" in file_data:
            config.log_level = file_data["log_level"]
        if "log_file" in file_data:
            config.log_file = file_data["log_file"]

        # Merge llama_firewall settings
        if "llama_firewall" in file_data and isinstance(file_data["llama_firewall"], dict):
            _merge_dict_into_dataclass(config.llama_firewall, file_data["llama_firewall"])

        # Merge nemo_guardrails settings
        if "nemo_guardrails" in file_data and isinstance(file_data["nemo_guardrails"], dict):
            _merge_dict_into_dataclass(config.nemo_guardrails, file_data["nemo_guardrails"])

        # Merge gcp_model_armor settings
        if "gcp_model_armor" in file_data and isinstance(file_data["gcp_model_armor"], dict):
            _merge_dict_into_dataclass(config.gcp_model_armor, file_data["gcp_model_armor"])

    # Apply environment variable overrides
    config = _apply_env_overrides(config)

    return config


def save_config(config: Config, path: Path | None = None) -> None:
    """Save configuration to file.

    Args:
        config: Configuration to save
        path: Path to save to (defaults to standard config path)
    """
    path = path or get_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w") as f:
        yaml.dump(
            asdict(config),
            f,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )


def save_default_config(path: Path | None = None) -> None:
    """Save the default config template with comments.

    This creates a nicely formatted config file with inline documentation.

    Args:
        path: Path to save to (defaults to standard config path)
    """
    path = path or get_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w") as f:
        f.write(DEFAULT_CONFIG_TEMPLATE)


def init_config(force: bool = False) -> Path:
    """Initialize config file with defaults.

    Args:
        force: Overwrite existing config if True

    Returns:
        Path to created config file

    Raises:
        FileExistsError: If config exists and force=False
    """
    config_path = get_config_path()

    if config_path.exists() and not force:
        raise FileExistsError(f"Config already exists: {config_path}")

    save_default_config(config_path)

    return config_path


def set_enabled(enabled: bool) -> Path:
    """Enable or disable context-protector.

    Updates the 'enabled' field in the config file while preserving
    other settings and comments. Creates config file if it doesn't exist.

    Args:
        enabled: True to enable, False to disable

    Returns:
        Path to config file
    """
    import re

    config_path = get_config_path()

    if not config_path.exists():
        save_default_config(config_path)

    content = config_path.read_text()
    enabled_str = "true" if enabled else "false"

    if re.search(r"^enabled:\s*(true|false)", content, re.MULTILINE):
        content = re.sub(
            r"^enabled:\s*(true|false)",
            f"enabled: {enabled_str}",
            content,
            flags=re.MULTILINE,
        )
    else:
        content = f"enabled: {enabled_str}\n\n" + content

    config_path.write_text(content)
    reset_config()

    return config_path


# Global config instance (loaded lazily)
_config: Config | None = None


def get_config() -> Config:
    """Get the global configuration instance.

    Loads configuration on first access.

    Returns:
        Global configuration instance
    """
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reset_config() -> None:
    """Reset the global configuration instance.

    Forces reload on next get_config() call.
    Useful for testing.
    """
    global _config
    _config = None
