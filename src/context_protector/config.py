"""Configuration management for Claude Context Protector.

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

# Default thresholds for NeMo jailbreak heuristics
DEFAULT_PERPLEXITY_THRESHOLD = 89.79
DEFAULT_PREFIX_THRESHOLD = 1845.65

# Default Ollama settings for local mode
DEFAULT_OLLAMA_MODEL = "mistral:7b"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"

# Default config file template with comments
DEFAULT_CONFIG_TEMPLATE = """\
# Claude Context Protector Configuration
# Location: ~/.config/context-protector/config.yaml
#
# Environment variables take precedence over this file.
# Run 'context-protector init' to regenerate defaults.

# General settings
general:
  # Mode: default, single, or multi
  # - default: LlamaFirewall (auto) + NeMo (all)
  # - single: Use single provider from 'provider' setting
  # - multi: Use providers from 'providers' list
  mode: default

  # Single provider (when mode: single)
  provider: LlamaFirewall

  # Multi-provider list (when mode: multi)
  # Format: "ProviderName" or "ProviderName:mode"
  providers: []

  # Logging
  log_level: WARNING  # DEBUG, INFO, WARNING, ERROR
  log_file: null      # Optional log file path

  # Response mode when threats detected: warn or block
  # - warn: Inject warning message, allow content through (default)
  # - block: Suppress malicious content, prevent it from reaching model
  response_mode: warn

# LlamaFirewall provider settings
llama_firewall:
  # Enabled in default mode
  enabled: true

  # Scanner mode: auto, basic, or full
  # - auto: Try full, fall back to basic on auth error (recommended)
  # - basic: No auth required (HIDDEN_ASCII, REGEX, CODE_SHIELD)
  # - full: Requires HuggingFace auth (includes PROMPT_GUARD)
  scanner_mode: auto

# NeMo Guardrails provider settings
nemo_guardrails:
  # Enabled in default mode
  enabled: true

  # Detection mode: heuristics, injection, self_check, local, or all
  # - heuristics: Perplexity-based jailbreak detection (local, no API)
  # - injection: YARA-based SQL/XSS/code injection detection (local, no API)
  # - self_check: LLM-based validation (requires OpenAI API)
  # - local: LLM-based validation using Ollama (local, no API key)
  # - all: heuristics + injection combined
  mode: all

  # Custom config directory (optional)
  config_path: null

  # OpenAI model for self_check mode
  openai_model: gpt-4o-mini

  # Ollama settings for local mode
  # Recommended models: mistral:7b (default), phi3 (lighter, ~4GB RAM)
  ollama_model: mistral:7b
  ollama_base_url: http://localhost:11434

  # Jailbreak heuristics thresholds
  perplexity_threshold: 89.79
  prefix_threshold: 1845.65

# AprielGuard provider settings
apriel_guard:
  enabled: false

  # Reasoning mode: on or off
  # Provides detailed explanations when enabled
  reasoning: false

  # Device: auto, cpu, or cuda
  device: auto

# GCP Model Armor provider settings
# Requires: google-cloud-modelarmor package
# See: https://cloud.google.com/security-command-center/docs/model-armor-overview
gcp_model_armor:
  enabled: false
  project_id: null      # Your GCP project ID
  location: null        # GCP region (e.g., us-central1)
  template_id: null     # Model Armor template ID
"""


@dataclass
class LlamaFirewallConfig:
    """LlamaFirewall provider configuration."""

    enabled: bool = True
    scanner_mode: str = "auto"


@dataclass
class NeMoGuardrailsConfig:
    """NeMo Guardrails provider configuration."""

    enabled: bool = True
    mode: str = "all"
    config_path: str | None = None
    openai_model: str = "gpt-4o-mini"
    ollama_model: str = DEFAULT_OLLAMA_MODEL
    ollama_base_url: str = DEFAULT_OLLAMA_BASE_URL
    perplexity_threshold: float = DEFAULT_PERPLEXITY_THRESHOLD
    prefix_threshold: float = DEFAULT_PREFIX_THRESHOLD


@dataclass
class AprielGuardConfig:
    """AprielGuard provider configuration."""

    enabled: bool = False
    reasoning: bool = False
    device: str = "auto"

@dataclass
class GCPModelArmorConfig:
    """GCP Model Armor provider configuration."""

    enabled: bool = False
    project_id: str | None = None
    location: str | None = None
    template_id: str | None = None

@dataclass
class GeneralConfig:
    """General configuration."""

    mode: str = "default"
    provider: str = "LlamaFirewall"
    providers: list[str] = field(default_factory=list)
    log_level: str = "WARNING"
    log_file: str | None = None
    response_mode: str = "warn"  # warn or block


@dataclass
class Config:
    """Complete configuration."""

    general: GeneralConfig = field(default_factory=GeneralConfig)
    llama_firewall: LlamaFirewallConfig = field(default_factory=LlamaFirewallConfig)
    nemo_guardrails: NeMoGuardrailsConfig = field(default_factory=NeMoGuardrailsConfig)
    apriel_guard: AprielGuardConfig = field(default_factory=AprielGuardConfig)
    gcp_model_armor: GCPModelArmorConfig = field(default_factory=GCPModelArmorConfig)


def get_config_path() -> Path:
    """Get the config file path.

    Respects XDG_CONFIG_HOME if set, otherwise uses ~/.config.

    Returns:
        Path to the config file
    """
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
    # General settings
    if mode := os.environ.get("CONTEXT_PROTECTOR_MODE"):
        config.general.mode = mode.lower()

    if provider := os.environ.get("CONTEXT_PROTECTOR_PROVIDER"):
        config.general.provider = provider

    if providers := os.environ.get("CONTEXT_PROTECTOR_PROVIDERS"):
        config.general.providers = [p.strip() for p in providers.split(",") if p.strip()]

    if log_level := os.environ.get("CONTEXT_PROTECTOR_LOG_LEVEL"):
        config.general.log_level = log_level.upper()

    if log_file := os.environ.get("CONTEXT_PROTECTOR_LOG_FILE"):
        config.general.log_file = log_file

    if response_mode := os.environ.get("CONTEXT_PROTECTOR_RESPONSE_MODE"):
        config.general.response_mode = response_mode.lower()

    # LlamaFirewall settings
    if scanner_mode := os.environ.get("CONTEXT_PROTECTOR_SCANNER_MODE"):
        config.llama_firewall.scanner_mode = scanner_mode.lower()

    # AprielGuard settings
    if reasoning := os.environ.get("CONTEXT_PROTECTOR_APRIEL_REASONING"):
        config.apriel_guard.reasoning = reasoning.lower() == "on"

    if device := os.environ.get("CONTEXT_PROTECTOR_APRIEL_DEVICE"):
        config.apriel_guard.device = device.lower()

    # NeMo Guardrails settings
    if nemo_mode := os.environ.get("CONTEXT_PROTECTOR_NEMO_MODE"):
        config.nemo_guardrails.mode = nemo_mode.lower()

    if nemo_config_path := os.environ.get("CONTEXT_PROTECTOR_NEMO_CONFIG_PATH"):
        config.nemo_guardrails.config_path = nemo_config_path

    if nemo_openai_model := os.environ.get("CONTEXT_PROTECTOR_NEMO_OPENAI_MODEL"):
        config.nemo_guardrails.openai_model = nemo_openai_model

    if ollama_model := os.environ.get("CONTEXT_PROTECTOR_NEMO_OLLAMA_MODEL"):
        config.nemo_guardrails.ollama_model = ollama_model

    if ollama_base_url := os.environ.get("CONTEXT_PROTECTOR_NEMO_OLLAMA_BASE_URL"):
        config.nemo_guardrails.ollama_base_url = ollama_base_url

    if perplexity := os.environ.get("CONTEXT_PROTECTOR_NEMO_PERPLEXITY_THRESHOLD"):
        try:
            config.nemo_guardrails.perplexity_threshold = float(perplexity)
        except ValueError:
            logger.warning("Invalid perplexity threshold: %s", perplexity)

    if prefix := os.environ.get("CONTEXT_PROTECTOR_NEMO_PREFIX_THRESHOLD"):
        try:
            config.nemo_guardrails.prefix_threshold = float(prefix)
        except ValueError:
            logger.warning("Invalid prefix threshold: %s", prefix)

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

        # Merge general settings
        if "general" in file_data and isinstance(file_data["general"], dict):
            _merge_dict_into_dataclass(config.general, file_data["general"])

        # Merge llama_firewall settings
        if "llama_firewall" in file_data and isinstance(file_data["llama_firewall"], dict):
            _merge_dict_into_dataclass(config.llama_firewall, file_data["llama_firewall"])

        # Merge nemo_guardrails settings
        if "nemo_guardrails" in file_data and isinstance(file_data["nemo_guardrails"], dict):
            _merge_dict_into_dataclass(config.nemo_guardrails, file_data["nemo_guardrails"])

        # Merge apriel_guard settings
        if "apriel_guard" in file_data and isinstance(file_data["apriel_guard"], dict):
            _merge_dict_into_dataclass(config.apriel_guard, file_data["apriel_guard"])

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

    # Use the template with comments for better UX
    save_default_config(config_path)

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
