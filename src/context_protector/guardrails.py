"""Guardrail provider loading and management."""

import importlib
import logging
import sys
from typing import cast

from context_protector.config import get_config
from context_protector.providers.base import GuardrailProvider

logger = logging.getLogger(__name__)

# Check if we're running in a test environment
IS_TEST = "pytest" in sys.modules or any("test" in arg.lower() for arg in sys.argv)

# Provider registry - maps names to module paths
PROVIDER_REGISTRY: dict[str, str] = {
    "LlamaFirewall": "context_protector.providers.llama_firewall",
    "AprielGuard": "context_protector.providers.apriel_guard",
    "NeMoGuardrails": "context_protector.providers.nemo_guardrails",
    "GCPModelArmor": "context_protector.providers.gcpmodelarmor_provider",
    "Mock": "context_protector.providers.mock_provider",
    "AlwaysAlert": "context_protector.providers.mock_provider",
    "NeverAlert": "context_protector.providers.mock_provider",
}

# Test-only providers
TEST_ONLY_PROVIDERS = {"Mock", "AlwaysAlert", "NeverAlert"}


def get_provider(name: str | None = None) -> GuardrailProvider:
    """Get a guardrail provider by name.

    Args:
        name: Provider name. If None, uses configuration (env var or config file)

    Returns:
        An instance of the requested provider

    Raises:
        ValueError: If the provider is not found or is test-only in production
    """
    if name is None:
        config = get_config()
        name = config.general.provider

    # Check if provider exists
    if name not in PROVIDER_REGISTRY:
        available = get_available_provider_names()
        msg = f"Unknown provider: {name}. Available providers: {available}"
        raise ValueError(msg)

    # Check if it's a test-only provider in production
    if name in TEST_ONLY_PROVIDERS and not IS_TEST:
        msg = f"Provider '{name}' is only available in test mode"
        raise ValueError(msg)

    # Import the module and get the provider class
    module_path = PROVIDER_REGISTRY[name]
    try:
        module = importlib.import_module(module_path)
    except ImportError as e:
        logger.exception("Failed to import provider module: %s", module_path)
        msg = f"Failed to import provider '{name}': {e}"
        raise ValueError(msg) from e

    # Get the appropriate class based on provider name
    class_map = {
        "LlamaFirewall": "LlamaFirewallProvider",
        "AprielGuard": "AprielGuardProvider",
        "NeMoGuardrails": "NeMoGuardrailsProvider",
        "GCPModelArmor": "GCPModelArmorProvider",
        "Mock": "MockGuardrailProvider",
        "AlwaysAlert": "AlwaysAlertProvider",
        "NeverAlert": "NeverAlertProvider",
    }

    class_name = class_map.get(name)
    if class_name is None:
        msg = f"No class mapping for provider: {name}"
        raise ValueError(msg)

    provider_class = getattr(module, class_name, None)
    if provider_class is None:
        msg = f"Provider class '{class_name}' not found in module '{module_path}'"
        raise ValueError(msg)

    logger.info("Loaded provider: %s", name)
    return cast(GuardrailProvider, provider_class())


def get_available_provider_names() -> list[str]:
    """Get list of available provider names.

    Returns:
        List of provider names available in the current environment
    """
    if IS_TEST:
        return list(PROVIDER_REGISTRY.keys())
    return [name for name in PROVIDER_REGISTRY if name not in TEST_ONLY_PROVIDERS]
