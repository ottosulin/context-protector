"""LlamaFirewall guardrail provider.

Uses Meta's LlamaFirewall to detect prompt injection and other threats.
"""

import logging
import os
import warnings

# Suppress the tokenizer regex warning from HuggingFace transformers/tokenizers
# This is a known issue with the Llama-Prompt-Guard-2-86M tokenizer
# See: https://github.com/huggingface/transformers/issues/42591
warnings.filterwarnings(
    "ignore",
    message=".*incorrect regex pattern.*fix_mistral_regex.*",
)

# Set environment variables to suppress tokenizers warnings before import
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
# Set transformers verbosity to error to suppress regex warnings
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")

# Suppress transformers logging for non-critical messages
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("transformers.tokenization_utils_base").setLevel(logging.ERROR)

# Import after environment setup to ensure warnings are suppressed
from llamafirewall import (  # noqa: E402
    LlamaFirewall,
    Role,
    ScanDecision,
    ScannerType,
    ToolMessage,
    UserMessage,
)

from context_protector.guardrail_types import (  # noqa: E402
    ContentToCheck,
    GuardrailAlert,
)
from context_protector.providers.base import GuardrailProvider  # noqa: E402

logger = logging.getLogger(__name__)

# Scanner types that don't require external authentication
NO_AUTH_SCANNERS = [
    ScannerType.HIDDEN_ASCII,
    ScannerType.REGEX,
    ScannerType.CODE_SHIELD,
]

# Full scanner list including PROMPT_GUARD (requires HuggingFace auth)
FULL_SCANNERS = [ScannerType.PROMPT_GUARD] + NO_AUTH_SCANNERS


def _get_scanner_config(scanner_mode: str) -> list[ScannerType]:
    """Get scanner configuration based on mode.

    Args:
        scanner_mode: Scanner mode (auto, basic, or full)

    Returns:
        List of scanner types to use
    """
    if scanner_mode == "full":
        # User explicitly wants PROMPT_GUARD (requires auth)
        return FULL_SCANNERS
    elif scanner_mode == "basic":
        # User explicitly wants no-auth scanners only
        return NO_AUTH_SCANNERS
    else:
        # Auto mode: try PROMPT_GUARD first, fall back to basic if it fails
        return FULL_SCANNERS


class LlamaFirewallProvider(GuardrailProvider):
    """LlamaFirewall guardrail provider.

    Uses LlamaFirewall's scanners to detect prompt injection
    and other security threats in content.

    Scanner modes (set via config or CONTEXT_PROTECTOR_SCANNER_MODE):
    - "auto" (default): Try full scanners, fall back to basic on auth error
    - "full": Use PROMPT_GUARD + basic scanners (requires HuggingFace auth)
    - "basic": Use only no-auth scanners (HIDDEN_ASCII, REGEX, CODE_SHIELD)
    """

    def __init__(self, mode: str | None = None) -> None:
        """Initialize the LlamaFirewall provider.

        Args:
            mode: Scanner mode override. If None, uses config/env var.
        """
        if mode is not None:
            self._scanner_mode = mode.lower()
        else:
            from context_protector.config import get_config

            config = get_config()
            self._scanner_mode = config.llama_firewall.scanner_mode.lower()

        self._use_fallback = False
        logger.info(
            "Initializing LlamaFirewallProvider (scanner_mode=%s)",
            self._scanner_mode,
        )

    @property
    def name(self) -> str:
        """Get the provider name."""
        return "LlamaFirewall"

    def _get_scanners(self) -> list[ScannerType]:
        """Get the scanners to use based on mode and fallback state."""
        if self._use_fallback or self._scanner_mode == "basic":
            return NO_AUTH_SCANNERS
        return _get_scanner_config(self._scanner_mode)

    def check_content(self, content: ContentToCheck) -> GuardrailAlert | None:
        """Check content for security threats using LlamaFirewall.

        Args:
            content: The content to check

        Returns:
            GuardrailAlert if a threat is detected, None otherwise
        """

        scanners = self._get_scanners()
        scanner_names = [s.name for s in scanners]
        logger.debug("Using scanners: %s", scanner_names)

        try:
            # Configure scanner based on content type
            if content.content_type == "tool_output":
                # Tool outputs use TOOL role
                lf = LlamaFirewall(scanners={Role.TOOL: scanners})
                message = ToolMessage(content=content.content)
            else:
                # Tool inputs and other content use USER role
                lf = LlamaFirewall(scanners={Role.USER: scanners})
                message = UserMessage(content=content.content)

            logger.debug("Scanning content with LlamaFirewall...")
            result = lf.scan(message)

            logger.info("Scan result: decision=%s", result.decision)

            if result.decision == ScanDecision.ALLOW:
                logger.debug("Content allowed")
                return None

            # Content blocked - create alert
            reason = getattr(result, "reason", None) or "Guardrail triggered"
            explanation = reason.split("\n")[0] if reason else "Security threat detected"

            logger.warning("Security threat detected: %s", explanation)
            return GuardrailAlert(
                explanation=explanation,
                data={
                    "full_reason": reason,
                    "decision": str(result.decision),
                    "scanners": scanner_names,
                    "content_type": content.content_type,
                    "tool_name": content.tool_name,
                },
            )

        except Exception as e:
            logger.exception("Error checking content with LlamaFirewall")
            error_str = str(e)

            # Detect HuggingFace auth issues and fall back to basic scanners
            if "gated repo" in error_str or "403" in error_str:
                if not self._use_fallback and self._scanner_mode == "auto":
                    logger.warning(
                        "PROMPT_GUARD requires HuggingFace auth. "
                        "Falling back to basic scanners (HIDDEN_ASCII, REGEX, CODE_SHIELD). "
                        "For full protection, run: llamafirewall configure"
                    )
                    self._use_fallback = True
                    # Retry with basic scanners
                    return self.check_content(content)
                else:
                    explanation = (
                        "LlamaFirewall PROMPT_GUARD requires authentication. "
                        "Run 'llamafirewall configure' or set CONTEXT_PROTECTOR_SCANNER_MODE=basic"
                    )
            else:
                explanation = f"Error checking content: {error_str}"

            # Return an alert on error to be safe
            return GuardrailAlert(
                explanation=explanation,
                data={
                    "error": error_str,
                    "content_type": content.content_type,
                    "tool_name": content.tool_name,
                },
            )
