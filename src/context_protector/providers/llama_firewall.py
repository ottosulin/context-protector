"""LlamaFirewall guardrail provider.

Uses Meta's LlamaFirewall to detect prompt injection and other threats.
"""

from __future__ import annotations

import contextlib
import io
import logging
import os
import warnings
from typing import Any

from context_protector.guardrail_types import ContentToCheck, GuardrailAlert
from context_protector.providers.base import GuardrailProvider

logger = logging.getLogger(__name__)

# Suppress warnings before importing HuggingFace-dependent libraries
warnings.filterwarnings("ignore", message=".*incorrect regex pattern.*")
warnings.filterwarnings("ignore", message=".*HfFolder.*")
warnings.filterwarnings("ignore", category=DeprecationWarning)
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("huggingface_hub").setLevel(logging.ERROR)

_llamafirewall_module: Any = None
_import_error: str | None = None


def _get_llamafirewall() -> Any:
    """Lazy import of llamafirewall module with stderr suppression."""
    global _llamafirewall_module, _import_error

    if _llamafirewall_module is not None:
        return _llamafirewall_module

    if _import_error is not None:
        raise ImportError(_import_error)

    try:
        with (
            contextlib.redirect_stderr(io.StringIO()),
            contextlib.redirect_stdout(io.StringIO()),
            warnings.catch_warnings(),
        ):
            warnings.simplefilter("ignore")
            import llamafirewall

            _llamafirewall_module = llamafirewall
            return llamafirewall
    except Exception as e:
        error_str = str(e)
        if "HfFolder" in error_str:
            setup_url = (
                "https://github.com/meta-llama/PurpleLlama/tree/main/"
                "LlamaFirewall#manual-setup"
            )
            _import_error = (
                "LlamaFirewall requires manual model setup. "
                "The Prompt Guard model must be downloaded before use. "
                f"See: {setup_url} - "
                "Or switch to NeMoGuardrails: CONTEXT_PROTECTOR_PROVIDER=NeMoGuardrails"
            )
        else:
            _import_error = error_str
        raise ImportError(_import_error) from e


class LlamaFirewallProvider(GuardrailProvider):
    """LlamaFirewall guardrail provider."""

    def __init__(self, mode: str | None = None) -> None:
        if mode is not None:
            self._scanner_mode = mode.lower()
        else:
            from context_protector.config import get_config

            config = get_config()
            self._scanner_mode = config.llama_firewall.scanner_mode.lower()

        self._use_fallback = False
        self._lf_module: Any = None

    @property
    def name(self) -> str:
        return "LlamaFirewall"

    def _get_module(self) -> Any:
        if self._lf_module is None:
            self._lf_module = _get_llamafirewall()
        return self._lf_module

    def _get_scanners(self) -> list[Any]:
        lf = self._get_module()
        ScannerType = lf.ScannerType

        no_auth = [
            ScannerType.HIDDEN_ASCII,
            ScannerType.REGEX,
            ScannerType.CODE_SHIELD,
        ]
        full = [ScannerType.PROMPT_GUARD] + no_auth

        if self._use_fallback or self._scanner_mode == "basic":
            return no_auth
        return full

    def check_content(self, content: ContentToCheck) -> GuardrailAlert | None:
        try:
            lf_mod = self._get_module()
        except ImportError as e:
            error_str = str(e)
            if "manual model setup" in error_str or "HfFolder" in error_str:
                explanation = error_str
            else:
                explanation = f"LlamaFirewall not available: {e}"
            return GuardrailAlert(
                explanation=explanation,
                data={"error": error_str},
            )

        LlamaFirewall = lf_mod.LlamaFirewall
        Role = lf_mod.Role
        ScanDecision = lf_mod.ScanDecision
        ToolMessage = lf_mod.ToolMessage
        UserMessage = lf_mod.UserMessage

        scanners = self._get_scanners()

        try:
            if content.content_type == "tool_output":
                lf = LlamaFirewall(scanners={Role.TOOL: scanners})
                message = ToolMessage(content=content.content)
            else:
                lf = LlamaFirewall(scanners={Role.USER: scanners})
                message = UserMessage(content=content.content)

            result = lf.scan(message)

            if result.decision == ScanDecision.ALLOW:
                return None

            reason = getattr(result, "reason", None) or "Guardrail triggered"
            explanation = reason.split("\n")[0] if reason else "Security threat detected"

            return GuardrailAlert(
                explanation=explanation,
                data={
                    "decision": str(result.decision),
                    "content_type": content.content_type,
                    "tool_name": content.tool_name,
                },
            )

        except Exception as e:
            error_str = str(e)

            if "gated repo" in error_str or "403" in error_str:
                if not self._use_fallback and self._scanner_mode == "auto":
                    self._use_fallback = True
                    return self.check_content(content)
                else:
                    explanation = (
                        "LlamaFirewall PROMPT_GUARD requires authentication. "
                        "Set CONTEXT_PROTECTOR_SCANNER_MODE=basic to use without auth."
                    )
            elif "HfFolder" in error_str:
                setup_url = (
                    "https://github.com/meta-llama/PurpleLlama/tree/main/"
                    "LlamaFirewall#manual-setup"
                )
                if not self._use_fallback and self._scanner_mode == "auto":
                    self._use_fallback = True
                    return self.check_content(content)
                explanation = (
                    "LlamaFirewall requires manual model setup. "
                    f"See: {setup_url} - "
                    "Or set CONTEXT_PROTECTOR_SCANNER_MODE=basic"
                )
            else:
                explanation = f"LlamaFirewall error: {error_str}"

            return GuardrailAlert(
                explanation=explanation,
                data={"error": error_str},
            )
