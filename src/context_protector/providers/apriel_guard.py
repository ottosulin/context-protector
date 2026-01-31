"""AprielGuard guardrail provider.

Uses ServiceNow's AprielGuard model to detect safety risks and adversarial attacks.
"""

import logging
import os
import re
from typing import Any

from context_protector.guardrail_types import ContentToCheck, GuardrailAlert
from context_protector.providers.base import GuardrailProvider

logger = logging.getLogger(__name__)

# Safety risk category descriptions
SAFETY_CATEGORIES = {
    "O1": "Toxic Content",
    "O2": "Unfair Representation",
    "O3": "Adult Content",
    "O4": "Erosion of Trust in Public Information",
    "O5": "Propagating Misconceptions",
    "O6": "Risky Financial Practices",
    "O7": "Trade and Compliance",
    "O8": "Dangerous Information",
    "O9": "Privacy Infringement",
    "O10": "Security Threats",
    "O11": "Defamation",
    "O12": "Fraud/Deception",
    "O13": "Influence Operations",
    "O14": "Illegal Activities",
    "O15": "Persuasion/Manipulation",
    "O16": "Property Rights Violation",
}


def parse_output(text: str, reasoning: bool = False) -> dict[str, Any]:
    """Parse AprielGuard model output.

    Args:
        text: Raw model output text
        reasoning: Whether reasoning mode was enabled

    Returns:
        Parsed result with safety and adversarial predictions
    """
    text = text.strip()
    result: dict[str, Any] = {
        "safety_risks_prediction": None,
        "safety_risks_categories": [],
        "adversarial_attacks_prediction": None,
        "safety_risks_reasoning": None,
        "adversarial_attacks_reasoning": None,
    }

    if not reasoning:
        # Standard format: "unsafe-O14,O12\nnon_adversarial" or "safe\nnon_adversarial"
        match = re.match(
            r"(safe|unsafe)-?([\w,]*)\s*\n\s*(adversarial|non_adversarial)",
            text,
            re.IGNORECASE,
        )
        if match:
            result["safety_risks_prediction"] = match.group(1).lower()
            categories_str = match.group(2)
            if categories_str:
                result["safety_risks_categories"] = [
                    c.strip() for c in categories_str.split(",") if c.strip()
                ]
            result["adversarial_attacks_prediction"] = match.group(3).lower()
        return result

    # Reasoning format parsing
    safety_reasoning = re.search(
        r"safety_risks_assessment_reasoning:(.*?),\s*safety_risks_class:",
        text,
        re.DOTALL | re.IGNORECASE,
    )
    adv_reasoning = re.search(
        r"adversarial_attacks_assessment_reasoning:(.*?),\s*adversarial_attacks_class:",
        text,
        re.DOTALL | re.IGNORECASE,
    )

    if safety_reasoning:
        result["safety_risks_reasoning"] = safety_reasoning.group(1).strip()
    if adv_reasoning:
        result["adversarial_attacks_reasoning"] = adv_reasoning.group(1).strip()

    s_class = re.search(r"safety_risks_class:\s*(safe|unsafe)", text, re.IGNORECASE)
    a_class = re.search(
        r"adversarial_attacks_class:\s*(adversarial|non_adversarial)",
        text,
        re.IGNORECASE,
    )

    if s_class:
        result["safety_risks_prediction"] = s_class.group(1).lower()
    if a_class:
        result["adversarial_attacks_prediction"] = a_class.group(1).lower()

    # Extract categories if present
    categories_match = re.search(r"safety_risks_categories:\s*\[(.*?)\]", text, re.IGNORECASE)
    if categories_match:
        categories_str = categories_match.group(1)
        result["safety_risks_categories"] = [
            c.strip().strip("'\"") for c in categories_str.split(",") if c.strip()
        ]

    return result


def format_categories(categories: list[str]) -> str:
    """Format safety risk categories into human-readable string.

    Args:
        categories: List of category codes (e.g., ["O14", "O12"])

    Returns:
        Formatted string with category names
    """
    if not categories:
        return ""

    descriptions = []
    for code in categories:
        code_upper = code.upper()
        if code_upper in SAFETY_CATEGORIES:
            descriptions.append(f"{code_upper}: {SAFETY_CATEGORIES[code_upper]}")
        else:
            descriptions.append(code_upper)

    return ", ".join(descriptions)


class AprielGuardProvider(GuardrailProvider):
    """AprielGuard guardrail provider.

    Uses ServiceNow's AprielGuard model for unified safety
    and adversarial attack detection.

    Environment variables:
    - CONTEXT_PROTECTOR_APRIEL_REASONING: Enable reasoning mode (on/off, default: off)
    - CONTEXT_PROTECTOR_APRIEL_DEVICE: Device to use (auto/cpu/cuda, default: auto)
    """

    def __init__(
        self,
        reasoning: bool | None = None,
        device: str | None = None,
    ) -> None:
        """Initialize the AprielGuard provider.

        Args:
            reasoning: Enable reasoning mode override. If None, uses config/env var.
            device: Device to use (auto/cpu/cuda) override. If None, uses config/env var.
        """
        from context_protector.config import get_config

        config = get_config()

        self._model: Any = None
        self._tokenizer: Any = None
        self._device: str | None = None

        # Reasoning mode: parameter > env > config
        if reasoning is not None:
            self._reasoning_mode = reasoning
        else:
            env_val = os.environ.get("CONTEXT_PROTECTOR_APRIEL_REASONING")
            if env_val:
                self._reasoning_mode = env_val.lower() == "on"
            else:
                self._reasoning_mode = config.apriel_guard.reasoning

        # Device config: parameter > env > config
        if device is not None:
            self._device_config = device.lower()
        else:
            env_val = os.environ.get("CONTEXT_PROTECTOR_APRIEL_DEVICE")
            self._device_config = env_val.lower() if env_val else config.apriel_guard.device.lower()

        logger.info(
            "Initializing AprielGuardProvider (reasoning=%s, device=%s)",
            self._reasoning_mode,
            self._device_config,
        )

    @property
    def name(self) -> str:
        """Get the provider name."""
        return "AprielGuard"

    def _get_device(self) -> str:
        """Determine the device to use for inference."""
        if self._device_config == "cpu":
            return "cpu"
        elif self._device_config == "cuda":
            return "cuda"
        else:
            # Auto-detect
            try:
                import torch

                if torch.cuda.is_available():
                    return "cuda"
                elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                    return "mps"
            except ImportError:
                pass
            return "cpu"

    def _load_model(self) -> None:
        """Lazy load the model on first use."""
        if self._model is not None:
            return

        logger.info("Loading AprielGuard model...")

        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as e:
            raise ImportError(
                "AprielGuard requires 'transformers' and 'torch'. "
                "Install with: pip install transformers torch"
            ) from e

        model_name = "ServiceNow-AI/AprielGuard"
        self._device = self._get_device()

        logger.info("Using device: %s", self._device)

        self._tokenizer = AutoTokenizer.from_pretrained(model_name)
        self._model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch.float16 if self._device != "cpu" else torch.float32,
        )
        self._model.to(self._device)
        self._model.eval()

        logger.info("AprielGuard model loaded successfully")

    def _build_messages(self, content: ContentToCheck) -> list[dict[str, str]]:
        """Build messages for the model based on content type.

        Args:
            content: The content to check

        Returns:
            List of message dicts for the model
        """
        if content.content_type == "tool_output":
            # Tool output - check as assistant response
            return [
                {"role": "user", "content": "Previous user request"},
                {"role": "assistant", "content": content.content},
            ]
        else:
            # Tool input or other - check as standalone content
            return [{"role": "content", "content": content.content}]

    def _generate(self, messages: list[dict[str, str]]) -> str:
        """Generate model output for the given messages.

        Args:
            messages: List of message dicts

        Returns:
            Generated text from the model
        """
        import torch

        # Apply chat template
        if self._reasoning_mode:
            input_ids = self._tokenizer.apply_chat_template(
                messages,
                reasoning_mode="on",
                return_tensors="pt",
            ).to(self._device)
            max_new_tokens = 2000
        else:
            input_ids = self._tokenizer.apply_chat_template(
                messages,
                return_tensors="pt",
            ).to(self._device)
            max_new_tokens = 50

        with torch.no_grad():
            output_ids = self._model.generate(
                input_ids,
                do_sample=False,
                max_new_tokens=max_new_tokens,
                temperature=0.0,
                pad_token_id=self._tokenizer.eos_token_id,
            )

        # Decode only the generated tokens
        generated_text: str = self._tokenizer.decode(
            output_ids[0][input_ids.shape[1] :],
            skip_special_tokens=True,
        )

        return generated_text

    def _create_alert(
        self, parsed: dict[str, Any], content: ContentToCheck
    ) -> GuardrailAlert | None:
        """Create an alert from parsed model output.

        Args:
            parsed: Parsed model output
            content: Original content that was checked

        Returns:
            GuardrailAlert if threat detected, None otherwise
        """
        is_adversarial = parsed.get("adversarial_attacks_prediction") == "adversarial"
        is_unsafe = parsed.get("safety_risks_prediction") == "unsafe"

        if not is_adversarial and not is_unsafe:
            return None

        # Build explanation
        explanations = []

        if is_adversarial:
            explanations.append("Adversarial attack detected (possible prompt injection)")

        if is_unsafe:
            categories = parsed.get("safety_risks_categories", [])
            if categories:
                cat_str = format_categories(categories)
                explanations.append(f"Safety risks detected: {cat_str}")
            else:
                explanations.append("Safety risks detected")

        explanation = "; ".join(explanations)

        # Build alert data
        data: dict[str, Any] = {
            "safety_prediction": parsed.get("safety_risks_prediction"),
            "safety_categories": parsed.get("safety_risks_categories", []),
            "adversarial_prediction": parsed.get("adversarial_attacks_prediction"),
            "content_type": content.content_type,
            "tool_name": content.tool_name,
        }

        # Include reasoning if available
        if parsed.get("safety_risks_reasoning"):
            data["safety_reasoning"] = parsed["safety_risks_reasoning"]
        if parsed.get("adversarial_attacks_reasoning"):
            data["adversarial_reasoning"] = parsed["adversarial_attacks_reasoning"]

        return GuardrailAlert(explanation=explanation, data=data)

    def check_content(self, content: ContentToCheck) -> GuardrailAlert | None:
        """Check content using AprielGuard model.

        Args:
            content: The content to check

        Returns:
            GuardrailAlert indicating AprielGuard is disabled, None otherwise
        """
        """
        logger.info(
            "Checking content: type=%s, tool=%s, length=%d",
            content.content_type,
            content.tool_name,
            len(content.content),
        )

        try:
            self._load_model()

            messages = self._build_messages(content)
            output = self._generate(messages)

            logger.debug("Model output: %s", output[:200])

            parsed = parse_output(output, reasoning=self._reasoning_mode)

            logger.info(
                "Parsed result: safety=%s, adversarial=%s, categories=%s",
                parsed.get("safety_risks_prediction"),
                parsed.get("adversarial_attacks_prediction"),
                parsed.get("safety_risks_categories"),
            )

            return self._create_alert(parsed, content)

        except ImportError as e:
            # Missing dependencies - log warning and skip (not a security issue)
            logger.warning(
                "AprielGuard unavailable: %s. "
                "Install with: uv pip install 'context-protector[aprielguard]'",
                e,
            )
            return None
        except Exception as e:
            logger.exception("Error checking content with AprielGuard")
            return GuardrailAlert(
                explanation=f"Error checking content: {e!s}",
                data={
                    "error": str(e),
                    "content_type": content.content_type,
                    "tool_name": content.tool_name,
                },
            )
        """

        logger.warning(
            "AprielGuard provider is currently disabled. "
            "This provider requires downloading a 16GB model and is not yet production-ready."
        )

        return GuardrailAlert(
            explanation="AprielGuard provider is currently disabled",
            data={
                "provider": "AprielGuard",
                "status": "disabled",
                "reason": "Not yet ready for production use",
            },
        )
