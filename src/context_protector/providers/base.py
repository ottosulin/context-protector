"""Base guardrail provider class."""

from abc import ABC, abstractmethod

from context_protector.guardrail_types import ContentToCheck, GuardrailAlert


class GuardrailProvider(ABC):
    """Base class for guardrail providers.

    Guardrail providers check content for potential security threats
    such as prompt injection attacks.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Get the provider name.

        Returns:
            The name of this provider
        """

    @abstractmethod
    def check_content(self, content: ContentToCheck) -> GuardrailAlert | None:
        """Check content for security threats.

        Args:
            content: The content to check

        Returns:
            GuardrailAlert if a threat is detected, None otherwise
        """
