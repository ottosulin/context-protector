"""Mock guardrail providers for testing."""

import logging

from context_protector.guardrail_types import ContentToCheck, GuardrailAlert
from context_protector.providers.base import GuardrailProvider

logger = logging.getLogger(__name__)


class MockGuardrailProvider(GuardrailProvider):
    """A configurable mock guardrail provider for testing.

    Can be configured to trigger or not trigger alerts for testing purposes.
    Only available when running tests.
    """

    def __init__(self) -> None:
        """Initialize the mock provider."""
        logger.info("Initializing MockGuardrailProvider")
        self._trigger_alert: bool = False
        self._alert_text: str = "Mock security alert"

    @property
    def name(self) -> str:
        """Get the provider name."""
        return "Mock"

    def set_trigger_alert(self, alert_text: str | None = None) -> None:
        """Configure the provider to trigger an alert.

        Args:
            alert_text: Optional custom alert text
        """
        logger.info("Setting trigger_alert to True")
        self._trigger_alert = True
        if alert_text is not None:
            self._alert_text = alert_text

    def unset_trigger_alert(self) -> None:
        """Configure the provider to not trigger an alert."""
        logger.info("Setting trigger_alert to False")
        self._trigger_alert = False
        self._alert_text = "Mock security alert"

    def check_content(self, content: ContentToCheck) -> GuardrailAlert | None:
        """Check content based on current trigger setting.

        Args:
            content: The content to check

        Returns:
            GuardrailAlert if trigger is set, None otherwise
        """
        logger.info(
            "MockGuardrailProvider checking content: type=%s, trigger=%s",
            content.content_type,
            self._trigger_alert,
        )

        if self._trigger_alert:
            logger.info("Triggering mock alert: %s", self._alert_text)
            return GuardrailAlert(
                explanation=self._alert_text,
                data={
                    "mock": True,
                    "content_type": content.content_type,
                    "tool_name": content.tool_name,
                    "content_length": len(content.content),
                },
            )

        logger.debug("No alert triggered")
        return None


class AlwaysAlertProvider(GuardrailProvider):
    """A mock provider that always triggers an alert.

    Useful for testing alert handling behavior.
    """

    def __init__(self, alert_text: str = "Security threat detected") -> None:
        """Initialize the always-alert provider.

        Args:
            alert_text: The text to use for alerts
        """
        logger.info("Initializing AlwaysAlertProvider")
        self._alert_text = alert_text

    @property
    def name(self) -> str:
        """Get the provider name."""
        return "AlwaysAlert"

    def check_content(self, content: ContentToCheck) -> GuardrailAlert:
        """Always return an alert.

        Args:
            content: The content to check

        Returns:
            GuardrailAlert with configured text
        """
        logger.info("AlwaysAlertProvider triggering alert")
        return GuardrailAlert(
            explanation=self._alert_text,
            data={
                "always_alert": True,
                "content_type": content.content_type,
                "tool_name": content.tool_name,
            },
        )


class NeverAlertProvider(GuardrailProvider):
    """A mock provider that never triggers an alert.

    Useful for testing normal operation flow.
    """

    def __init__(self) -> None:
        """Initialize the never-alert provider."""
        logger.info("Initializing NeverAlertProvider")

    @property
    def name(self) -> str:
        """Get the provider name."""
        return "NeverAlert"

    def check_content(self, content: ContentToCheck) -> None:
        """Never return an alert.

        Args:
            content: The content to check

        Returns:
            None, always
        """
        logger.debug("NeverAlertProvider: allowing content")
        return None
