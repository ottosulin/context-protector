"""Tests for AprielGuard provider."""


from context_protector.guardrail_types import ContentToCheck
from context_protector.providers.apriel_guard import (
    SAFETY_CATEGORIES,
    AprielGuardProvider,
    format_categories,
    parse_output,
)


class TestParseOutputStandard:
    """Tests for parse_output with standard format."""

    def test_parse_safe_non_adversarial(self) -> None:
        """Test parsing safe, non-adversarial output."""
        text = "safe\nnon_adversarial"
        result = parse_output(text)

        assert result["safety_risks_prediction"] == "safe"
        assert result["safety_risks_categories"] == []
        assert result["adversarial_attacks_prediction"] == "non_adversarial"

    def test_parse_unsafe_with_categories(self) -> None:
        """Test parsing unsafe output with categories."""
        text = "unsafe-O14,O12\nnon_adversarial"
        result = parse_output(text)

        assert result["safety_risks_prediction"] == "unsafe"
        assert result["safety_risks_categories"] == ["O14", "O12"]
        assert result["adversarial_attacks_prediction"] == "non_adversarial"

    def test_parse_unsafe_adversarial(self) -> None:
        """Test parsing unsafe and adversarial output."""
        text = "unsafe-O10\nadversarial"
        result = parse_output(text)

        assert result["safety_risks_prediction"] == "unsafe"
        assert result["safety_risks_categories"] == ["O10"]
        assert result["adversarial_attacks_prediction"] == "adversarial"

    def test_parse_safe_adversarial(self) -> None:
        """Test parsing safe but adversarial output."""
        text = "safe\nadversarial"
        result = parse_output(text)

        assert result["safety_risks_prediction"] == "safe"
        assert result["safety_risks_categories"] == []
        assert result["adversarial_attacks_prediction"] == "adversarial"

    def test_parse_multiple_categories(self) -> None:
        """Test parsing output with multiple categories."""
        text = "unsafe-O1,O2,O3,O14\nnon_adversarial"
        result = parse_output(text)

        assert result["safety_risks_prediction"] == "unsafe"
        assert result["safety_risks_categories"] == ["O1", "O2", "O3", "O14"]
        assert result["adversarial_attacks_prediction"] == "non_adversarial"

    def test_parse_case_insensitive(self) -> None:
        """Test case insensitive parsing."""
        text = "UNSAFE-O14\nADVERSARIAL"
        result = parse_output(text)

        assert result["safety_risks_prediction"] == "unsafe"
        assert result["adversarial_attacks_prediction"] == "adversarial"

    def test_parse_with_whitespace(self) -> None:
        """Test parsing with extra whitespace."""
        text = "  unsafe-O14  \n  non_adversarial  "
        result = parse_output(text)

        assert result["safety_risks_prediction"] == "unsafe"
        assert result["adversarial_attacks_prediction"] == "non_adversarial"

    def test_parse_invalid_format(self) -> None:
        """Test parsing invalid format returns None values."""
        text = "invalid output"
        result = parse_output(text)

        assert result["safety_risks_prediction"] is None
        assert result["safety_risks_categories"] == []
        assert result["adversarial_attacks_prediction"] is None


class TestParseOutputReasoning:
    """Tests for parse_output with reasoning format."""

    def test_parse_reasoning_format(self) -> None:
        """Test parsing reasoning format output."""
        text = """
        safety_risks_assessment_reasoning: The content discusses illegal activities,
        safety_risks_class: unsafe
        safety_risks_categories: [O14, O12]
        adversarial_attacks_assessment_reasoning: The input contains manipulation attempts,
        adversarial_attacks_class: adversarial
        """
        result = parse_output(text, reasoning=True)

        assert result["safety_risks_prediction"] == "unsafe"
        assert result["adversarial_attacks_prediction"] == "adversarial"
        assert "illegal activities" in result["safety_risks_reasoning"]
        assert "manipulation attempts" in result["adversarial_attacks_reasoning"]

    def test_parse_reasoning_safe(self) -> None:
        """Test parsing reasoning format with safe content."""
        text = """
        safety_risks_assessment_reasoning: The content is harmless,
        safety_risks_class: safe
        adversarial_attacks_assessment_reasoning: No manipulation detected,
        adversarial_attacks_class: non_adversarial
        """
        result = parse_output(text, reasoning=True)

        assert result["safety_risks_prediction"] == "safe"
        assert result["adversarial_attacks_prediction"] == "non_adversarial"


class TestFormatCategories:
    """Tests for format_categories function."""

    def test_format_single_category(self) -> None:
        """Test formatting a single category."""
        result = format_categories(["O14"])
        assert result == "O14: Illegal Activities"

    def test_format_multiple_categories(self) -> None:
        """Test formatting multiple categories."""
        result = format_categories(["O14", "O12"])
        assert "O14: Illegal Activities" in result
        assert "O12: Fraud/Deception" in result

    def test_format_unknown_category(self) -> None:
        """Test formatting unknown category."""
        result = format_categories(["O99"])
        assert result == "O99"

    def test_format_empty_list(self) -> None:
        """Test formatting empty list."""
        result = format_categories([])
        assert result == ""

    def test_format_lowercase_category(self) -> None:
        """Test formatting lowercase category code."""
        result = format_categories(["o14"])
        assert "O14: Illegal Activities" in result


class TestSafetyCategories:
    """Tests for safety categories constant."""

    def test_all_categories_defined(self) -> None:
        """Test all 16 categories are defined."""
        assert len(SAFETY_CATEGORIES) == 16

    def test_category_codes(self) -> None:
        """Test category codes are correct."""
        assert "O1" in SAFETY_CATEGORIES
        assert "O16" in SAFETY_CATEGORIES
        assert SAFETY_CATEGORIES["O1"] == "Toxic Content"
        assert SAFETY_CATEGORIES["O10"] == "Security Threats"


class TestAprielGuardProvider:
    """Tests for AprielGuardProvider class."""

    def test_provider_name(self) -> None:
        """Test provider name."""
        provider = AprielGuardProvider()
        assert provider.name == "AprielGuard"

    def test_build_messages_tool_input(self) -> None:
        """Test building messages for tool input."""
        provider = AprielGuardProvider()
        content = ContentToCheck(
            content="test command",
            content_type="tool_input",
            tool_name="Bash",
        )
        messages = provider._build_messages(content)

        assert len(messages) == 1
        assert messages[0]["role"] == "content"
        assert messages[0]["content"] == "test command"

    def test_build_messages_tool_output(self) -> None:
        """Test building messages for tool output."""
        provider = AprielGuardProvider()
        content = ContentToCheck(
            content="file contents here",
            content_type="tool_output",
            tool_name="Read",
        )
        messages = provider._build_messages(content)

        assert len(messages) == 2
        assert messages[0]["role"] == "user"
        assert messages[1]["role"] == "assistant"
        assert messages[1]["content"] == "file contents here"

    def test_create_alert_safe(self) -> None:
        """Test no alert for safe content."""
        provider = AprielGuardProvider()
        parsed = {
            "safety_risks_prediction": "safe",
            "safety_risks_categories": [],
            "adversarial_attacks_prediction": "non_adversarial",
        }
        content = ContentToCheck(
            content="test",
            content_type="tool_input",
            tool_name="Bash",
        )

        alert = provider._create_alert(parsed, content)
        assert alert is None

    def test_create_alert_adversarial(self) -> None:
        """Test alert for adversarial content."""
        provider = AprielGuardProvider()
        parsed = {
            "safety_risks_prediction": "safe",
            "safety_risks_categories": [],
            "adversarial_attacks_prediction": "adversarial",
        }
        content = ContentToCheck(
            content="test",
            content_type="tool_input",
            tool_name="Bash",
        )

        alert = provider._create_alert(parsed, content)
        assert alert is not None
        assert "Adversarial attack" in alert.explanation
        assert "prompt injection" in alert.explanation

    def test_create_alert_unsafe(self) -> None:
        """Test alert for unsafe content."""
        provider = AprielGuardProvider()
        parsed = {
            "safety_risks_prediction": "unsafe",
            "safety_risks_categories": ["O14", "O12"],
            "adversarial_attacks_prediction": "non_adversarial",
        }
        content = ContentToCheck(
            content="test",
            content_type="tool_input",
            tool_name="Bash",
        )

        alert = provider._create_alert(parsed, content)
        assert alert is not None
        assert "Safety risks" in alert.explanation
        assert "O14" in alert.explanation
        assert "Illegal Activities" in alert.explanation

    def test_create_alert_both(self) -> None:
        """Test alert for both unsafe and adversarial content."""
        provider = AprielGuardProvider()
        parsed = {
            "safety_risks_prediction": "unsafe",
            "safety_risks_categories": ["O10"],
            "adversarial_attacks_prediction": "adversarial",
        }
        content = ContentToCheck(
            content="test",
            content_type="tool_input",
            tool_name="Bash",
        )

        alert = provider._create_alert(parsed, content)
        assert alert is not None
        assert "Adversarial attack" in alert.explanation
        assert "Safety risks" in alert.explanation


class TestAprielGuardProviderRegistry:
    """Tests for AprielGuard in provider registry."""

    def test_aprielguard_in_registry(self) -> None:
        """Test AprielGuard is in provider registry."""
        from context_protector.guardrails import PROVIDER_REGISTRY

        assert "AprielGuard" in PROVIDER_REGISTRY

    def test_aprielguard_in_available_providers(self) -> None:
        """Test AprielGuard is in available providers."""
        from context_protector.guardrails import get_available_provider_names

        available = get_available_provider_names()
        assert "AprielGuard" in available

    def test_aprielguard_disabled_behavior(self) -> None:
        """Test that AprielGuard returns disabled alert."""
        from context_protector.guardrail_types import ContentToCheck
        from context_protector.providers.apriel_guard import AprielGuardProvider

        provider = AprielGuardProvider()

        content = ContentToCheck(
            content="Test content",
            content_type="tool_input",
            tool_name="test_tool",
        )

        alert = provider.check_content(content)

        assert alert is not None
        assert "disabled" in alert.explanation.lower()
        assert alert.data["status"] == "disabled"
        assert alert.data["provider"] == "AprielGuard"
