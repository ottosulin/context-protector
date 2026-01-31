"""Tests for GCP Model Armor provider."""

from unittest.mock import MagicMock, patch

from context_protector.guardrail_types import ContentToCheck
from context_protector.providers.gcpmodelarmor_provider import GCPModelArmorProvider


class TestGCPModelArmorProviderInit:
    """Tests for GCPModelArmorProvider initialization."""

    def test_provider_name(self) -> None:
        """Test provider name."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )
        assert provider.name == "GCPModelArmor"

    def test_init_with_parameters(self) -> None:
        """Test initialization with explicit parameters."""
        provider = GCPModelArmorProvider(
            project_id="my-project",
            location="europe-west1",
            template_id="my-template",
        )
        assert provider._project_id == "my-project"
        assert provider._location == "europe-west1"
        assert provider._template_id == "my-template"

    def test_init_from_env_vars(self) -> None:
        """Test initialization from environment variables."""
        with patch.dict(
            "os.environ",
            {
                "CONTEXT_PROTECTOR_GCP_PROJECT_ID": "env-project",
                "CONTEXT_PROTECTOR_GCP_LOCATION": "asia-east1",
                "CONTEXT_PROTECTOR_GCP_TEMPLATE_ID": "env-template",
            },
        ):
            provider = GCPModelArmorProvider()
            assert provider._project_id == "env-project"
            assert provider._location == "asia-east1"
            assert provider._template_id == "env-template"

    def test_params_override_env_vars(self) -> None:
        """Test that explicit parameters override environment variables."""
        with patch.dict(
            "os.environ",
            {
                "CONTEXT_PROTECTOR_GCP_PROJECT_ID": "env-project",
                "CONTEXT_PROTECTOR_GCP_LOCATION": "asia-east1",
                "CONTEXT_PROTECTOR_GCP_TEMPLATE_ID": "env-template",
            },
        ):
            provider = GCPModelArmorProvider(
                project_id="param-project",
                location="param-location",
                template_id="param-template",
            )
            assert provider._project_id == "param-project"
            assert provider._location == "param-location"
            assert provider._template_id == "param-template"


class TestGCPModelArmorProviderValidation:
    """Tests for configuration validation."""

    def test_validate_config_success(self) -> None:
        """Test successful configuration validation."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )
        assert provider._validate_config() is None

    def test_validate_config_missing_project_id(self) -> None:
        """Test validation fails when project_id is missing."""
        # Mock config to return empty values (isolate from user's config file)
        mock_config = MagicMock()
        mock_config.gcp_model_armor.project_id = None
        mock_config.gcp_model_armor.location = None
        mock_config.gcp_model_armor.template_id = None

        with patch("context_protector.config.get_config", return_value=mock_config):
            provider = GCPModelArmorProvider(
                project_id=None,
                location="us-central1",
                template_id="test-template",
            )
            error = provider._validate_config()
            assert error is not None
            assert "project_id" in error

    def test_validate_config_missing_location(self) -> None:
        """Test validation fails when location is missing."""
        # Mock config to return empty values (isolate from user's config file)
        mock_config = MagicMock()
        mock_config.gcp_model_armor.project_id = None
        mock_config.gcp_model_armor.location = None
        mock_config.gcp_model_armor.template_id = None

        with patch("context_protector.config.get_config", return_value=mock_config):
            provider = GCPModelArmorProvider(
                project_id="test-project",
                location=None,
                template_id="test-template",
            )
            error = provider._validate_config()
            assert error is not None
            assert "location" in error

    def test_validate_config_missing_template_id(self) -> None:
        """Test validation fails when template_id is missing."""
        # Mock config to return empty values (isolate from user's config file)
        mock_config = MagicMock()
        mock_config.gcp_model_armor.project_id = None
        mock_config.gcp_model_armor.location = None
        mock_config.gcp_model_armor.template_id = None

        with patch("context_protector.config.get_config", return_value=mock_config):
            provider = GCPModelArmorProvider(
                project_id="test-project",
                location="us-central1",
                template_id=None,
            )
            error = provider._validate_config()
            assert error is not None
            assert "template_id" in error

    def test_validate_config_all_missing(self) -> None:
        """Test validation fails when all config is missing."""
        # Mock config to return empty values (isolate from user's config file)
        mock_config = MagicMock()
        mock_config.gcp_model_armor.project_id = None
        mock_config.gcp_model_armor.location = None
        mock_config.gcp_model_armor.template_id = None

        with patch("context_protector.config.get_config", return_value=mock_config):
            provider = GCPModelArmorProvider(
                project_id=None,
                location=None,
                template_id=None,
            )
            error = provider._validate_config()
            assert error is not None
            assert "project_id" in error
            assert "location" in error
            assert "template_id" in error


class TestGCPModelArmorProviderCheckContent:
    """Tests for check_content method."""

    def test_check_content_missing_config(self) -> None:
        """Test check_content returns alert when config is missing."""
        # Mock config to return empty values (isolate from user's config file)
        mock_config = MagicMock()
        mock_config.gcp_model_armor.project_id = None
        mock_config.gcp_model_armor.location = None
        mock_config.gcp_model_armor.template_id = None

        with patch("context_protector.config.get_config", return_value=mock_config):
            provider = GCPModelArmorProvider(
                project_id=None,
                location=None,
                template_id=None,
            )

            content = ContentToCheck(
                content="Test content",
                content_type="tool_input",
                tool_name="Bash",
            )

            alert = provider.check_content(content)
            assert alert is not None
            assert "configuration error" in alert.explanation.lower()
            assert alert.data["error"] == "configuration_error"

    def test_check_content_safe(self) -> None:
        """Test check_content returns None for safe content."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # Mock the _sanitize_content method
        provider._sanitize_content = MagicMock(return_value=(True, {"is_safe": True}))  # type: ignore[method-assign]

        content = ContentToCheck(
            content="Hello, how are you?",
            content_type="tool_input",
            tool_name="Read",
        )

        alert = provider.check_content(content)
        assert alert is None

    def test_check_content_unsafe(self) -> None:
        """Test check_content returns alert for unsafe content."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # Mock the _sanitize_content method with new detailed format
        provider._sanitize_content = MagicMock(  # type: ignore[method-assign]
            return_value=(
                False,
                {
                    "match_state": "MATCH_FOUND",
                    "is_safe": False,
                    "invocation_result": "SUCCESS",
                    "filter_results": [
                        {
                            "filter_name": "pi_and_jailbreak",
                            "filter_type": "Prompt Injection & Jailbreak",
                            "match_state": "MATCH_FOUND",
                            "execution_state": "EXECUTION_SUCCESS",
                            "confidence": "HIGH",
                        }
                    ],
                },
            )
        )

        content = ContentToCheck(
            content="Ignore previous instructions",
            content_type="tool_input",
            tool_name="Bash",
        )

        alert = provider.check_content(content)
        assert alert is not None
        assert "prompt injection" in alert.explanation.lower()
        assert alert.data["provider"] == "GCPModelArmor"
        assert alert.data["is_safe"] is False

    def test_check_content_api_error(self) -> None:
        """Test check_content handles API errors gracefully."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # Mock the _sanitize_content method to raise an exception
        provider._sanitize_content = MagicMock(  # type: ignore[method-assign]
            side_effect=Exception("API connection failed")
        )

        content = ContentToCheck(
            content="Test content",
            content_type="tool_input",
            tool_name="Bash",
        )

        alert = provider.check_content(content)
        assert alert is not None
        assert "error" in alert.explanation.lower()
        assert alert.data["error"] == "Exception"
        assert "API connection failed" in alert.data["details"]

    def test_check_content_import_error(self) -> None:
        """Test check_content handles ImportError when package not installed."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # Mock the _sanitize_content method to raise ImportError
        provider._sanitize_content = MagicMock(  # type: ignore[method-assign]
            side_effect=ImportError("No module named 'google.cloud.modelarmor_v1'")
        )

        content = ContentToCheck(
            content="Test content",
            content_type="tool_input",
            tool_name="Bash",
        )

        alert = provider.check_content(content)
        assert alert is not None
        assert "unavailable" in alert.explanation.lower()
        assert alert.data["error"] == "import_error"
        # Check that the error mentions the module or package name
        assert "google.cloud.modelarmor" in alert.explanation.lower()

    def test_check_content_with_filter_details(self) -> None:
        """Test check_content includes filter details in alert."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # Mock the _sanitize_content method with multiple filter results in new format
        provider._sanitize_content = MagicMock(  # type: ignore[method-assign]
            return_value=(
                False,
                {
                    "match_state": "MATCH_FOUND",
                    "is_safe": False,
                    "invocation_result": "SUCCESS",
                    "filter_results": [
                        {
                            "filter_name": "pi_and_jailbreak",
                            "filter_type": "Prompt Injection & Jailbreak",
                            "match_state": "MATCH_FOUND",
                            "execution_state": "EXECUTION_SUCCESS",
                            "confidence": "MEDIUM_AND_ABOVE",
                        },
                        {
                            "filter_name": "malicious_uris",
                            "filter_type": "Malicious URI",
                            "match_state": "MATCH_FOUND",
                            "execution_state": "EXECUTION_SUCCESS",
                            "malicious_uris": ["http://evil.example.com"],
                        },
                    ],
                },
            )
        )

        content = ContentToCheck(
            content="Malicious content",
            content_type="tool_output",
            tool_name="Read",
        )

        alert = provider.check_content(content)
        assert alert is not None
        assert "prompt injection" in alert.explanation.lower()
        assert "malicious uri" in alert.explanation.lower()
        assert "evil.example.com" in alert.explanation
        assert alert.data["content_type"] == "tool_output"
        assert alert.data["tool_name"] == "Read"

    def test_check_content_with_rai_details(self) -> None:
        """Test check_content includes RAI filter details in alert."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # Mock with detailed RAI filter results
        provider._sanitize_content = MagicMock(  # type: ignore[method-assign]
            return_value=(
                False,
                {
                    "match_state": "MATCH_FOUND",
                    "is_safe": False,
                    "invocation_result": "SUCCESS",
                    "filter_results": [
                        {
                            "filter_name": "rai",
                            "filter_type": "Responsible AI",
                            "match_state": "MATCH_FOUND",
                            "execution_state": "EXECUTION_SUCCESS",
                            "detections": [
                                {"type": "hate_speech", "confidence": "HIGH"},
                                {"type": "harassment", "confidence": "MEDIUM_AND_ABOVE"},
                            ],
                        }
                    ],
                },
            )
        )

        content = ContentToCheck(
            content="Hateful content",
            content_type="tool_input",
            tool_name="Bash",
        )

        alert = provider.check_content(content)
        assert alert is not None
        assert "responsible ai" in alert.explanation.lower()
        assert "hate speech" in alert.explanation.lower()
        assert "harassment" in alert.explanation.lower()
        assert "HIGH" in alert.explanation

    def test_check_content_without_filter_results(self) -> None:
        """Test check_content provides informative message when filter_results is missing."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # Mock without filter_results (simulates API response without detailed filters)
        provider._sanitize_content = MagicMock(  # type: ignore[method-assign]
            return_value=(
                False,
                {
                    "match_state": "MATCH_FOUND",
                    "is_safe": False,
                    "invocation_result": "SUCCESS",
                },
            )
        )

        content = ContentToCheck(
            content="Some content",
            content_type="tool_input",
            tool_name="Bash",
        )

        alert = provider.check_content(content)
        assert alert is not None
        # Should provide informative fallback message
        assert "blocked content" in alert.explanation.lower()
        assert "content flagged" in alert.explanation.lower()
        assert "SUCCESS" in alert.explanation

    def test_check_content_with_numeric_match_state(self) -> None:
        """Test check_content handles numeric match_state values (from raw API)."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # Mock with numeric match_state (like what user saw: '2')
        provider._sanitize_content = MagicMock(  # type: ignore[method-assign]
            return_value=(
                False,
                {
                    "match_state": 2,  # Numeric value for MATCH_FOUND
                    "is_safe": False,
                },
            )
        )

        content = ContentToCheck(
            content="Some content",
            content_type="tool_input",
            tool_name="Bash",
        )

        alert = provider.check_content(content)
        assert alert is not None
        # Should convert numeric state to human-readable
        assert "blocked content" in alert.explanation.lower()
        assert "content flagged" in alert.explanation.lower()

    def test_check_content_with_error_message(self) -> None:
        """Test check_content includes error message when present."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # Mock with error message
        provider._sanitize_content = MagicMock(  # type: ignore[method-assign]
            return_value=(
                False,
                {
                    "match_state": "MATCH_FOUND",
                    "is_safe": False,
                    "error_message": "Template configuration issue",
                },
            )
        )

        content = ContentToCheck(
            content="Some content",
            content_type="tool_input",
            tool_name="Bash",
        )

        alert = provider.check_content(content)
        assert alert is not None
        assert "error" in alert.explanation.lower()
        assert "template configuration issue" in alert.explanation.lower()


class TestGCPModelArmorFormatMatchState:
    """Tests for _format_match_state method."""

    def test_format_match_state_string_match_found(self) -> None:
        """Test formatting string MATCH_FOUND."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )
        assert provider._format_match_state("MATCH_FOUND") == "content flagged"

    def test_format_match_state_string_no_match(self) -> None:
        """Test formatting string NO_MATCH."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )
        assert provider._format_match_state("NO_MATCH") == "content safe"

    def test_format_match_state_numeric_match_found(self) -> None:
        """Test formatting numeric value 2 (MATCH_FOUND)."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )
        assert provider._format_match_state(2) == "content flagged"

    def test_format_match_state_numeric_no_match(self) -> None:
        """Test formatting numeric value 1 (NO_MATCH)."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )
        assert provider._format_match_state(1) == "content safe"

    def test_format_match_state_enum_with_name(self) -> None:
        """Test formatting enum-like object with name attribute."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # Create mock enum-like object
        mock_enum = MagicMock()
        mock_enum.name = "MATCH_FOUND"

        assert provider._format_match_state(mock_enum) == "content flagged"

    def test_format_match_state_unknown_value(self) -> None:
        """Test formatting unknown value falls back to string."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )
        assert provider._format_match_state("UNKNOWN_STATE") == "UNKNOWN_STATE"


class TestGCPModelArmorClient:
    """Tests for GCP Model Armor client creation."""

    def test_get_client_import_error(self) -> None:
        """Test _get_client behavior is tested via check_content_import_error.

        We can't easily test the actual import error without uninstalling
        the package, so we rely on test_check_content_import_error which
        mocks _sanitize_content to raise ImportError.
        """
        # This test is a placeholder - the actual import error handling
        # is tested via test_check_content_import_error
        pass

    def test_client_cached(self) -> None:
        """Test that client is cached after first creation."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # Set a mock client
        mock_client = MagicMock()
        provider._client = mock_client

        # _get_client should return cached client
        assert provider._get_client() is mock_client

    def test_client_not_created_until_needed(self) -> None:
        """Test that client is not created during initialization."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # Client should be None until first use
        assert provider._client is None


class TestGCPModelArmorProviderRegistry:
    """Tests for GCPModelArmor in provider registry."""

    def test_gcpmodelarmor_in_registry(self) -> None:
        """Test GCPModelArmor is in provider registry."""
        from context_protector.guardrails import PROVIDER_REGISTRY

        assert "GCPModelArmor" in PROVIDER_REGISTRY

    def test_gcpmodelarmor_in_available_providers(self) -> None:
        """Test GCPModelArmor is in available providers."""
        from context_protector.guardrails import get_available_provider_names

        available = get_available_provider_names()
        assert "GCPModelArmor" in available


class TestGCPModelArmorConfig:
    """Tests for GCP Model Armor configuration."""

    def test_config_defaults(self) -> None:
        """Test default configuration values."""
        from context_protector.config import GCPModelArmorConfig

        config = GCPModelArmorConfig()
        assert config.enabled is False
        assert config.project_id is None
        assert config.location is None
        assert config.template_id is None

    def test_config_in_main_config(self) -> None:
        """Test GCP Model Armor config is included in main config."""
        from context_protector.config import Config

        config = Config()
        assert hasattr(config, "gcp_model_armor")
        assert config.gcp_model_armor.enabled is False

    def test_config_env_override(self) -> None:
        """Test environment variables override config."""
        from context_protector.config import Config, _apply_env_overrides

        config = Config()

        with patch.dict(
            "os.environ",
            {
                "CONTEXT_PROTECTOR_GCP_PROJECT_ID": "env-project",
                "CONTEXT_PROTECTOR_GCP_LOCATION": "us-west1",
                "CONTEXT_PROTECTOR_GCP_TEMPLATE_ID": "env-template",
            },
        ):
            config = _apply_env_overrides(config)
            assert config.gcp_model_armor.project_id == "env-project"
            assert config.gcp_model_armor.location == "us-west1"
            assert config.gcp_model_armor.template_id == "env-template"


class TestGCPModelArmorFormatDetectionExplanation:
    """Tests for _format_detection_explanation method covering all filter types."""

    def test_format_sdp_detection(self) -> None:
        """Test formatting Sensitive Data Protection detection."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        response_data = {
            "match_state": "MATCH_FOUND",
            "is_safe": False,
            "filter_results": [
                {
                    "filter_name": "sdp",
                    "filter_type": "Sensitive Data Protection",
                    "match_state": "MATCH_FOUND",
                    "execution_state": "EXECUTION_SUCCESS",
                    "findings": [
                        {"info_type": "CREDIT_CARD_NUMBER", "likelihood": "VERY_LIKELY"},
                        {"info_type": "EMAIL_ADDRESS", "likelihood": "LIKELY"},
                    ],
                }
            ],
        }

        explanation = provider._format_detection_explanation(response_data)
        assert "sensitive data" in explanation.lower()
        assert "CREDIT_CARD_NUMBER" in explanation
        assert "EMAIL_ADDRESS" in explanation

    def test_format_sdp_detection_without_findings(self) -> None:
        """Test formatting SDP detection when no specific findings provided but with messages."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # With new filtering, SDP needs findings or messages to be included
        response_data = {
            "match_state": "MATCH_FOUND",
            "is_safe": False,
            "filter_results": [
                {
                    "filter_name": "sdp",
                    "filter_type": "Sensitive Data Protection",
                    "match_state": "MATCH_FOUND",
                    "execution_state": "EXECUTION_SUCCESS",
                    # No findings, but has messages
                    "messages": [{"type": "WARNING", "text": "Sensitive data found"}],
                }
            ],
        }

        explanation = provider._format_detection_explanation(response_data)
        assert "sensitive data detected" in explanation.lower()

    def test_format_csam_detection(self) -> None:
        """Test formatting CSAM detection."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        response_data = {
            "match_state": "MATCH_FOUND",
            "is_safe": False,
            "filter_results": [
                {
                    "filter_name": "csam",
                    "filter_type": "CSAM",
                    "match_state": "MATCH_FOUND",
                    "execution_state": "EXECUTION_SUCCESS",
                    # No messages - CSAM should NOT be reported
                }
            ],
        }

        explanation = provider._format_detection_explanation(response_data)
        # CSAM should NOT be reported when there are no messages
        assert "csam" not in explanation.lower()
        assert "child safety" not in explanation.lower()
        # Should fall back to generic message
        assert "detected potentially harmful content" in explanation.lower()

    def test_format_csam_detection_with_messages(self) -> None:
        """Test formatting CSAM detection when it has actual messages."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        response_data = {
            "match_state": "MATCH_FOUND",
            "is_safe": False,
            "filter_results": [
                {
                    "filter_name": "csam",
                    "filter_type": "CSAM",
                    "match_state": "MATCH_FOUND",
                    "execution_state": "EXECUTION_SUCCESS",
                    "messages": [{"type": "WARNING", "text": "CSAM content detected in image"}],
                }
            ],
        }

        explanation = provider._format_detection_explanation(response_data)
        # CSAM SHOULD be reported when it has messages
        assert "csam" in explanation.lower()
        assert "child safety" in explanation.lower()

    def test_format_virus_detection_with_names(self) -> None:
        """Test formatting virus detection with virus names."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        response_data = {
            "match_state": "MATCH_FOUND",
            "is_safe": False,
            "filter_results": [
                {
                    "filter_name": "virus_scan",
                    "filter_type": "Virus Scan",
                    "match_state": "MATCH_FOUND",
                    "execution_state": "EXECUTION_SUCCESS",
                    "viruses": [
                        {"names": ["Trojan.GenericKD", "Win32.Malware"], "threat_type": "MALWARE"},
                    ],
                }
            ],
        }

        explanation = provider._format_detection_explanation(response_data)
        assert "malware" in explanation.lower()
        assert "Trojan.GenericKD" in explanation

    def test_format_virus_detection_without_names(self) -> None:
        """Test formatting virus detection without specific virus names but with messages."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # Now requires messages or viruses to be included (not just MATCH_FOUND)
        response_data = {
            "match_state": "MATCH_FOUND",
            "is_safe": False,
            "filter_results": [
                {
                    "filter_name": "virus_scan",
                    "filter_type": "Virus Scan",
                    "match_state": "MATCH_FOUND",
                    "execution_state": "EXECUTION_SUCCESS",
                    "messages": [{"type": "WARNING", "text": "Malware detected"}],
                }
            ],
        }

        explanation = provider._format_detection_explanation(response_data)
        assert "malware" in explanation.lower()

    def test_format_unknown_filter_type(self) -> None:
        """Test formatting unknown filter type falls back gracefully."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        response_data = {
            "match_state": "MATCH_FOUND",
            "is_safe": False,
            "filter_results": [
                {
                    "filter_name": "custom_filter",
                    "filter_type": "Custom Filter Type",
                    "match_state": "MATCH_FOUND",
                    "execution_state": "EXECUTION_SUCCESS",
                }
            ],
        }

        explanation = provider._format_detection_explanation(response_data)
        assert "Custom Filter Type" in explanation
        assert "triggered" in explanation

    def test_format_multiple_filter_matches(self) -> None:
        """Test formatting when multiple filters match."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        response_data = {
            "match_state": "MATCH_FOUND",
            "is_safe": False,
            "filter_results": [
                {
                    "filter_name": "rai",
                    "filter_type": "Responsible AI",
                    "match_state": "MATCH_FOUND",
                    "execution_state": "EXECUTION_SUCCESS",
                    "detections": [{"type": "hate_speech", "confidence": "HIGH"}],
                },
                {
                    "filter_name": "pi_and_jailbreak",
                    "filter_type": "Prompt Injection & Jailbreak",
                    "match_state": "MATCH_FOUND",
                    "execution_state": "EXECUTION_SUCCESS",
                    "confidence": "HIGH",
                },
            ],
        }

        explanation = provider._format_detection_explanation(response_data)
        assert "responsible ai" in explanation.lower()
        assert "prompt injection" in explanation.lower()
        assert ";" in explanation  # Multiple explanations joined with semicolon

    def test_format_no_match_found_filters_skipped(self) -> None:
        """Test that filters without MATCH_FOUND are skipped."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        response_data = {
            "match_state": "MATCH_FOUND",
            "is_safe": False,
            "filter_results": [
                {
                    "filter_name": "rai",
                    "filter_type": "Responsible AI",
                    "match_state": "NO_MATCH",  # Not matched
                    "execution_state": "EXECUTION_SUCCESS",
                },
                {
                    "filter_name": "pi_and_jailbreak",
                    "filter_type": "Prompt Injection & Jailbreak",
                    "match_state": "MATCH_FOUND",
                    "execution_state": "EXECUTION_SUCCESS",
                    "confidence": "MEDIUM",
                },
            ],
        }

        explanation = provider._format_detection_explanation(response_data)
        # Should NOT contain RAI since it didn't match
        assert "responsible ai" not in explanation.lower()
        # Should contain PI since it matched
        assert "prompt injection" in explanation.lower()

    def test_format_match_found_but_no_content_skipped(self) -> None:
        """Test that filters with MATCH_FOUND but no detection content are skipped.

        This prevents showing all categories when the API returns MATCH_FOUND for
        all configured filters even though only one actually triggered.
        """
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        response_data = {
            "match_state": "MATCH_FOUND",
            "is_safe": False,
            "filter_results": [
                {
                    # RAI with MATCH_FOUND but no detections or messages - should be skipped
                    "filter_name": "rai",
                    "filter_type": "Responsible AI",
                    "match_state": "MATCH_FOUND",
                    "execution_state": "EXECUTION_SUCCESS",
                },
                {
                    # SDP with MATCH_FOUND but no findings or messages - should be skipped
                    "filter_name": "sdp",
                    "filter_type": "Sensitive Data Protection",
                    "match_state": "MATCH_FOUND",
                    "execution_state": "EXECUTION_SUCCESS",
                },
                {
                    # Malicious URI with MATCH_FOUND but no URIs - should be skipped
                    "filter_name": "malicious_uris",
                    "filter_type": "Malicious URI",
                    "match_state": "MATCH_FOUND",
                    "execution_state": "EXECUTION_SUCCESS",
                },
                {
                    # PI with actual confidence - should be included
                    "filter_name": "pi_and_jailbreak",
                    "filter_type": "Prompt Injection & Jailbreak",
                    "match_state": "MATCH_FOUND",
                    "execution_state": "EXECUTION_SUCCESS",
                    "confidence": "HIGH",
                },
            ],
        }

        explanation = provider._format_detection_explanation(response_data)
        # Only PI should be included since it has actual detection content
        assert "prompt injection" in explanation.lower()
        assert "HIGH" in explanation
        # Others should be skipped (no detection content)
        assert "responsible ai" not in explanation.lower()
        assert "sensitive data" not in explanation.lower()
        assert "malicious uri" not in explanation.lower()

    def test_format_sdp_truncated_findings(self) -> None:
        """Test formatting SDP with many findings shows truncation indicator."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # More than 5 findings to trigger truncation message
        response_data = {
            "match_state": "MATCH_FOUND",
            "is_safe": False,
            "filter_results": [
                {
                    "filter_name": "sdp",
                    "filter_type": "Sensitive Data Protection",
                    "match_state": "MATCH_FOUND",
                    "execution_state": "EXECUTION_SUCCESS",
                    "findings": [
                        {"info_type": "CREDIT_CARD_NUMBER", "likelihood": "VERY_LIKELY"},
                        {"info_type": "EMAIL_ADDRESS", "likelihood": "LIKELY"},
                        {"info_type": "PHONE_NUMBER", "likelihood": "LIKELY"},
                        {"info_type": "PERSON_NAME", "likelihood": "POSSIBLE"},
                        {"info_type": "STREET_ADDRESS", "likelihood": "POSSIBLE"},
                        {"info_type": "SSN", "likelihood": "VERY_LIKELY"},
                        {"info_type": "PASSPORT", "likelihood": "LIKELY"},
                    ],
                }
            ],
        }

        explanation = provider._format_detection_explanation(response_data)
        assert "sensitive data" in explanation.lower()
        # First 5 should be shown
        assert "CREDIT_CARD_NUMBER" in explanation
        # Should indicate more items exist
        assert "+2 more" in explanation


class TestGCPModelArmorCheckContentEdgeCases:
    """Tests for edge cases in check_content method."""

    def test_check_content_empty_string(self) -> None:
        """Test check_content handles empty string."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        provider._sanitize_content = MagicMock(return_value=(True, {"is_safe": True}))  # type: ignore[method-assign]

        content = ContentToCheck(
            content="",
            content_type="tool_input",
            tool_name="Bash",
        )

        alert = provider.check_content(content)
        assert alert is None
        provider._sanitize_content.assert_called_once_with("")

    def test_check_content_with_malicious_uri_truncation(self) -> None:
        """Test that malicious URIs are truncated when more than 3."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        provider._sanitize_content = MagicMock(  # type: ignore[method-assign]
            return_value=(
                False,
                {
                    "match_state": "MATCH_FOUND",
                    "is_safe": False,
                    "filter_results": [
                        {
                            "filter_name": "malicious_uris",
                            "filter_type": "Malicious URI",
                            "match_state": "MATCH_FOUND",
                            "execution_state": "EXECUTION_SUCCESS",
                            "malicious_uris": [
                                "http://evil1.com",
                                "http://evil2.com",
                                "http://evil3.com",
                                "http://evil4.com",
                                "http://evil5.com",
                            ],
                        }
                    ],
                },
            )
        )

        content = ContentToCheck(
            content="Content with many malicious URIs",
            content_type="tool_output",
            tool_name="WebFetch",
        )

        alert = provider.check_content(content)
        assert alert is not None
        assert "evil1.com" in alert.explanation
        assert "evil2.com" in alert.explanation
        assert "evil3.com" in alert.explanation
        assert "+2 more" in alert.explanation

    def test_check_content_rai_without_detections(self) -> None:
        """Test RAI filter without specific detections but with messages."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # With new filtering, RAI needs messages or detections to be included
        provider._sanitize_content = MagicMock(  # type: ignore[method-assign]
            return_value=(
                False,
                {
                    "match_state": "MATCH_FOUND",
                    "is_safe": False,
                    "filter_results": [
                        {
                            "filter_name": "rai",
                            "filter_type": "Responsible AI",
                            "match_state": "MATCH_FOUND",
                            "execution_state": "EXECUTION_SUCCESS",
                            # No detections array, but has messages
                            "messages": [{"type": "WARNING", "text": "Content flagged"}],
                        }
                    ],
                },
            )
        )

        content = ContentToCheck(
            content="Some content",
            content_type="tool_input",
            tool_name="Bash",
        )

        alert = provider.check_content(content)
        assert alert is not None
        assert "responsible ai" in alert.explanation.lower()
        assert "violation detected" in alert.explanation.lower()

    def test_check_content_pi_without_confidence(self) -> None:
        """Test prompt injection filter without confidence level but with messages."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )

        # With new filtering, PI needs confidence or messages to be included
        provider._sanitize_content = MagicMock(  # type: ignore[method-assign]
            return_value=(
                False,
                {
                    "match_state": "MATCH_FOUND",
                    "is_safe": False,
                    "filter_results": [
                        {
                            "filter_name": "pi_and_jailbreak",
                            "filter_type": "Prompt Injection & Jailbreak",
                            "match_state": "MATCH_FOUND",
                            "execution_state": "EXECUTION_SUCCESS",
                            # No confidence field, but has messages
                            "messages": [{"type": "WARNING", "text": "Jailbreak attempt detected"}],
                        }
                    ],
                },
            )
        )

        content = ContentToCheck(
            content="Ignore previous instructions",
            content_type="tool_input",
            tool_name="Bash",
        )

        alert = provider.check_content(content)
        assert alert is not None
        assert "prompt injection" in alert.explanation.lower()
        # Should not have "(confidence)" since no confidence provided
        assert "confidence" not in alert.explanation.lower()


class TestGCPModelArmorFormatMatchStateAdditional:
    """Additional tests for _format_match_state edge cases."""

    def test_format_match_state_unspecified_string(self) -> None:
        """Test formatting MATCH_STATE_UNSPECIFIED string."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )
        assert provider._format_match_state("MATCH_STATE_UNSPECIFIED") == "unspecified"

    def test_format_match_state_zero(self) -> None:
        """Test formatting numeric value 0 (MATCH_STATE_UNSPECIFIED)."""
        provider = GCPModelArmorProvider(
            project_id="test-project",
            location="us-central1",
            template_id="test-template",
        )
        assert provider._format_match_state(0) == "unspecified"
