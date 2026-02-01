"""Tests for the config module."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from context_protector.config import (
    Config,
    GCPModelArmorConfig,
    LlamaFirewallConfig,
    NeMoGuardrailsConfig,
    _apply_env_overrides,
    _load_config_from_file,
    _merge_dict_into_dataclass,
    get_config,
    get_config_path,
    init_config,
    load_config,
    reset_config,
    save_config,
    save_default_config,
    set_config_path,
)


class TestDataclasses:
    """Test configuration dataclasses."""

    def test_llama_firewall_config_defaults(self) -> None:
        """Test LlamaFirewallConfig default values."""
        config = LlamaFirewallConfig()
        assert config.scanner_mode == "auto"

    def test_nemo_guardrails_config_defaults(self) -> None:
        """Test NeMoGuardrailsConfig default values."""
        config = NeMoGuardrailsConfig()
        assert config.mode == "all"
        assert config.ollama_model == "mistral:7b"
        assert config.ollama_base_url == "http://localhost:11434"

    def test_gcp_model_armor_config_defaults(self) -> None:
        """Test GCPModelArmorConfig default values."""
        config = GCPModelArmorConfig()
        assert config.project_id is None
        assert config.location is None
        assert config.template_id is None

    def test_config_defaults(self) -> None:
        """Test Config default values."""
        config = Config()
        assert config.provider == "LlamaFirewall"
        assert config.response_mode == "warn"
        assert config.log_level == "WARNING"
        assert config.log_file is None
        assert isinstance(config.llama_firewall, LlamaFirewallConfig)
        assert isinstance(config.nemo_guardrails, NeMoGuardrailsConfig)
        assert isinstance(config.gcp_model_armor, GCPModelArmorConfig)


class TestGetConfigPath:
    """Test get_config_path function."""

    def test_default_path(self) -> None:
        """Test default config path uses ~/.config."""
        # Reset any override from previous tests
        set_config_path(None)
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("XDG_CONFIG_HOME", None)
            path = get_config_path()
            expected = Path.home() / ".config" / "context-protector" / "config.yaml"
            assert path == expected

    def test_xdg_config_home(self) -> None:
        """Test config path respects XDG_CONFIG_HOME."""
        set_config_path(None)
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": "/custom/config"}):
            path = get_config_path()
            expected = Path("/custom/config/context-protector/config.yaml")
            assert path == expected

    def test_set_config_path_override(self) -> None:
        """Test set_config_path overrides default path."""
        custom_path = Path("/custom/path/config.yaml")
        set_config_path(custom_path)
        try:
            path = get_config_path()
            assert path == custom_path
        finally:
            set_config_path(None)


class TestMergeDictIntoDataclass:
    """Test _merge_dict_into_dataclass function."""

    def test_merge_valid_keys(self) -> None:
        """Test merging valid keys into dataclass."""
        config = Config()
        _merge_dict_into_dataclass(config, {"provider": "NeMoGuardrails", "response_mode": "block"})
        assert config.provider == "NeMoGuardrails"
        assert config.response_mode == "block"

    def test_merge_ignores_unknown_keys(self) -> None:
        """Test merging ignores unknown keys."""
        config = Config()
        _merge_dict_into_dataclass(config, {"unknown_key": "value", "provider": "Mock"})
        assert config.provider == "Mock"
        assert not hasattr(config, "unknown_key")

    def test_merge_ignores_none_values(self) -> None:
        """Test merging ignores None values."""
        config = Config()
        config.provider = "existing"
        _merge_dict_into_dataclass(config, {"provider": None})
        assert config.provider == "existing"


class TestLoadConfigFromFile:
    """Test _load_config_from_file function."""

    def test_load_nonexistent_file(self) -> None:
        """Test loading from nonexistent file returns empty dict."""
        result = _load_config_from_file(Path("/nonexistent/config.yaml"))
        assert result == {}

    def test_load_valid_yaml(self) -> None:
        """Test loading valid YAML file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("provider: NeMoGuardrails\nresponse_mode: block\n")
            f.flush()
            try:
                result = _load_config_from_file(Path(f.name))
                assert result == {"provider": "NeMoGuardrails", "response_mode": "block"}
            finally:
                os.unlink(f.name)

    def test_load_invalid_yaml(self) -> None:
        """Test loading invalid YAML returns empty dict."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: syntax:\n  - broken")
            f.flush()
            try:
                result = _load_config_from_file(Path(f.name))
                assert result == {}
            finally:
                os.unlink(f.name)

    def test_load_non_dict_yaml(self) -> None:
        """Test loading non-dict YAML returns empty dict."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("- item1\n- item2\n")
            f.flush()
            try:
                result = _load_config_from_file(Path(f.name))
                assert result == {}
            finally:
                os.unlink(f.name)


class TestApplyEnvOverrides:
    """Test _apply_env_overrides function."""

    def test_provider_override(self) -> None:
        """Test CONTEXT_PROTECTOR_PROVIDER override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_PROVIDER": "NeMoGuardrails"}):
            _apply_env_overrides(config)
            assert config.provider == "NeMoGuardrails"

    def test_response_mode_override(self) -> None:
        """Test CONTEXT_PROTECTOR_RESPONSE_MODE override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_RESPONSE_MODE": "BLOCK"}):
            _apply_env_overrides(config)
            assert config.response_mode == "block"

    def test_log_level_override(self) -> None:
        """Test CONTEXT_PROTECTOR_LOG_LEVEL override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_LOG_LEVEL": "debug"}):
            _apply_env_overrides(config)
            assert config.log_level == "DEBUG"

    def test_log_file_override(self) -> None:
        """Test CONTEXT_PROTECTOR_LOG_FILE override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_LOG_FILE": "/var/log/protector.log"}):
            _apply_env_overrides(config)
            assert config.log_file == "/var/log/protector.log"

    def test_scanner_mode_override(self) -> None:
        """Test CONTEXT_PROTECTOR_SCANNER_MODE override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_SCANNER_MODE": "FULL"}):
            _apply_env_overrides(config)
            assert config.llama_firewall.scanner_mode == "full"

    def test_nemo_mode_override(self) -> None:
        """Test CONTEXT_PROTECTOR_NEMO_MODE override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_NEMO_MODE": "INJECTION"}):
            _apply_env_overrides(config)
            assert config.nemo_guardrails.mode == "injection"

    def test_nemo_ollama_model_override(self) -> None:
        """Test CONTEXT_PROTECTOR_OLLAMA_MODEL override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_OLLAMA_MODEL": "phi3"}):
            _apply_env_overrides(config)
            assert config.nemo_guardrails.ollama_model == "phi3"

    def test_nemo_ollama_base_url_override(self) -> None:
        """Test CONTEXT_PROTECTOR_OLLAMA_BASE_URL override."""
        config = Config()
        with patch.dict(
            os.environ, {"CONTEXT_PROTECTOR_OLLAMA_BASE_URL": "http://remote:11434"}
        ):
            _apply_env_overrides(config)
            assert config.nemo_guardrails.ollama_base_url == "http://remote:11434"

    def test_gcp_project_id_override(self) -> None:
        """Test CONTEXT_PROTECTOR_GCP_PROJECT_ID override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_GCP_PROJECT_ID": "my-project"}):
            _apply_env_overrides(config)
            assert config.gcp_model_armor.project_id == "my-project"

    def test_gcp_location_override(self) -> None:
        """Test CONTEXT_PROTECTOR_GCP_LOCATION override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_GCP_LOCATION": "us-central1"}):
            _apply_env_overrides(config)
            assert config.gcp_model_armor.location == "us-central1"

    def test_gcp_template_id_override(self) -> None:
        """Test CONTEXT_PROTECTOR_GCP_TEMPLATE_ID override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_GCP_TEMPLATE_ID": "my-template"}):
            _apply_env_overrides(config)
            assert config.gcp_model_armor.template_id == "my-template"


class TestLoadConfig:
    """Test load_config function."""

    def test_load_config_no_file(self) -> None:
        """Test loading config when no file exists."""
        set_config_path(None)
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"XDG_CONFIG_HOME": tmpdir}, clear=True),
        ):
            config = load_config()
            # Should have defaults
            assert config.provider == "LlamaFirewall"
            assert config.llama_firewall.scanner_mode == "auto"

    def test_load_config_with_file(self) -> None:
        """Test loading config from file."""
        set_config_path(None)
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "context-protector"
            config_dir.mkdir(parents=True)
            config_file = config_dir / "config.yaml"
            config_file.write_text("provider: NeMoGuardrails\nresponse_mode: block\n")

            with patch.dict(os.environ, {"XDG_CONFIG_HOME": tmpdir}, clear=True):
                config = load_config()
                assert config.provider == "NeMoGuardrails"
                assert config.response_mode == "block"

    def test_load_config_env_overrides_file(self) -> None:
        """Test environment variables override file values."""
        set_config_path(None)
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "context-protector"
            config_dir.mkdir(parents=True)
            config_file = config_dir / "config.yaml"
            config_file.write_text("provider: NeMoGuardrails\n")

            env = {
                "XDG_CONFIG_HOME": tmpdir,
                "CONTEXT_PROTECTOR_PROVIDER": "LlamaFirewall",
            }
            with patch.dict(os.environ, env, clear=True):
                config = load_config()
                # Env var should override file
                assert config.provider == "LlamaFirewall"

    def test_load_config_nested_settings(self) -> None:
        """Test loading nested provider settings from file."""
        set_config_path(None)
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "context-protector"
            config_dir.mkdir(parents=True)
            config_file = config_dir / "config.yaml"
            config_file.write_text(
                "llama_firewall:\n  scanner_mode: full\nnemo_guardrails:\n  mode: local\n"
            )

            with patch.dict(os.environ, {"XDG_CONFIG_HOME": tmpdir}, clear=True):
                config = load_config()
                assert config.llama_firewall.scanner_mode == "full"
                assert config.nemo_guardrails.mode == "local"


class TestSaveConfig:
    """Test save_config function."""

    def test_save_config_creates_file(self) -> None:
        """Test save_config creates config file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "subdir" / "config.yaml"
            config = Config()
            config.provider = "NeMoGuardrails"

            save_config(config, path)

            assert path.exists()
            content = path.read_text()
            assert "provider: NeMoGuardrails" in content

    def test_save_config_default_path(self) -> None:
        """Test save_config uses default path."""
        set_config_path(None)
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"XDG_CONFIG_HOME": tmpdir}),
        ):
            config = Config()
            save_config(config)

            expected_path = Path(tmpdir) / "context-protector" / "config.yaml"
            assert expected_path.exists()


class TestSaveDefaultConfig:
    """Test save_default_config function."""

    def test_save_default_config_creates_template(self) -> None:
        """Test save_default_config creates template with comments."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.yaml"
            save_default_config(path)

            content = path.read_text()
            assert "# Context Protector Configuration" in content
            assert "provider: LlamaFirewall" in content
            assert "scanner_mode: auto" in content


class TestInitConfig:
    """Test init_config function."""

    def test_init_config_creates_file(self) -> None:
        """Test init_config creates config file."""
        set_config_path(None)
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"XDG_CONFIG_HOME": tmpdir}),
        ):
            path = init_config()

            assert path.exists()
            assert "config.yaml" in str(path)

    def test_init_config_raises_if_exists(self) -> None:
        """Test init_config raises FileExistsError if file exists."""
        set_config_path(None)
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "context-protector"
            config_dir.mkdir(parents=True)
            config_file = config_dir / "config.yaml"
            config_file.write_text("existing: config\n")

            with (
                patch.dict(os.environ, {"XDG_CONFIG_HOME": tmpdir}),
                pytest.raises(FileExistsError),
            ):
                init_config()

    def test_init_config_force_overwrites(self) -> None:
        """Test init_config with force=True overwrites existing."""
        set_config_path(None)
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "context-protector"
            config_dir.mkdir(parents=True)
            config_file = config_dir / "config.yaml"
            config_file.write_text("existing: config\n")

            with patch.dict(os.environ, {"XDG_CONFIG_HOME": tmpdir}):
                path = init_config(force=True)

                content = path.read_text()
                # Should have template content, not original
                assert "# Context Protector Configuration" in content
                assert "existing: config" not in content


class TestGetConfigAndReset:
    """Test get_config and reset_config functions."""

    def test_get_config_returns_same_instance(self) -> None:
        """Test get_config returns cached instance."""
        reset_config()  # Ensure clean state

        config1 = get_config()
        config2 = get_config()

        assert config1 is config2

    def test_reset_config_clears_cache(self) -> None:
        """Test reset_config forces reload."""
        reset_config()  # Ensure clean state

        config1 = get_config()
        reset_config()
        config2 = get_config()

        # Different instances
        assert config1 is not config2

    def test_get_config_loads_from_file(self) -> None:
        """Test get_config loads from file."""
        reset_config()
        set_config_path(None)

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "context-protector"
            config_dir.mkdir(parents=True)
            config_file = config_dir / "config.yaml"
            config_file.write_text("provider: NeMoGuardrails\n")

            with patch.dict(os.environ, {"XDG_CONFIG_HOME": tmpdir}, clear=True):
                reset_config()
                config = get_config()
                assert config.provider == "NeMoGuardrails"

        # Clean up
        reset_config()
