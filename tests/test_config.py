"""Tests for the config module."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from context_protector.config import (
    AprielGuardConfig,
    Config,
    GeneralConfig,
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
)


class TestDataclasses:
    """Test configuration dataclasses."""

    def test_general_config_defaults(self) -> None:
        """Test GeneralConfig default values."""
        config = GeneralConfig()
        assert config.mode == "default"
        assert config.provider == "LlamaFirewall"
        assert config.providers == []
        assert config.log_level == "WARNING"
        assert config.log_file is None

    def test_llama_firewall_config_defaults(self) -> None:
        """Test LlamaFirewallConfig default values."""
        config = LlamaFirewallConfig()
        assert config.enabled is True
        assert config.scanner_mode == "auto"

    def test_nemo_guardrails_config_defaults(self) -> None:
        """Test NeMoGuardrailsConfig default values."""
        config = NeMoGuardrailsConfig()
        assert config.enabled is True
        assert config.mode == "all"
        assert config.config_path is None
        assert config.openai_model == "gpt-4o-mini"
        assert config.ollama_model == "mistral:7b"
        assert config.ollama_base_url == "http://localhost:11434"
        assert config.perplexity_threshold == 89.79
        assert config.prefix_threshold == 1845.65

    def test_apriel_guard_config_defaults(self) -> None:
        """Test AprielGuardConfig default values."""
        config = AprielGuardConfig()
        assert config.enabled is False
        assert config.reasoning is False
        assert config.device == "auto"

    def test_config_defaults(self) -> None:
        """Test Config default values."""
        config = Config()
        assert isinstance(config.general, GeneralConfig)
        assert isinstance(config.llama_firewall, LlamaFirewallConfig)
        assert isinstance(config.nemo_guardrails, NeMoGuardrailsConfig)
        assert isinstance(config.apriel_guard, AprielGuardConfig)


class TestGetConfigPath:
    """Test get_config_path function."""

    def test_default_path(self) -> None:
        """Test default config path uses ~/.config."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("XDG_CONFIG_HOME", None)
            path = get_config_path()
            expected = Path.home() / ".config" / "context-protector" / "config.yaml"
            assert path == expected

    def test_xdg_config_home(self) -> None:
        """Test config path respects XDG_CONFIG_HOME."""
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": "/custom/config"}):
            path = get_config_path()
            expected = Path("/custom/config/context-protector/config.yaml")
            assert path == expected


class TestMergeDictIntoDataclass:
    """Test _merge_dict_into_dataclass function."""

    def test_merge_valid_keys(self) -> None:
        """Test merging valid keys into dataclass."""
        config = GeneralConfig()
        _merge_dict_into_dataclass(config, {"mode": "single", "provider": "NeMoGuardrails"})
        assert config.mode == "single"
        assert config.provider == "NeMoGuardrails"

    def test_merge_ignores_unknown_keys(self) -> None:
        """Test merging ignores unknown keys."""
        config = GeneralConfig()
        _merge_dict_into_dataclass(config, {"unknown_key": "value", "mode": "multi"})
        assert config.mode == "multi"
        assert not hasattr(config, "unknown_key")

    def test_merge_ignores_none_values(self) -> None:
        """Test merging ignores None values."""
        config = GeneralConfig()
        config.mode = "existing"
        _merge_dict_into_dataclass(config, {"mode": None})
        assert config.mode == "existing"


class TestLoadConfigFromFile:
    """Test _load_config_from_file function."""

    def test_load_nonexistent_file(self) -> None:
        """Test loading from nonexistent file returns empty dict."""
        result = _load_config_from_file(Path("/nonexistent/config.yaml"))
        assert result == {}

    def test_load_valid_yaml(self) -> None:
        """Test loading valid YAML file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("general:\n  mode: single\n")
            f.flush()
            try:
                result = _load_config_from_file(Path(f.name))
                assert result == {"general": {"mode": "single"}}
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

    def test_general_mode_override(self) -> None:
        """Test CONTEXT_PROTECTOR_MODE override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_MODE": "SINGLE"}):
            _apply_env_overrides(config)
            assert config.general.mode == "single"

    def test_general_provider_override(self) -> None:
        """Test CONTEXT_PROTECTOR_PROVIDER override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_PROVIDER": "NeMoGuardrails"}):
            _apply_env_overrides(config)
            assert config.general.provider == "NeMoGuardrails"

    def test_general_providers_override(self) -> None:
        """Test CONTEXT_PROTECTOR_PROVIDERS override."""
        config = Config()
        env = {"CONTEXT_PROTECTOR_PROVIDERS": "LlamaFirewall, NeMoGuardrails"}
        with patch.dict(os.environ, env):
            _apply_env_overrides(config)
            assert config.general.providers == ["LlamaFirewall", "NeMoGuardrails"]

    def test_log_level_override(self) -> None:
        """Test CONTEXT_PROTECTOR_LOG_LEVEL override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_LOG_LEVEL": "debug"}):
            _apply_env_overrides(config)
            assert config.general.log_level == "DEBUG"

    def test_log_file_override(self) -> None:
        """Test CONTEXT_PROTECTOR_LOG_FILE override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_LOG_FILE": "/var/log/protector.log"}):
            _apply_env_overrides(config)
            assert config.general.log_file == "/var/log/protector.log"

    def test_scanner_mode_override(self) -> None:
        """Test CONTEXT_PROTECTOR_SCANNER_MODE override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_SCANNER_MODE": "FULL"}):
            _apply_env_overrides(config)
            assert config.llama_firewall.scanner_mode == "full"

    def test_apriel_reasoning_override(self) -> None:
        """Test CONTEXT_PROTECTOR_APRIEL_REASONING override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_APRIEL_REASONING": "on"}):
            _apply_env_overrides(config)
            assert config.apriel_guard.reasoning is True

    def test_apriel_device_override(self) -> None:
        """Test CONTEXT_PROTECTOR_APRIEL_DEVICE override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_APRIEL_DEVICE": "CUDA"}):
            _apply_env_overrides(config)
            assert config.apriel_guard.device == "cuda"

    def test_nemo_mode_override(self) -> None:
        """Test CONTEXT_PROTECTOR_NEMO_MODE override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_NEMO_MODE": "INJECTION"}):
            _apply_env_overrides(config)
            assert config.nemo_guardrails.mode == "injection"

    def test_nemo_config_path_override(self) -> None:
        """Test CONTEXT_PROTECTOR_NEMO_CONFIG_PATH override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_NEMO_CONFIG_PATH": "/custom/nemo"}):
            _apply_env_overrides(config)
            assert config.nemo_guardrails.config_path == "/custom/nemo"

    def test_nemo_openai_model_override(self) -> None:
        """Test CONTEXT_PROTECTOR_NEMO_OPENAI_MODEL override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_NEMO_OPENAI_MODEL": "gpt-4"}):
            _apply_env_overrides(config)
            assert config.nemo_guardrails.openai_model == "gpt-4"

    def test_nemo_perplexity_threshold_override(self) -> None:
        """Test CONTEXT_PROTECTOR_NEMO_PERPLEXITY_THRESHOLD override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_NEMO_PERPLEXITY_THRESHOLD": "100.5"}):
            _apply_env_overrides(config)
            assert config.nemo_guardrails.perplexity_threshold == 100.5

    def test_nemo_perplexity_threshold_invalid(self) -> None:
        """Test invalid CONTEXT_PROTECTOR_NEMO_PERPLEXITY_THRESHOLD is ignored."""
        config = Config()
        original = config.nemo_guardrails.perplexity_threshold
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_NEMO_PERPLEXITY_THRESHOLD": "invalid"}):
            _apply_env_overrides(config)
            assert config.nemo_guardrails.perplexity_threshold == original

    def test_nemo_prefix_threshold_override(self) -> None:
        """Test CONTEXT_PROTECTOR_NEMO_PREFIX_THRESHOLD override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_NEMO_PREFIX_THRESHOLD": "2000.0"}):
            _apply_env_overrides(config)
            assert config.nemo_guardrails.prefix_threshold == 2000.0

    def test_nemo_ollama_model_override(self) -> None:
        """Test CONTEXT_PROTECTOR_NEMO_OLLAMA_MODEL override."""
        config = Config()
        with patch.dict(os.environ, {"CONTEXT_PROTECTOR_NEMO_OLLAMA_MODEL": "phi3"}):
            _apply_env_overrides(config)
            assert config.nemo_guardrails.ollama_model == "phi3"

    def test_nemo_ollama_base_url_override(self) -> None:
        """Test CONTEXT_PROTECTOR_NEMO_OLLAMA_BASE_URL override."""
        config = Config()
        with patch.dict(
            os.environ, {"CONTEXT_PROTECTOR_NEMO_OLLAMA_BASE_URL": "http://remote:11434"}
        ):
            _apply_env_overrides(config)
            assert config.nemo_guardrails.ollama_base_url == "http://remote:11434"


class TestLoadConfig:
    """Test load_config function."""

    def test_load_config_no_file(self) -> None:
        """Test loading config when no file exists."""
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"XDG_CONFIG_HOME": tmpdir}, clear=True),
        ):
            config = load_config()
            # Should have defaults
            assert config.general.mode == "default"
            assert config.llama_firewall.scanner_mode == "auto"

    def test_load_config_with_file(self) -> None:
        """Test loading config from file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "context-protector"
            config_dir.mkdir(parents=True)
            config_file = config_dir / "config.yaml"
            config_file.write_text("general:\n  mode: multi\n  provider: AprielGuard\n")

            with patch.dict(os.environ, {"XDG_CONFIG_HOME": tmpdir}, clear=True):
                config = load_config()
                assert config.general.mode == "multi"
                assert config.general.provider == "AprielGuard"

    def test_load_config_env_overrides_file(self) -> None:
        """Test environment variables override file values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "context-protector"
            config_dir.mkdir(parents=True)
            config_file = config_dir / "config.yaml"
            config_file.write_text("general:\n  mode: multi\n")

            env = {
                "XDG_CONFIG_HOME": tmpdir,
                "CONTEXT_PROTECTOR_MODE": "single",
            }
            with patch.dict(os.environ, env, clear=True):
                config = load_config()
                # Env var should override file
                assert config.general.mode == "single"


class TestSaveConfig:
    """Test save_config function."""

    def test_save_config_creates_file(self) -> None:
        """Test save_config creates config file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "subdir" / "config.yaml"
            config = Config()
            config.general.mode = "single"

            save_config(config, path)

            assert path.exists()
            content = path.read_text()
            assert "mode: single" in content

    def test_save_config_default_path(self) -> None:
        """Test save_config uses default path."""
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
            assert "# Claude Context Protector Configuration" in content
            assert "# Environment variables take precedence" in content
            assert "scanner_mode: auto" in content


class TestInitConfig:
    """Test init_config function."""

    def test_init_config_creates_file(self) -> None:
        """Test init_config creates config file."""
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"XDG_CONFIG_HOME": tmpdir}),
        ):
            path = init_config()

            assert path.exists()
            assert "config.yaml" in str(path)

    def test_init_config_raises_if_exists(self) -> None:
        """Test init_config raises FileExistsError if file exists."""
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
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "context-protector"
            config_dir.mkdir(parents=True)
            config_file = config_dir / "config.yaml"
            config_file.write_text("existing: config\n")

            with patch.dict(os.environ, {"XDG_CONFIG_HOME": tmpdir}):
                path = init_config(force=True)

                content = path.read_text()
                # Should have template content, not original
                assert "# Claude Context Protector Configuration" in content
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

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "context-protector"
            config_dir.mkdir(parents=True)
            config_file = config_dir / "config.yaml"
            config_file.write_text("general:\n  mode: multi\n")

            with patch.dict(os.environ, {"XDG_CONFIG_HOME": tmpdir}, clear=True):
                reset_config()
                config = get_config()
                assert config.general.mode == "multi"

        # Clean up
        reset_config()
