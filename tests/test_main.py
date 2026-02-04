"""Tests for context_protector main module."""

from context_protector import HookHandler, __version__, main, process_hook


def test_version() -> None:
    """Test that version is set and follows semver format."""
    # Check version is a non-empty string matching semver pattern
    assert isinstance(__version__, str)
    assert len(__version__) > 0
    parts = __version__.split(".")
    assert len(parts) >= 2, f"Version {__version__} should have at least major.minor"
    assert all(p.isdigit() for p in parts[:2]), f"Version {__version__} should be numeric"


def test_main_exists() -> None:
    """Test that main function exists."""
    assert callable(main)


def test_process_hook_exists() -> None:
    """Test that process_hook function exists."""
    assert callable(process_hook)


def test_hook_handler_exported() -> None:
    """Test that HookHandler is exported."""
    assert HookHandler is not None
