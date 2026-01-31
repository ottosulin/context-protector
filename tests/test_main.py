"""Tests for context_protector main module."""

from context_protector import HookHandler, __version__, main, process_hook


def test_version() -> None:
    """Test that version is set."""
    assert __version__ == "0.1.0"


def test_main_exists() -> None:
    """Test that main function exists."""
    assert callable(main)


def test_process_hook_exists() -> None:
    """Test that process_hook function exists."""
    assert callable(process_hook)


def test_hook_handler_exported() -> None:
    """Test that HookHandler is exported."""
    assert HookHandler is not None
