#!/usr/bin/env python3
"""Smoke tests for --check CLI mode.

Run this script to verify the --check mode works end-to-end.
Uses the actual CLI interface, not unit test mocks.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
SRC_DIR = PROJECT_ROOT / "src"

def run_check(input_data: dict) -> dict:
    """Run context-protector --check with given input."""
    env = {"PYTHONPATH": str(SRC_DIR)}
    result = subprocess.run(
        [sys.executable, "-m", "context_protector", "--check"],
        input=json.dumps(input_data),
        capture_output=True,
        text=True,
        env={**os.environ, **env},
        cwd=PROJECT_ROOT,
    )
    
    if result.returncode != 0:
        print(f"STDERR: {result.stderr}")
        raise RuntimeError(f"Command failed with code {result.returncode}")
    
    return json.loads(result.stdout)


def test_safe_content():
    """Test that safe content passes."""
    print("Testing safe content...", end=" ")
    
    result = run_check({
        "content": "Hello, please help me write a function to calculate fibonacci numbers.",
        "type": "tool_input",
        "tool_name": "Write",
    })
    
    assert result["safe"] is True, f"Expected safe=True, got {result}"
    assert result["alert"] is None, f"Expected no alert, got {result['alert']}"
    
    print("PASSED")


def test_empty_content():
    """Test that empty content is safe."""
    print("Testing empty content...", end=" ")
    
    result = run_check({
        "content": "",
        "type": "tool_input",
    })
    
    assert result["safe"] is True
    print("PASSED")


def test_json_output_structure():
    """Test that output has correct JSON structure."""
    print("Testing JSON output structure...", end=" ")
    
    result = run_check({
        "content": "test content",
        "type": "tool_output",
    })
    
    assert "safe" in result, "Missing 'safe' key"
    assert "alert" in result, "Missing 'alert' key"
    assert isinstance(result["safe"], bool), "'safe' should be bool"
    
    print("PASSED")


def test_tool_output_type():
    """Test tool_output content type."""
    print("Testing tool_output type...", end=" ")
    
    result = run_check({
        "content": "File contents: def hello():\n    pass",
        "type": "tool_output",
        "tool_name": "Read",
    })
    
    assert result["safe"] is True
    print("PASSED")


def test_large_content():
    """Test handling of large content."""
    print("Testing large content (10KB)...", end=" ")
    
    large_content = "x" * 10000
    result = run_check({
        "content": large_content,
        "type": "tool_input",
    })
    
    assert "safe" in result
    print("PASSED")


def test_unicode_content():
    """Test handling of unicode content."""
    print("Testing unicode content...", end=" ")
    
    result = run_check({
        "content": "Hello 世界 🌍 مرحبا Привет",
        "type": "tool_input",
    })
    
    assert result["safe"] is True
    print("PASSED")


def test_newlines_in_content():
    """Test content with various newlines."""
    print("Testing newlines in content...", end=" ")
    
    result = run_check({
        "content": "Line 1\nLine 2\r\nLine 3\rLine 4",
        "type": "tool_input",
    })
    
    assert result["safe"] is True
    print("PASSED")


def test_json_special_chars():
    """Test content with JSON special characters."""
    print("Testing JSON special characters...", end=" ")
    
    result = run_check({
        "content": 'Quote: "hello" and backslash: \\ and tab: \t',
        "type": "tool_input",
    })
    
    assert result["safe"] is True
    print("PASSED")


def test_help_flag():
    """Test --help flag shows check mode."""
    print("Testing --help shows --check...", end=" ")
    
    result = subprocess.run(
        [sys.executable, "-m", "context_protector", "--help"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(SRC_DIR)},
        cwd=PROJECT_ROOT,
    )
    
    assert "--check" in result.stdout, "--check not in help output"
    assert "OpenCode" in result.stdout, "OpenCode not mentioned in help"
    
    print("PASSED")


def test_version_flag():
    """Test --version flag works."""
    print("Testing --version...", end=" ")
    
    result = subprocess.run(
        [sys.executable, "-m", "context_protector", "--version"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(SRC_DIR)},
        cwd=PROJECT_ROOT,
    )
    
    assert "0.1.0" in result.stdout or "context-protector" in result.stdout
    print("PASSED")


def main():
    print("=" * 60)
    print("Context Protector --check Mode Smoke Tests")
    print("=" * 60)
    print()
    
    tests = [
        test_safe_content,
        test_empty_content,
        test_json_output_structure,
        test_tool_output_type,
        test_large_content,
        test_unicode_content,
        test_newlines_in_content,
        test_json_special_chars,
        test_help_flag,
        test_version_flag,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"FAILED: {e}")
            failed += 1
    
    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
