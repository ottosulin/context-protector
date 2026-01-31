"""Integration tests for the hook CLI."""

import json
import subprocess
import sys


class TestHookCLIOutput:
    """Tests for the actual CLI JSON output format."""

    def test_stop_event_json_output(self) -> None:
        """Test that Stop event produces correct JSON output."""
        input_data = json.dumps({
            "session_id": "test",
            "transcript_path": "/tmp/test",
            "cwd": "/tmp",
            "permission_mode": "default",
            "hook_event_name": "Stop",
        })

        # Run the hook directly via Python to test the exact output
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                """
import sys
import json
sys.path.insert(0, 'src')
from context_protector.guardrail_types import HookInput
from context_protector.hook_handler import HookHandler
from context_protector.providers.mock_provider import NeverAlertProvider

data = json.loads(sys.stdin.read())
hook_input = HookInput.from_dict(data)
handler = HookHandler(provider=NeverAlertProvider())
output = handler.handle(hook_input)
print(json.dumps(output.to_dict()))
""",
            ],
            input=input_data,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Hook failed: {result.stderr}"

        output = json.loads(result.stdout.strip())

        # Stop events should NOT have hookSpecificOutput
        assert output == {"continue": True}
        assert "hookSpecificOutput" not in output

    def test_subagent_stop_event_json_output(self) -> None:
        """Test that SubAgentStop event produces correct JSON output."""
        input_data = json.dumps({
            "session_id": "test",
            "transcript_path": "/tmp/test",
            "cwd": "/tmp",
            "permission_mode": "default",
            "hook_event_name": "SubagentStop",
        })

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                """
import sys
import json
sys.path.insert(0, 'src')
from context_protector.guardrail_types import HookInput
from context_protector.hook_handler import HookHandler
from context_protector.providers.mock_provider import NeverAlertProvider

data = json.loads(sys.stdin.read())
hook_input = HookInput.from_dict(data)
handler = HookHandler(provider=NeverAlertProvider())
output = handler.handle(hook_input)
print(json.dumps(output.to_dict()))
""",
            ],
            input=input_data,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Hook failed: {result.stderr}"

        output = json.loads(result.stdout.strip())

        # SubAgentStop events should NOT have hookSpecificOutput
        assert output == {"continue": True}
        assert "hookSpecificOutput" not in output

    def test_pre_tool_use_json_output(self) -> None:
        """Test that PreToolUse event produces correct JSON output."""
        input_data = json.dumps({
            "session_id": "test",
            "transcript_path": "/tmp/test",
            "cwd": "/tmp",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_use_id": "test123",
        })

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                """
import sys
import json
sys.path.insert(0, 'src')
from context_protector.guardrail_types import HookInput
from context_protector.hook_handler import HookHandler
from context_protector.providers.mock_provider import NeverAlertProvider

data = json.loads(sys.stdin.read())
hook_input = HookInput.from_dict(data)
handler = HookHandler(provider=NeverAlertProvider())
output = handler.handle(hook_input)
print(json.dumps(output.to_dict()))
""",
            ],
            input=input_data,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Hook failed: {result.stderr}"

        output = json.loads(result.stdout.strip())

        # PreToolUse should have hookSpecificOutput with proper structure
        assert output["continue"] is True
        assert "hookSpecificOutput" in output
        assert output["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
        assert output["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_post_tool_use_no_alert_json_output(self) -> None:
        """Test that PostToolUse without alert produces correct JSON output.

        PostToolUse uses the new decision control format:
        - Always includes hookSpecificOutput with hookEventName
        - No decision field when no alert (means allow continuation)
        """
        input_data = json.dumps({
            "session_id": "test",
            "transcript_path": "/tmp/test",
            "cwd": "/tmp",
            "permission_mode": "default",
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/test.txt"},
            "tool_use_id": "test123",
            "tool_result": "file contents here",
        })

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                """
import sys
import json
sys.path.insert(0, 'src')
from context_protector.guardrail_types import HookInput
from context_protector.hook_handler import HookHandler
from context_protector.providers.mock_provider import NeverAlertProvider

data = json.loads(sys.stdin.read())
hook_input = HookInput.from_dict(data)
handler = HookHandler(provider=NeverAlertProvider())
output = handler.handle(hook_input)
print(json.dumps(output.to_dict()))
""",
            ],
            input=input_data,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Hook failed: {result.stderr}"

        output = json.loads(result.stdout.strip())

        # PostToolUse uses the new format with hookSpecificOutput
        assert "hookSpecificOutput" in output
        assert output["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        # No decision field when no alert (undefined means continue normally)
        assert "decision" not in output
        # No additionalContext when no alert
        assert "additionalContext" not in output.get("hookSpecificOutput", {})
