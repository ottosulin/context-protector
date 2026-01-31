"""Tests for guardrail_types module."""


from context_protector.guardrail_types import (
    ContentToCheck,
    GuardrailAlert,
    HookEventName,
    HookInput,
    HookOutput,
    PermissionDecision,
    PostToolUseDecision,
    PostToolUseOutput,
    PreToolUseOutput,
)


class TestHookInput:
    """Tests for HookInput dataclass."""

    def test_from_dict_pre_tool_use(self) -> None:
        """Test parsing PreToolUse hook input."""
        data = {
            "session_id": "test-session",
            "transcript_path": "/path/to/transcript",
            "cwd": "/home/user/project",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "tool_use_id": "toolu_123",
        }

        hook_input = HookInput.from_dict(data)

        assert hook_input.session_id == "test-session"
        assert hook_input.transcript_path == "/path/to/transcript"
        assert hook_input.cwd == "/home/user/project"
        assert hook_input.permission_mode == "default"
        assert hook_input.hook_event_name == HookEventName.PRE_TOOL_USE
        assert hook_input.tool_name == "Bash"
        assert hook_input.tool_input == {"command": "ls -la"}
        assert hook_input.tool_use_id == "toolu_123"
        assert hook_input.tool_result is None

    def test_from_dict_post_tool_use(self) -> None:
        """Test parsing PostToolUse hook input."""
        data = {
            "session_id": "test-session",
            "transcript_path": "/path/to/transcript",
            "cwd": "/home/user/project",
            "permission_mode": "default",
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/etc/passwd"},
            "tool_use_id": "toolu_456",
            "tool_result": "root:x:0:0:root:/root:/bin/bash",
        }

        hook_input = HookInput.from_dict(data)

        assert hook_input.hook_event_name == HookEventName.POST_TOOL_USE
        assert hook_input.tool_result == "root:x:0:0:root:/root:/bin/bash"

    def test_from_dict_stop(self) -> None:
        """Test parsing Stop hook input."""
        data = {
            "session_id": "test-session",
            "transcript_path": "/path/to/transcript",
            "cwd": "/home/user/project",
            "permission_mode": "default",
            "hook_event_name": "Stop",
        }

        hook_input = HookInput.from_dict(data)

        assert hook_input.hook_event_name == HookEventName.STOP
        assert hook_input.tool_name is None
        assert hook_input.tool_input is None

    def test_from_dict_sub_agent_stop(self) -> None:
        """Test parsing SubAgentStop hook input."""
        data = {
            "session_id": "test-session",
            "transcript_path": "/path/to/transcript",
            "cwd": "/home/user/project",
            "permission_mode": "default",
            "hook_event_name": "SubagentStop",
        }

        hook_input = HookInput.from_dict(data)

        assert hook_input.hook_event_name == HookEventName.SUB_AGENT_STOP

    def test_from_dict_with_defaults(self) -> None:
        """Test parsing with minimal data uses defaults."""
        data = {"hook_event_name": "PreToolUse"}

        hook_input = HookInput.from_dict(data)

        assert hook_input.session_id == ""
        assert hook_input.permission_mode == "default"


class TestHookOutput:
    """Tests for HookOutput dataclass."""

    def test_to_dict_minimal(self) -> None:
        """Test minimal output serialization."""
        output = HookOutput(continue_execution=True)

        result = output.to_dict()

        assert result == {"continue": True}

    def test_to_dict_with_stop_reason(self) -> None:
        """Test output with stop reason."""
        output = HookOutput(
            continue_execution=False,
            stop_reason="Security threat detected",
        )

        result = output.to_dict()

        assert result == {
            "continue": False,
            "stopReason": "Security threat detected",
        }

    def test_to_dict_with_system_message(self) -> None:
        """Test output with system message."""
        output = HookOutput(
            continue_execution=True,
            system_message="Warning: potentially malicious content",
        )

        result = output.to_dict()

        assert result == {
            "continue": True,
            "systemMessage": "Warning: potentially malicious content",
        }

    def test_to_dict_with_pre_tool_use_output(self) -> None:
        """Test output with PreToolUse specific data."""
        output = HookOutput(
            continue_execution=True,
            hook_specific_output=PreToolUseOutput(
                permission_decision=PermissionDecision.DENY,
                permission_decision_reason="Dangerous command",
            ),
        )

        result = output.to_dict()

        assert result == {
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "Dangerous command",
            },
        }


class TestPreToolUseOutput:
    """Tests for PreToolUseOutput dataclass."""

    def test_to_dict_allow(self) -> None:
        """Test allow decision serialization."""
        output = PreToolUseOutput(permission_decision=PermissionDecision.ALLOW)

        result = output.to_dict()

        assert result == {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
        }

    def test_to_dict_deny_with_reason(self) -> None:
        """Test deny decision with reason."""
        output = PreToolUseOutput(
            permission_decision=PermissionDecision.DENY,
            permission_decision_reason="Security risk",
        )

        result = output.to_dict()

        assert result == {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "Security risk",
        }

    def test_to_dict_with_updated_input(self) -> None:
        """Test output with updated input."""
        output = PreToolUseOutput(
            permission_decision=PermissionDecision.ALLOW,
            updated_input={"command": "ls"},
        )

        result = output.to_dict()

        assert result == {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": {"command": "ls"},
        }


class TestPostToolUseOutput:
    """Tests for PostToolUseOutput dataclass.

    PostToolUse hooks run AFTER the tool has completed. They CANNOT prevent
    tool execution or hide output. The 'decision: block' mechanism provides
    FEEDBACK to Claude, automatically prompting it with the reason.
    """

    def test_to_dict_no_decision(self) -> None:
        """Test output with no decision (normal continuation)."""
        output = PostToolUseOutput(decision=PostToolUseDecision.NONE)

        result = output.to_dict()

        # No decision field when NONE (undefined means continue normally)
        assert "decision" not in result
        assert result["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert "additionalContext" not in result["hookSpecificOutput"]

    def test_to_dict_block_decision(self) -> None:
        """Test output with block decision to prompt Claude."""
        output = PostToolUseOutput(
            decision=PostToolUseDecision.BLOCK,
            reason="Potential prompt injection detected",
        )

        result = output.to_dict()

        assert result["decision"] == "block"
        assert result["reason"] == "Potential prompt injection detected"
        assert result["hookSpecificOutput"]["hookEventName"] == "PostToolUse"

    def test_to_dict_with_additional_context(self) -> None:
        """Test output with additionalContext (warn mode)."""
        output = PostToolUseOutput(
            decision=PostToolUseDecision.NONE,
            additional_context="Warning: suspicious content detected",
        )

        result = output.to_dict()

        # No decision when NONE
        assert "decision" not in result
        assert result["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        additional_context = result["hookSpecificOutput"]["additionalContext"]
        assert additional_context == "Warning: suspicious content detected"

    def test_to_dict_block_without_reason(self) -> None:
        """Test block decision without reason still includes decision."""
        output = PostToolUseOutput(decision=PostToolUseDecision.BLOCK)

        result = output.to_dict()

        assert result["decision"] == "block"
        assert "reason" not in result
        assert result["hookSpecificOutput"]["hookEventName"] == "PostToolUse"


class TestHookOutputWithPostToolUse:
    """Tests for HookOutput with PostToolUseOutput."""

    def test_to_dict_with_post_tool_use_output(self) -> None:
        """Test HookOutput serializes PostToolUseOutput correctly."""
        output = HookOutput(
            post_tool_use_output=PostToolUseOutput(
                decision=PostToolUseDecision.BLOCK,
                reason="Security threat detected",
            )
        )

        result = output.to_dict()

        # PostToolUse format is different - decision/reason at top level
        assert result["decision"] == "block"
        assert result["reason"] == "Security threat detected"
        assert result["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        # Should NOT have the standard HookOutput fields
        assert "continue" not in result

    def test_to_dict_post_tool_use_takes_precedence(self) -> None:
        """Test that PostToolUseOutput takes precedence when set."""
        output = HookOutput(
            continue_execution=True,
            system_message="This should be ignored",
            post_tool_use_output=PostToolUseOutput(
                decision=PostToolUseDecision.NONE,
                additional_context="This should be used",
            )
        )

        result = output.to_dict()

        # PostToolUse format wins
        assert "continue" not in result
        assert "systemMessage" not in result
        assert result["hookSpecificOutput"]["additionalContext"] == "This should be used"


class TestGuardrailAlert:
    """Tests for GuardrailAlert dataclass."""

    def test_creation(self) -> None:
        """Test alert creation."""
        alert = GuardrailAlert(
            explanation="Prompt injection detected",
            data={"confidence": 0.95},
        )

        assert alert.explanation == "Prompt injection detected"
        assert alert.data == {"confidence": 0.95}

    def test_default_data(self) -> None:
        """Test alert with default empty data."""
        alert = GuardrailAlert(explanation="Test alert")

        assert alert.data == {}


class TestContentToCheck:
    """Tests for ContentToCheck dataclass."""

    def test_creation(self) -> None:
        """Test content creation."""
        content = ContentToCheck(
            content="Some text to check",
            content_type="tool_input",
            tool_name="Bash",
            context={"key": "value"},
        )

        assert content.content == "Some text to check"
        assert content.content_type == "tool_input"
        assert content.tool_name == "Bash"
        assert content.context == {"key": "value"}

    def test_default_values(self) -> None:
        """Test content with default values."""
        content = ContentToCheck(
            content="Text",
            content_type="test",
        )

        assert content.tool_name is None
        assert content.context == {}
