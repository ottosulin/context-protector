"""Core types for context-protector.

Defines data classes for hook inputs, outputs, and guardrail alerts.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class HookEventName(str, Enum):
    """Hook event names supported by Claude Code."""

    PRE_TOOL_USE = "PreToolUse"
    POST_TOOL_USE = "PostToolUse"
    STOP = "Stop"
    SUB_AGENT_STOP = "SubagentStop"


class PermissionDecision(str, Enum):
    """Permission decisions for PreToolUse hooks."""

    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


class PostToolUseDecision(str, Enum):
    """Decision options for PostToolUse hooks.

    Unlike PreToolUse, PostToolUse runs AFTER the tool has completed.
    The 'block' decision provides FEEDBACK to Claude (prompts with reason),
    it does NOT prevent tool execution or hide output.
    """

    NONE = ""  # No decision - allows normal continuation
    BLOCK = "block"  # Prompts Claude with the reason (feedback mechanism)


@dataclass
class HookInput:
    """Input data received from Claude Code via stdin.

    Attributes:
        session_id: Unique session identifier
        transcript_path: Path to the session transcript file
        cwd: Current working directory
        permission_mode: Current permission mode
        hook_event_name: The type of hook event
        tool_name: Name of the tool (PreToolUse, PostToolUse only)
        tool_input: Input arguments for the tool (PreToolUse, PostToolUse only)
        tool_use_id: Unique identifier for this tool use (PreToolUse, PostToolUse only)
        tool_result: Result from the tool (PostToolUse only)
    """

    session_id: str
    transcript_path: str
    cwd: str
    permission_mode: str
    hook_event_name: HookEventName
    tool_name: str | None = None
    tool_input: dict[str, Any] | None = None
    tool_use_id: str | None = None
    tool_result: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HookInput":
        """Create HookInput from a dictionary (parsed JSON).

        Args:
            data: Dictionary containing hook input data

        Returns:
            HookInput instance
        """
        # Extract tool_result from tool_response if present
        # Claude Code sends tool_response with stdout/stderr/content fields
        tool_result = data.get("tool_result")
        if not tool_result:
            tool_response = data.get("tool_response")
            if isinstance(tool_response, dict):
                # Try stdout first (for Bash), then content (for Read), then stringify
                tool_result = tool_response.get("stdout") or tool_response.get("content")
                if not tool_result and tool_response:
                    # Fallback: stringify the entire response
                    import json

                    tool_result = json.dumps(tool_response)
            elif isinstance(tool_response, str):
                tool_result = tool_response

        return cls(
            session_id=data.get("session_id", ""),
            transcript_path=data.get("transcript_path", ""),
            cwd=data.get("cwd", ""),
            permission_mode=data.get("permission_mode", "default"),
            hook_event_name=HookEventName(data.get("hook_event_name", "PreToolUse")),
            tool_name=data.get("tool_name"),
            tool_input=data.get("tool_input"),
            tool_use_id=data.get("tool_use_id"),
            tool_result=tool_result,
        )


@dataclass
class PreToolUseOutput:
    """Output specific to PreToolUse hooks."""

    hook_event_name: str = "PreToolUse"
    permission_decision: PermissionDecision = PermissionDecision.ALLOW
    permission_decision_reason: str | None = None
    updated_input: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: dict[str, Any] = {
            "hookEventName": self.hook_event_name,
            "permissionDecision": self.permission_decision.value,
        }
        if self.permission_decision_reason:
            result["permissionDecisionReason"] = self.permission_decision_reason
        if self.updated_input:
            result["updatedInput"] = self.updated_input
        return result


@dataclass
class PostToolUseOutput:
    """Output specific to PostToolUse hooks.

    Based on Claude Code PostToolUse Decision Control documentation:
    https://code.claude.com/docs/en/hooks#posttooluse-decision-control

    PostToolUse hooks run AFTER the tool has completed. They CANNOT prevent
    tool execution or hide output. The 'decision: block' mechanism provides
    FEEDBACK to Claude, automatically prompting it with the reason.

    Output format:
    {
        "decision": "block" | undefined,
        "reason": "Explanation for decision",
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "Additional information for Claude"
        }
    }
    """

    decision: PostToolUseDecision = PostToolUseDecision.NONE
    reason: str | None = None
    additional_context: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization.

        Returns the correct format for PostToolUse decision control:
        - When decision is BLOCK: includes 'decision' and 'reason' at top level
        - hookSpecificOutput contains hookEventName and optional additionalContext
        """
        result: dict[str, Any] = {}

        # Only include decision if it's BLOCK (not empty string)
        if self.decision == PostToolUseDecision.BLOCK:
            result["decision"] = self.decision.value
            if self.reason:
                result["reason"] = self.reason

        # Always include hookSpecificOutput
        hook_specific: dict[str, Any] = {
            "hookEventName": "PostToolUse",
        }
        if self.additional_context:
            hook_specific["additionalContext"] = self.additional_context

        result["hookSpecificOutput"] = hook_specific

        return result


@dataclass
class HookOutput:
    """Output data to send to Claude Code via stdout.

    For PreToolUse:
        Uses hook_specific_output with PreToolUseOutput containing decision/reason.

    For PostToolUse:
        Uses post_tool_use_output with PostToolUseOutput. The decision/reason
        go at the TOP LEVEL of the JSON (not inside hookSpecificOutput).
        This is per the Claude Code PostToolUse Decision Control spec.

    Attributes:
        continue_execution: Whether to continue execution (not used for PostToolUse)
        stop_reason: Reason for stopping (if continue_execution is False)
        suppress_output: Whether to suppress output (not used for PostToolUse)
        system_message: Optional system message to inject (not used for PostToolUse)
        hook_specific_output: PreToolUse-specific output data
        post_tool_use_output: PostToolUse-specific output data
    """

    continue_execution: bool = True
    stop_reason: str | None = None
    suppress_output: bool = False
    system_message: str | None = None
    hook_specific_output: PreToolUseOutput | None = None
    post_tool_use_output: PostToolUseOutput | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization.

        For PostToolUse, returns the format expected by Claude Code:
        {
            "decision": "block" | undefined,
            "reason": "...",
            "hookSpecificOutput": { "hookEventName": "PostToolUse", ... }
        }

        For PreToolUse, returns the standard format with hookSpecificOutput.
        """
        # PostToolUse has its own special format
        if self.post_tool_use_output:
            return self.post_tool_use_output.to_dict()

        # PreToolUse and other hooks use the standard format
        result: dict[str, Any] = {"continue": self.continue_execution}
        if self.stop_reason:
            result["stopReason"] = self.stop_reason
        if self.suppress_output:
            result["suppressOutput"] = self.suppress_output
        if self.system_message:
            result["systemMessage"] = self.system_message
        if self.hook_specific_output:
            result["hookSpecificOutput"] = self.hook_specific_output.to_dict()
        return result


@dataclass
class GuardrailAlert:
    """Alert triggered by a guardrail provider.

    Attributes:
        explanation: Human-readable explanation of the alert
        data: Additional data associated with the alert
    """

    explanation: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ContentToCheck:
    """Content to be checked by a guardrail provider.

    Attributes:
        content: The text content to check
        content_type: Type of content (tool_input, tool_output, etc.)
        tool_name: Name of the tool (if applicable)
        context: Additional context about the content
    """

    content: str
    content_type: str
    tool_name: str | None = None
    context: dict[str, Any] = field(default_factory=dict)
