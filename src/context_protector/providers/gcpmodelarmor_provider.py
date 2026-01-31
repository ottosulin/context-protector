"""GCP Model Armor guardrail provider.

Uses Google Cloud Model Armor to detect and sanitize potentially harmful content.
"""

import logging
import os
from typing import Any

from context_protector.guardrail_types import ContentToCheck, GuardrailAlert
from context_protector.providers.base import GuardrailProvider

logger = logging.getLogger(__name__)


class GCPModelArmorProvider(GuardrailProvider):
    """GCP Model Armor guardrail provider.

    Uses Google Cloud Model Armor API for content sanitization and threat detection.

    Configuration can be provided via:
    - Constructor parameters (highest priority)
    - Environment variables (CONTEXT_PROTECTOR_GCP_*)
    - Config file (lowest priority)

    Environment variables:
    - CONTEXT_PROTECTOR_GCP_PROJECT_ID: GCP project ID
    - CONTEXT_PROTECTOR_GCP_LOCATION: GCP region (e.g., us-central1)
    - CONTEXT_PROTECTOR_GCP_TEMPLATE_ID: Model Armor template ID
    """

    def __init__(
        self,
        project_id: str | None = None,
        location: str | None = None,
        template_id: str | None = None,
    ) -> None:
        """Initialize the GCP Model Armor provider.

        Args:
            project_id: GCP project ID override
            location: GCP region override
            template_id: Model Armor template ID override
        """
        from context_protector.config import get_config

        config = get_config()

        # Declare types explicitly (all can be None if not configured)
        self._project_id: str | None
        self._location: str | None
        self._template_id: str | None

        # Project ID: parameter > env > config
        if project_id is not None:
            self._project_id = project_id
        else:
            env_val = os.environ.get("CONTEXT_PROTECTOR_GCP_PROJECT_ID")
            self._project_id = env_val if env_val else config.gcp_model_armor.project_id

        # Location: parameter > env > config
        if location is not None:
            self._location = location
        else:
            env_val = os.environ.get("CONTEXT_PROTECTOR_GCP_LOCATION")
            self._location = env_val if env_val else config.gcp_model_armor.location

        # Template ID: parameter > env > config
        if template_id is not None:
            self._template_id = template_id
        else:
            env_val = os.environ.get("CONTEXT_PROTECTOR_GCP_TEMPLATE_ID")
            self._template_id = env_val if env_val else config.gcp_model_armor.template_id

        self._client: Any = None

        logger.debug(
            "Initializing GCPModelArmorProvider (project=%s, location=%s, template=%s)",
            self._project_id,
            self._location,
            self._template_id,
        )

    @property
    def name(self) -> str:
        """Get the provider name."""
        return "GCPModelArmor"

    def _validate_config(self) -> str | None:
        """Validate that required configuration is present.

        Returns:
            Error message if configuration is invalid, None otherwise
        """
        missing = []
        if not self._project_id:
            missing.append("project_id")
        if not self._location:
            missing.append("location")
        if not self._template_id:
            missing.append("template_id")

        if missing:
            return f"Missing required GCP Model Armor configuration: {', '.join(missing)}"
        return None

    def _get_client(self) -> Any:
        """Get or create the Model Armor client.

        Returns:
            Model Armor client instance

        Raises:
            ImportError: If google-cloud-modelarmor is not installed
        """
        if self._client is not None:
            return self._client

        try:
            from google.api_core.client_options import ClientOptions
            from google.cloud import modelarmor_v1
        except ImportError as e:
            raise ImportError(
                "GCP Model Armor requires 'google-cloud-modelarmor'. "
                "Install with: pip install google-cloud-modelarmor"
            ) from e

        self._client = modelarmor_v1.ModelArmorClient(
            transport="rest",
            client_options=ClientOptions(
                api_endpoint=f"modelarmor.{self._location}.rep.googleapis.com"
            ),
        )

        logger.info("Created GCP Model Armor client for location: %s", self._location)
        return self._client

    def _extract_filter_details(self, filter_name: str, filter_result: Any) -> dict[str, Any]:
        """Extract detailed information from a specific filter result.

        Args:
            filter_name: Name of the filter (e.g., "rai", "pi_and_jailbreak")
            filter_result: The FilterResult object

        Returns:
            Dictionary with filter details
        """
        from google.cloud import modelarmor_v1

        details: dict[str, Any] = {"filter_name": filter_name}

        # Check for RAI filter result
        if filter_result.rai_filter_result:
            rai = filter_result.rai_filter_result
            details["filter_type"] = "Responsible AI"
            details["match_state"] = rai.match_state.name
            details["execution_state"] = rai.execution_state.name

            # Extract specific RAI type results (sexually_explicit, hate_speech, etc.)
            if rai.rai_filter_type_results:
                rai_details = []
                for rai_type, type_result in rai.rai_filter_type_results.items():
                    if type_result.match_state == modelarmor_v1.FilterMatchState.MATCH_FOUND:
                        rai_details.append(
                            {
                                "type": rai_type,
                                "confidence": type_result.confidence_level.name,
                            }
                        )
                if rai_details:
                    details["detections"] = rai_details

            # Extract message items
            if rai.message_items:
                details["messages"] = [
                    {"type": m.message_type.name, "text": m.message} for m in rai.message_items
                ]

        # Check for Prompt Injection / Jailbreak filter result
        elif filter_result.pi_and_jailbreak_filter_result:
            pi = filter_result.pi_and_jailbreak_filter_result
            details["filter_type"] = "Prompt Injection & Jailbreak"
            details["match_state"] = pi.match_state.name
            details["execution_state"] = pi.execution_state.name
            if pi.match_state == modelarmor_v1.FilterMatchState.MATCH_FOUND:
                details["confidence"] = pi.confidence_level.name

            if pi.message_items:
                details["messages"] = [
                    {"type": m.message_type.name, "text": m.message} for m in pi.message_items
                ]

        # Check for Malicious URI filter result
        elif filter_result.malicious_uri_filter_result:
            uri = filter_result.malicious_uri_filter_result
            details["filter_type"] = "Malicious URI"
            details["match_state"] = uri.match_state.name
            details["execution_state"] = uri.execution_state.name

            if uri.malicious_uri_matched_items:
                details["malicious_uris"] = [item.uri for item in uri.malicious_uri_matched_items]

            if uri.message_items:
                details["messages"] = [
                    {"type": m.message_type.name, "text": m.message} for m in uri.message_items
                ]

        # Check for SDP (Sensitive Data Protection) filter result
        elif filter_result.sdp_filter_result:
            sdp = filter_result.sdp_filter_result
            details["filter_type"] = "Sensitive Data Protection"

            if sdp.inspect_result:
                inspect = sdp.inspect_result
                details["match_state"] = inspect.match_state.name
                details["execution_state"] = inspect.execution_state.name

                if inspect.findings:
                    details["findings"] = [
                        {
                            "info_type": f.info_type,
                            "likelihood": f.likelihood.name,
                        }
                        for f in inspect.findings[:5]  # Limit to first 5
                    ]
                    if len(inspect.findings) > 5:
                        details["findings_truncated"] = True

                if inspect.message_items:
                    details["messages"] = [
                        {"type": m.message_type.name, "text": m.message}
                        for m in inspect.message_items
                    ]

        # Check for CSAM filter result
        elif filter_result.csam_filter_filter_result:
            csam = filter_result.csam_filter_filter_result
            details["filter_type"] = "CSAM"
            details["match_state"] = csam.match_state.name
            details["execution_state"] = csam.execution_state.name

            if csam.message_items:
                details["messages"] = [
                    {"type": m.message_type.name, "text": m.message} for m in csam.message_items
                ]

        # Check for Virus Scan filter result
        elif filter_result.virus_scan_filter_result:
            virus = filter_result.virus_scan_filter_result
            details["filter_type"] = "Virus Scan"
            details["match_state"] = virus.match_state.name
            details["execution_state"] = virus.execution_state.name

            if virus.virus_details:
                details["viruses"] = [
                    {
                        "names": list(v.names),
                        "threat_type": v.threat_type.name,
                        "vendor": v.vendor,
                    }
                    for v in virus.virus_details
                ]

            if virus.message_items:
                details["messages"] = [
                    {"type": m.message_type.name, "text": m.message} for m in virus.message_items
                ]

        return details

    def _sanitize_content(self, content: str) -> tuple[bool, dict[str, Any]]:
        """Sanitize content using Model Armor.

        Args:
            content: The content to sanitize

        Returns:
            Tuple of (is_safe, response_data)
        """
        from google.cloud import modelarmor_v1

        client = self._get_client()

        # Create the request
        user_prompt_data = modelarmor_v1.DataItem(text=content)

        request = modelarmor_v1.SanitizeUserPromptRequest(
            name=f"projects/{self._project_id}/locations/{self._location}/templates/{self._template_id}",
            user_prompt_data=user_prompt_data,
        )

        response = client.sanitize_user_prompt(request=request)

        # Check if any filter matched (content flagged)
        match_state = response.sanitization_result.filter_match_state
        is_safe = match_state != modelarmor_v1.FilterMatchState.MATCH_FOUND

        # Extract response data for logging/alerts
        response_data: dict[str, Any] = {
            "match_state": match_state.name,
            "is_safe": is_safe,
        }

        # Add invocation result
        if hasattr(response.sanitization_result, "invocation_result"):
            response_data["invocation_result"] = response.sanitization_result.invocation_result.name

        # Add sanitization metadata if present
        if hasattr(response.sanitization_result, "sanitization_metadata"):
            meta = response.sanitization_result.sanitization_metadata
            if meta.error_message:
                response_data["error_message"] = meta.error_message
            if meta.error_code:
                response_data["error_code"] = meta.error_code

        # Add detailed filter results
        if hasattr(response.sanitization_result, "filter_results"):
            filter_results = []
            for filter_name, filter_result in response.sanitization_result.filter_results.items():
                filter_details = self._extract_filter_details(filter_name, filter_result)
                filter_results.append(filter_details)
            if filter_results:
                response_data["filter_results"] = filter_results

        return is_safe, response_data

    def _format_match_state(self, match_state: Any) -> str | None:
        """Format match_state to a human-readable string.

        Handles both enum objects and raw values (int/str).

        Args:
            match_state: The match state (enum, int, or str)

        Returns:
            Human-readable match state string
        """
        # Map of known match state values to descriptions
        match_state_map = {
            "MATCH_FOUND": "content flagged",
            "NO_MATCH": "content safe",
            "MATCH_STATE_UNSPECIFIED": "unspecified",
            # Integer values from the protobuf enum
            0: "unspecified",
            1: "content safe",
            2: "content flagged",
        }

        if match_state == match_state_map["NO_MATCH"] or match_state == match_state_map[1]:
            return None

        # Try to get the name if it's an enum
        if hasattr(match_state, "name"):
            state_name: str = match_state.name
            result = match_state_map.get(state_name)
            return str(result) if result is not None else state_name

        # Handle raw int or string values
        if match_state in match_state_map:
            result = match_state_map[match_state]
            return str(result) if result is not None else None

        # Fallback to string representation
        return str(match_state)

    def _has_actual_detection_content(
        self, filter_type: str, filter_info: dict[str, Any]
    ) -> bool:
        """Check if a filter has actual detection content beyond just match_state.

        This helps filter out false positives where the API returns MATCH_FOUND
        but no actual detection details.

        Args:
            filter_type: The type of filter
            filter_info: The filter information dictionary

        Returns:
            True if the filter has actual detection content
        """
        # Check for filter-specific content that indicates a real detection
        if filter_type == "Responsible AI":
            # RAI should have detections or messages
            return bool(filter_info.get("detections") or filter_info.get("messages"))

        if filter_type == "Prompt Injection & Jailbreak":
            # PI should have confidence level or messages
            return bool(filter_info.get("confidence") or filter_info.get("messages"))

        if filter_type == "Malicious URI":
            # Should have actual URIs detected
            return bool(filter_info.get("malicious_uris") or filter_info.get("messages"))

        if filter_type == "Sensitive Data Protection":
            # Should have findings or messages
            return bool(filter_info.get("findings") or filter_info.get("messages"))

        if filter_type == "Virus Scan":
            # Should have virus details or messages
            return bool(filter_info.get("viruses") or filter_info.get("messages"))

        if filter_type == "CSAM":
            # CSAM should have messages or other detection content
            # Don't report CSAM just because match_state is MATCH_FOUND
            return bool(filter_info.get("messages"))

        # Unknown filter types - report if they have match_state
        return True

    def _format_detection_explanation(self, response_data: dict[str, Any]) -> str:
        """Format a human-readable explanation of the detection.

        Only includes filter types that have actual detection content, not just
        a MATCH_FOUND status. This prevents showing all categories when the API
        returns MATCH_FOUND for all configured filters even if only one actually
        triggered.

        Args:
            response_data: The response data from sanitization

        Returns:
            A human-readable explanation string
        """
        explanations: list[str] = []

        # Handle case where filter_results is missing or empty
        if "filter_results" not in response_data or not response_data["filter_results"]:
            # Try to provide what information we have
            parts = ["GCP Model Armor blocked content"]

            match_state = response_data.get("match_state")
            if match_state:
                state_desc = self._format_match_state(match_state)
                parts.append(f"(status: {state_desc})")

            # Add invocation result if available
            if response_data.get("invocation_result"):
                parts.append(f"[{response_data['invocation_result']}]")

            # Add error details if available
            if response_data.get("error_message"):
                parts.append(f"Error: {response_data['error_message']}")

            return " ".join(parts)

        for filter_info in response_data["filter_results"]:
            match_state = filter_info.get("match_state", "")
            # Use exact equality check for robustness
            if match_state != "MATCH_FOUND":
                continue

            filter_type = filter_info.get("filter_type", filter_info.get("filter_name", "Unknown"))

            # Skip filters without actual detection content
            # This prevents showing all categories when only one actually triggered
            if not self._has_actual_detection_content(filter_type, filter_info):
                logger.debug(
                    "Skipping filter %s - MATCH_FOUND but no detection content",
                    filter_type,
                )
                continue

            # Build specific explanation based on filter type
            if filter_type == "Responsible AI":
                detections = filter_info.get("detections", [])
                if detections:
                    detection_strs = [
                        f"{d['type'].replace('_', ' ')} ({d['confidence']})" for d in detections
                    ]
                    explanations.append(f"Responsible AI violations: {', '.join(detection_strs)}")
                else:
                    explanations.append("Responsible AI content violation detected")

            elif filter_type == "Prompt Injection & Jailbreak":
                confidence = filter_info.get("confidence", "")
                if confidence:
                    explanations.append(
                        f"Prompt injection/jailbreak attempt detected ({confidence} confidence)"
                    )
                else:
                    explanations.append("Prompt injection/jailbreak attempt detected")

            elif filter_type == "Malicious URI":
                uris = filter_info.get("malicious_uris", [])
                if uris:
                    # Truncate to first 3 URIs if more
                    if len(uris) > 3:
                        uri_str = ", ".join(uris[:3]) + f" (+{len(uris) - 3} more)"
                    else:
                        uri_str = ", ".join(uris)
                    explanations.append(f"Malicious URIs detected: {uri_str}")
                else:
                    explanations.append("Malicious URI detected")

            elif filter_type == "Sensitive Data Protection":
                findings = filter_info.get("findings", [])
                if findings:
                    info_types = [f["info_type"] for f in findings]
                    # Truncate to first 5 info types if more
                    if len(info_types) > 5:
                        info_str = ", ".join(info_types[:5]) + f" (+{len(info_types) - 5} more)"
                    else:
                        info_str = ", ".join(info_types)
                    explanations.append(f"Sensitive data detected: {info_str}")
                else:
                    explanations.append("Sensitive data detected")

            elif filter_type == "CSAM":
                explanations.append("CSAM (Child Safety) content detected")

            elif filter_type == "Virus Scan":
                viruses = filter_info.get("viruses", [])
                if viruses:
                    virus_names = []
                    for v in viruses:
                        names = v.get("names", [])
                        if names:
                            virus_names.append(names[0])
                    if virus_names:
                        explanations.append(f"Malware detected: {', '.join(virus_names)}")
                    else:
                        explanations.append("Malware detected")
                else:
                    explanations.append("Malware detected")

            else:
                explanations.append(f"{filter_type} filter triggered")

        if not explanations:
            return "GCP Model Armor detected potentially harmful content"

        return "GCP Model Armor: " + "; ".join(explanations)

    def check_content(self, content: ContentToCheck) -> GuardrailAlert | None:
        """Check content using GCP Model Armor.

        Args:
            content: The content to check

        Returns:
            GuardrailAlert if a threat is detected, None otherwise
        """
        logger.info(
            "Checking content: type=%s, tool=%s, length=%d",
            content.content_type,
            content.tool_name,
            len(content.content),
        )

        # Validate configuration
        config_error = self._validate_config()
        if config_error:
            logger.error(config_error)
            return GuardrailAlert(
                explanation=f"GCP Model Armor configuration error: {config_error}",
                data={
                    "provider": "GCPModelArmor",
                    "error": "configuration_error",
                    "details": config_error,
                },
            )

        try:
            is_safe, response_data = self._sanitize_content(content.content)

            if is_safe:
                logger.debug("Content passed Model Armor sanitization")
                return None

            # Content was flagged - generate detailed explanation first
            explanation = self._format_detection_explanation(response_data)

            # Log with human-readable explanation
            logger.warning("Content flagged by Model Armor: %s", explanation)

            # Also log detailed filter results at debug level for troubleshooting
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    "Model Armor response details: %s",
                    response_data,
                )

            return GuardrailAlert(
                explanation=explanation,
                data={
                    "provider": "GCPModelArmor",
                    "content_type": content.content_type,
                    "tool_name": content.tool_name,
                    **response_data,
                },
            )

        except ImportError as e:
            logger.warning(
                "GCP Model Armor unavailable: %s. "
                "Install with: pip install google-cloud-modelarmor",
                e,
            )
            return GuardrailAlert(
                explanation=f"GCP Model Armor unavailable: {e}",
                data={
                    "provider": "GCPModelArmor",
                    "error": "import_error",
                    "details": str(e),
                },
            )
        except Exception as e:
            logger.exception("Error checking content with GCP Model Armor")
            return GuardrailAlert(
                explanation=f"Error checking content with GCP Model Armor: {e!s}",
                data={
                    "provider": "GCPModelArmor",
                    "error": str(type(e).__name__),
                    "details": str(e),
                    "content_type": content.content_type,
                    "tool_name": content.tool_name,
                },
            )
