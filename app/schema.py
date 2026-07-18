from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Tuple


class PayloadValidationError(ValueError):
    pass


def _require_string(payload: Dict[str, Any], key: str, path: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PayloadValidationError(f"Missing or invalid string at {path}.{key}")
    return value.strip()


def _optional_string(payload: Dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise PayloadValidationError(f"Invalid string at {key}")
    return value.strip()


def _require_object(payload: Dict[str, Any], key: str, path: str) -> Dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise PayloadValidationError(f"Missing or invalid object at {path}.{key}")
    return value


def _validate_iso8601(value: str, field_name: str) -> str:
    candidate = value.replace("Z", "+00:00")
    try:
        datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise PayloadValidationError(f"Invalid ISO-8601 timestamp at {field_name}") from exc
    return value


def validate_webhook_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise PayloadValidationError("Payload must be a JSON object")

    event_id = _require_string(payload, "event_id", "payload")
    source = _require_string(payload, "source", "payload")
    if source != "teams_workflow":
        raise PayloadValidationError("payload.source must be 'teams_workflow'")

    delivered_at = _validate_iso8601(
        _require_string(payload, "delivered_at", "payload"),
        "payload.delivered_at",
    )

    teams = _require_object(payload, "teams", "payload")
    betterstack = _require_object(payload, "betterstack", "payload")

    teams_validated = {
        "team_id": _require_string(teams, "team_id", "payload.teams"),
        "channel_id": _require_string(teams, "channel_id", "payload.teams"),
        "root_message_id": _require_string(teams, "root_message_id", "payload.teams"),
        "reply_to_message_id": _optional_string(teams, "reply_to_message_id"),
    }

    betterstack_validated = {
        "alert_id": _require_string(betterstack, "alert_id", "payload.betterstack"),
        "monitor_name": _require_string(betterstack, "monitor_name", "payload.betterstack"),
        "monitor_url": _require_string(betterstack, "monitor_url", "payload.betterstack"),
        "status": _require_string(betterstack, "status", "payload.betterstack"),
        "alert_type": _require_string(betterstack, "alert_type", "payload.betterstack"),
        "check_timestamp": _validate_iso8601(
            _require_string(betterstack, "check_timestamp", "payload.betterstack"),
            "payload.betterstack.check_timestamp",
        ),
        "incident_id": _optional_string(betterstack, "incident_id"),
        "severity": _optional_string(betterstack, "severity"),
        "raw_body": betterstack.get("raw_body"),
        "metadata": betterstack.get("metadata", {}),
    }

    if betterstack_validated["metadata"] is not None and not isinstance(
        betterstack_validated["metadata"], dict
    ):
        raise PayloadValidationError("payload.betterstack.metadata must be an object")

    external_incident_key = (
        betterstack_validated["incident_id"]
        or betterstack_validated["alert_id"]
        or event_id
    )

    return {
        "event_id": event_id,
        "source": source,
        "delivered_at": delivered_at,
        "external_incident_key": external_incident_key,
        "teams": teams_validated,
        "betterstack": betterstack_validated,
        "raw_payload": payload,
    }


def validation_example_payload() -> Dict[str, Any]:
    return {
        "event_id": "evt_20260718_0001",
        "source": "teams_workflow",
        "delivered_at": "2026-07-18T12:34:56Z",
        "teams": {
            "team_id": "team-123",
            "channel_id": "channel-456",
            "root_message_id": "1752849296000",
            "reply_to_message_id": "1752849296000",
        },
        "betterstack": {
            "alert_id": "alert-789",
            "incident_id": "incident-789",
            "monitor_name": "hcww homepage",
            "monitor_url": "https://hcww.net/",
            "status": "down",
            "alert_type": "monitor.down",
            "check_timestamp": "2026-07-18T12:34:00Z",
            "severity": "critical",
            "raw_body": "Better Stack detected hcww.net is down",
            "metadata": {"monitor_id": "mon-123", "response_code": 523},
        },
    }


def describe_webhook_schema() -> Dict[str, Any]:
    return {
        "headers": {
            "Content-Type": "application/json",
            "X-HCWW-Workflow-Secret": "required when TEAMS_WORKFLOW_SHARED_SECRET is configured",
        },
        "required_top_level_fields": [
            "event_id",
            "source",
            "delivered_at",
            "teams",
            "betterstack",
        ],
        "expected_source": "teams_workflow",
        "example_payload": validation_example_payload(),
    }
