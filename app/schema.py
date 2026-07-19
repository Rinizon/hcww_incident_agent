from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

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


def _validate_betterstack_payload(betterstack: Dict[str, Any], path: str) -> Dict[str, Any]:
    betterstack_validated = {
        "alert_id": _require_string(betterstack, "alert_id", path),
        "monitor_name": _require_string(betterstack, "monitor_name", path),
        "monitor_url": _require_string(betterstack, "monitor_url", path),
        "status": _require_string(betterstack, "status", path),
        "alert_type": _require_string(betterstack, "alert_type", path),
        "check_timestamp": _validate_iso8601(
            _require_string(betterstack, "check_timestamp", path),
            f"{path}.check_timestamp",
        ),
        "incident_id": _optional_string(betterstack, "incident_id"),
        "severity": _optional_string(betterstack, "severity"),
        "raw_body": betterstack.get("raw_body"),
        "metadata": betterstack.get("metadata", {}),
    }

    if betterstack_validated["metadata"] is not None and not isinstance(
        betterstack_validated["metadata"], dict
    ):
        raise PayloadValidationError(f"{path}.metadata must be an object")

    return betterstack_validated


def _normalize_payload(
    *, event_id: str, delivered_at: str, betterstack: Dict[str, Any], raw_payload: Dict[str, Any]
) -> Dict[str, Any]:
    betterstack_validated = _validate_betterstack_payload(betterstack, "payload.betterstack")
    external_incident_key = (
        betterstack_validated["incident_id"]
        or betterstack_validated["alert_id"]
        or event_id
    )

    return {
        "event_id": event_id,
        "source": "betterstack_webhook",
        "delivered_at": delivered_at,
        "external_incident_key": external_incident_key,
        "betterstack": betterstack_validated,
        "raw_payload": raw_payload,
    }


def validate_webhook_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise PayloadValidationError("Payload must be a JSON object")

    event_id = _require_string(payload, "event_id", "payload")
    source = _require_string(payload, "source", "payload")
    if source != "betterstack_webhook":
        raise PayloadValidationError("payload.source must be 'betterstack_webhook'")

    delivered_at = _validate_iso8601(
        _require_string(payload, "delivered_at", "payload"),
        "payload.delivered_at",
    )
    betterstack = _require_object(payload, "betterstack", "payload")
    return _normalize_payload(
        event_id=event_id,
        delivered_at=delivered_at,
        betterstack=betterstack,
        raw_payload=payload,
    )


def direct_betterstack_example_payload() -> Dict[str, Any]:
    return {
        "event_id": "btst_incident_789_started",
        "source": "betterstack_webhook",
        "delivered_at": "2026-07-19T00:34:56Z",
        "betterstack": {
            "alert_id": "alert-789",
            "incident_id": "incident-789",
            "monitor_name": "hcww homepage",
            "monitor_url": "https://hcww.net/",
            "status": "down",
            "alert_type": "monitor.down",
            "check_timestamp": "2026-07-19T00:34:00Z",
            "severity": "critical",
            "raw_body": "Better Stack detected hcww.net is down",
            "metadata": {
                "event_type": "incident.started",
                "monitor_id": "mon-123",
                "response_code": 523,
            },
        },
    }


def describe_direct_betterstack_webhook_schema(secret_header_name: str) -> Dict[str, Any]:
    return {
        "headers": {
            "Content-Type": "application/json",
            secret_header_name: "required when BETTERSTACK_WEBHOOK_SHARED_SECRET is configured",
        },
        "required_top_level_fields": [
            "event_id",
            "source",
            "delivered_at",
            "betterstack",
        ],
        "expected_source": "betterstack_webhook",
        "notes": ["This endpoint is intended for a Better Stack custom outgoing webhook template."],
        "example_payload": direct_betterstack_example_payload(),
    }
