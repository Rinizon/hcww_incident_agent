from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


REDACTED = "[REDACTED]"
MAX_BODY_EXCERPT_CHARS = 500

SENSITIVE_KEY_PARTS = (
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
)

SENSITIVE_KEYS = {
    "raw_payload",
    "raw_payload_json",
    "teams_webhook_url",
    "webhook_url",
    "deploy_base_url",
    "deploy_api_token",
    "cloudflare_api_token",
    "api_token",
    "x-hcww-workflow-secret",
    "x-hcww-admin-secret",
}

PUBLIC_HOSTS = {"hcww.net", "www.hcww.net"}
URL_KEYS = {"target", "target_url", "webhook_url", "deploy_url", "deploy_base_url"}


def redact_data(value: Any) -> Any:
    return _redact(value, parent_key="")


def _redact(value: Any, parent_key: str) -> Any:
    if isinstance(value, dict):
        return {
            key: _redact_key_value(str(key), nested)
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, parent_key=parent_key) for item in value]
    if isinstance(value, tuple):
        return [_redact(item, parent_key=parent_key) for item in value]
    if parent_key == "body_excerpt" and isinstance(value, str):
        return _truncate_body_excerpt(value)
    return value


def _redact_key_value(key: str, value: Any) -> Any:
    normalized = key.lower()
    if normalized in SENSITIVE_KEYS or any(part in normalized for part in SENSITIVE_KEY_PARTS):
        return REDACTED
    if normalized == "headers" and isinstance(value, dict):
        return _redact_headers(value)
    if normalized == "body_excerpt" and isinstance(value, str):
        return _truncate_body_excerpt(value)
    if normalized in URL_KEYS and isinstance(value, str) and _should_redact_url(value):
        return REDACTED
    return _redact(value, parent_key=normalized)


def _redact_headers(headers: dict) -> dict:
    redacted = {}
    for key, value in headers.items():
        normalized = str(key).lower()
        if normalized in SENSITIVE_KEYS or any(part in normalized for part in SENSITIVE_KEY_PARTS):
            redacted[key] = REDACTED
        else:
            redacted[key] = _redact(value, parent_key=normalized)
    return redacted


def _truncate_body_excerpt(value: str) -> str:
    if len(value) <= MAX_BODY_EXCERPT_CHARS:
        return value
    return f"{value[:MAX_BODY_EXCERPT_CHARS]}...[truncated]"


def _should_redact_url(value: str) -> bool:
    parsed = urlparse(value)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if hostname in PUBLIC_HOSTS:
        return False
    return bool(parsed.scheme and parsed.netloc)
