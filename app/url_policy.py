from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


DEFAULT_ALLOWED_PUBLIC_ORIGINS = "https://hcww.net,https://www.hcww.net"


class URLPolicyError(ValueError):
    pass


def parse_allowed_origins(raw: str) -> tuple[str, ...]:
    origins = []
    for value in raw.split(","):
        candidate = value.strip()
        if not candidate:
            continue
        origins.append(_normalize_origin(candidate, "allowed origin"))
    if not origins:
        raise URLPolicyError("At least one allowed public origin is required")
    return tuple(dict.fromkeys(origins))


def validate_public_url(url: str, allowed_origins: tuple[str, ...], field_name: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise URLPolicyError(f"{field_name} must use https")
    if parsed.username or parsed.password:
        raise URLPolicyError(f"{field_name} must not include credentials")
    hostname = parsed.hostname
    if not hostname:
        raise URLPolicyError(f"{field_name} must include a hostname")
    _reject_unsafe_hostname(hostname, field_name)
    port = _safe_port(parsed, field_name)
    if port not in (None, 443):
        raise URLPolicyError(f"{field_name} must not use an unexpected port")

    origin = _origin(parsed.scheme, hostname, None if port == 443 else port)
    if origin not in allowed_origins:
        raise URLPolicyError(f"{field_name} origin is not allowed")
    return url


def validate_optional_public_url(url: str, allowed_origins: tuple[str, ...], field_name: str) -> None:
    if url.strip():
        validate_public_url(url.strip(), allowed_origins, field_name)


def validate_public_url_csv(raw: str, allowed_origins: tuple[str, ...], field_name: str) -> None:
    for index, value in enumerate(raw.split(","), start=1):
        url = value.strip()
        if url:
            validate_public_url(url, allowed_origins, f"{field_name}[{index}]")


def _normalize_origin(raw: str, field_name: str) -> str:
    parsed = urlparse(raw)
    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        raise URLPolicyError(f"{field_name} must be an origin without path or query")
    validate_public_url(raw, (_origin(parsed.scheme, parsed.hostname or "", None),), field_name)
    port = _safe_port(parsed, field_name)
    return _origin(parsed.scheme, parsed.hostname or "", None if port == 443 else port)


def _reject_unsafe_hostname(hostname: str, field_name: str) -> None:
    normalized = hostname.rstrip(".").lower()
    if normalized in {"localhost"} or normalized.endswith(".localhost"):
        raise URLPolicyError(f"{field_name} must not target localhost")
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    ):
        raise URLPolicyError(f"{field_name} must not target a private or local address")
    raise URLPolicyError(f"{field_name} must not target an IP literal")


def _safe_port(parsed, field_name: str) -> int | None:
    try:
        return parsed.port
    except ValueError as exc:
        raise URLPolicyError(f"{field_name} has an invalid port") from exc


def _origin(scheme: str, hostname: str, port: int | None) -> str:
    host = hostname.rstrip(".").lower()
    if port is None:
        return f"{scheme.lower()}://{host}"
    return f"{scheme.lower()}://{host}:{port}"
