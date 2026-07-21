from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


SEVERITY_MAP = {
    "critical": "sev1",
    "emergency": "sev1",
    "p1": "sev1",
    "sev1": "sev1",
    "major": "sev2",
    "high": "sev2",
    "p2": "sev2",
    "sev2": "sev2",
    "warning": "sev3",
    "medium": "sev3",
    "degraded": "sev3",
    "p3": "sev3",
    "sev3": "sev3",
    "low": "sev4",
    "info": "sev4",
    "informational": "sev4",
    "ok": "sev4",
    "p4": "sev4",
    "sev4": "sev4",
}

CORE_ROUTE_SEVERITIES = {
    "/": "sev1",
    "/contact/": "sev2",
    "/services/": "sev3",
    "/pricing/": "sev3",
}


def classify_incident(payload: Dict[str, Any]) -> Dict[str, Any]:
    betterstack = payload["betterstack"]
    monitor_url = betterstack["monitor_url"]
    route = _normalize_route(monitor_url)
    metadata = betterstack.get("metadata") or {}
    text_blob = " ".join(
        [
            str(betterstack.get("monitor_name", "")),
            str(betterstack.get("status", "")),
            str(betterstack.get("alert_type", "")),
            str(betterstack.get("severity", "")),
            str(betterstack.get("raw_body", "")),
            str(metadata),
        ]
    ).lower()

    incident_type = _classify_incident_type(route, text_blob)
    normalized_severity = _normalize_severity(
        explicit_severity=betterstack.get("severity"),
        status=betterstack.get("status", ""),
        alert_type=betterstack.get("alert_type", ""),
        route=route,
        incident_type=incident_type,
        text_blob=text_blob,
    )

    current_status = "triaged"
    if _is_recovery_signal(text_blob):
        current_status = "resolved"

    summary = _build_summary(
        severity=normalized_severity,
        incident_type=incident_type,
        route=route,
        monitor_name=betterstack["monitor_name"],
    )

    return {
        "normalized_severity": normalized_severity,
        "incident_type": incident_type,
        "affected_route": route,
        "current_status": current_status,
        "summary": summary,
        "classifier_version": "v1",
        "signals": _collect_signals(route, text_blob, betterstack),
    }


def _normalize_route(monitor_url: str) -> str:
    parsed = urlparse(monitor_url)
    path = parsed.path or "/"
    if path != "/" and not path.endswith("/"):
        path = f"{path}/"
    return path


def _classify_incident_type(route: str, text_blob: str) -> str:
    if _is_recovery_signal(text_blob):
        return "recovery"
    if any(keyword in text_blob for keyword in ("dns", "nxdomain", "hostname", "resolve")):
        return "dns"
    if route.startswith("/contact"):
        return "contact_path"
    if any(keyword in text_blob for keyword in ("third-party", "third party", "vendor outage", "provider outage", "upstream provider")):
        return "third_party_outage"
    if any(keyword in text_blob for keyword in ("cloudflare", "edge", "522", "523", "524", "525", "526", "520", "521")):
        return "edge"
    if any(keyword in text_blob for keyword in ("timeout", "degraded", "latency")):
        return "degradation"
    if any(keyword in text_blob for keyword in ("down", "failed", "unreachable", "error")):
        return "availability"
    return "unknown"


def _normalize_severity(
    explicit_severity: Optional[str],
    status: str,
    alert_type: str,
    route: str,
    incident_type: str,
    text_blob: str,
) -> str:
    if explicit_severity:
        mapped = SEVERITY_MAP.get(explicit_severity.strip().lower())
        if mapped:
            return _adjust_severity(mapped, route, incident_type, text_blob, status, alert_type)

    if _is_recovery_signal(text_blob):
        return "sev4"

    derived = "sev3"
    if incident_type == "dns":
        derived = "sev1"
    elif incident_type == "edge":
        derived = "sev1" if route == "/" else "sev2"
    elif incident_type == "contact_path":
        derived = "sev2"
    elif route in CORE_ROUTE_SEVERITIES:
        derived = CORE_ROUTE_SEVERITIES[route]
    elif status.lower() in {"down", "failed"} or "down" in alert_type.lower():
        derived = "sev3"

    return _adjust_severity(derived, route, incident_type, text_blob, status, alert_type)


def _adjust_severity(
    base: str,
    route: str,
    incident_type: str,
    text_blob: str,
    status: str,
    alert_type: str,
) -> str:
    if _is_recovery_signal(text_blob):
        return "sev4"
    if route == "/" and incident_type in {"availability", "edge", "dns"}:
        return "sev1"
    if route.startswith("/contact") and base == "sev3":
        return "sev2"
    if "timeout" in text_blob and base == "sev1":
        return "sev2"
    return base


def _is_recovery_signal(text_blob: str) -> bool:
    return bool(
        re.search(r"\b(recovered|resolved|up)\b", text_blob)
        or re.search(r"\bback\s+up\b", text_blob)
    )


def _collect_signals(route: str, text_blob: str, betterstack: Dict[str, Any]) -> List[str]:
    signals: List[str] = []
    if route:
        signals.append(f"route:{route}")
    if betterstack.get("severity"):
        signals.append(f"betterstack_severity:{betterstack['severity']}")
    if _is_recovery_signal(text_blob):
        signals.append("recovery-signal")
    if any(keyword in text_blob for keyword in ("dns", "nxdomain", "hostname", "resolve")):
        signals.append("dns-signal")
    if any(keyword in text_blob for keyword in ("522", "523", "524", "525", "526", "520", "521", "cloudflare")):
        signals.append("edge-signal")
    return signals


def _build_summary(severity: str, incident_type: str, route: str, monitor_name: str) -> str:
    route_label = route or "/"
    return f"{severity} {incident_type} incident detected for {route_label} from monitor '{monitor_name}'"
