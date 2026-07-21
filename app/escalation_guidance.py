from __future__ import annotations

from typing import Any, Dict, List, Optional


def select_escalation_guidance(
    incident: Dict[str, Any],
    diagnostics: Dict[str, Any],
) -> Dict[str, Any]:
    failure_mode = _failure_mode(incident, diagnostics)
    incident_type = incident.get("incident_type") or "unknown"
    guidance_key = failure_mode if failure_mode in GUIDANCE else incident_type
    guidance = GUIDANCE.get(guidance_key, GUIDANCE["unknown"])
    return {
        "incident_type": incident_type,
        "failure_mode": failure_mode,
        **guidance,
    }


def _failure_mode(incident: Dict[str, Any], diagnostics: Dict[str, Any]) -> str:
    remediation = diagnostics.get("remediation") or {}
    if remediation.get("reason") == "Global remediation kill switch is enabled":
        return "remediation_disabled"
    if remediation.get("reason") == "Recent remediation activity is still within cooldown window":
        return "remediation_cooldown"
    if _has_failed_redeploy(diagnostics):
        return "deploy_failure"

    reason = str(diagnostics.get("outcome_reason", "")).lower()
    if "url policy" in reason or "origin is not allowed" in reason:
        return "url_policy_blocked"
    if not diagnostics.get("dns", {}).get("ok"):
        return "dns"
    contact = diagnostics.get("contact")
    if contact is not None and not contact.get("ok"):
        return "contact_path"
    if "third" in reason or incident.get("incident_type") == "third_party_outage":
        return "third_party_outage"
    if not _all_http_checks_ok(diagnostics):
        return "route_checks_failed"
    return incident.get("incident_type") or "unknown"


def _has_failed_redeploy(diagnostics: Dict[str, Any]) -> bool:
    remediation = diagnostics.get("remediation") or {}
    for step in remediation.get("steps", []):
        if step.get("playbook") != "known_good_redeploy":
            continue
        if step.get("status") != "verified":
            return True
    return False


def _all_http_checks_ok(diagnostics: Dict[str, Any]) -> bool:
    checks: Optional[List[Dict[str, Any]]] = diagnostics.get("http_checks")
    if checks is None:
        return bool(diagnostics.get("http", {}).get("ok"))
    return all(check.get("result", {}).get("ok") for check in checks)


GUIDANCE: Dict[str, Dict[str, Any]] = {
    "dns": {
        "title": "DNS Escalation",
        "recommended_next_step": "Check Cloudflare DNS records and recent zone changes before retrying automated remediation.",
        "checklist": [
            "Confirm authoritative DNS answers for hcww.net and www.hcww.net.",
            "Review recent Cloudflare DNS, registrar, and nameserver changes.",
            "Escalate to the domain owner if authoritative records are missing or stale.",
        ],
    },
    "edge": {
        "title": "Edge Escalation",
        "recommended_next_step": "Inspect Cloudflare edge status, origin reachability, and cache rules for the affected route.",
        "checklist": [
            "Check Cloudflare analytics, firewall events, and origin error details.",
            "Verify the origin responds directly from an approved network path.",
            "Review recent cache, redirect, SSL, and WAF changes.",
        ],
    },
    "availability": {
        "title": "Availability Escalation",
        "recommended_next_step": "Verify hosting health and core public routes before changing infrastructure.",
        "checklist": [
            "Check host, deploy platform, and origin service health.",
            "Compare homepage, services, pricing, and contact route behavior.",
            "Review recent deployments and error logs for matching timestamps.",
        ],
    },
    "contact_path": {
        "title": "Contact Path Escalation",
        "recommended_next_step": "Validate the contact page, form action, and submission workflow end to end.",
        "checklist": [
            "Open the contact page and confirm the form renders.",
            "Confirm the configured form action or provider endpoint is present.",
            "Submit a controlled test message and verify delivery.",
        ],
    },
    "deploy_failure": {
        "title": "Deploy Escalation",
        "recommended_next_step": "Review the deploy provider and latest build before retrying redeploy manually.",
        "checklist": [
            "Check deploy hook/API response details and provider status.",
            "Inspect the latest build logs and rollback target.",
            "Retry manually only after confirming the previous deployment state.",
        ],
    },
    "third_party_outage": {
        "title": "Third-Party Escalation",
        "recommended_next_step": "Check the upstream provider status page and disable dependent automations if failures persist.",
        "checklist": [
            "Confirm provider status and incident notices.",
            "Identify affected HCWW workflows or embeds.",
            "Prepare a manual workaround or customer-facing update if impact continues.",
        ],
    },
    "unknown": {
        "title": "Unknown Incident Escalation",
        "recommended_next_step": "Review diagnostics, logs, and recent changes before attempting manual remediation.",
        "checklist": [
            "Inspect the full incident audit trail and diagnostic evidence.",
            "Check recent site, DNS, deploy, and workflow changes.",
            "Assign an owner for manual investigation.",
        ],
    },
    "route_checks_failed": {
        "title": "Route Check Escalation",
        "recommended_next_step": "Compare failed public routes and inspect the shared origin path before mutating configuration.",
        "checklist": [
            "Identify whether failures share the same origin, route group, or template.",
            "Check status codes, redirects, and expected text failures.",
            "Review recent content, routing, and deployment changes.",
        ],
    },
    "remediation_disabled": {
        "title": "Remediation Disabled",
        "recommended_next_step": "Keep automation disabled and assign an operator to investigate manually.",
        "checklist": [
            "Confirm the kill switch was intentionally enabled.",
            "Review diagnostics and decide whether manual remediation is appropriate.",
            "Leave a note before re-enabling automated remediation.",
        ],
    },
    "remediation_cooldown": {
        "title": "Remediation Cooldown",
        "recommended_next_step": "Avoid repeated automation and review the previous action attempts.",
        "checklist": [
            "Inspect recent action attempts for the same incident.",
            "Confirm whether the site recovered or still requires manual action.",
            "Adjust retry/cooldown settings only after reviewing the incident timeline.",
        ],
    },
    "url_policy_blocked": {
        "title": "URL Policy Escalation",
        "recommended_next_step": "Review the requested URL against the HCWW public-origin allowlist before changing policy.",
        "checklist": [
            "Confirm the URL is an HCWW-owned public HTTPS endpoint.",
            "Reject private, local, link-local, or unexpected redirect targets.",
            "Update the allowlist in staging before production.",
        ],
    },
}
