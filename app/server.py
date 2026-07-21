from __future__ import annotations

import json
import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from app.classifier import classify_incident
from app.config import Settings
from app.diagnostics import DiagnosticEngine
from app.notifier import AGENT_MESSAGE_MARKER, SUPPORTED_PHASES, TeamsNotifier
from app.remediation import RemediationEngine
from app.schema import PayloadValidationError, describe_webhook_schema, validate_webhook_payload
from app.store import IncidentStore
from app.url_policy import URLPolicyError, validate_public_url


class IncidentAgentApplication:
    def __init__(
        self,
        settings: Optional[Settings] = None,
        diagnostics: Optional[DiagnosticEngine] = None,
        notifier: Optional[TeamsNotifier] = None,
        remediation: Optional[RemediationEngine] = None,
    ) -> None:
        self.settings = settings or Settings()
        self.store = IncidentStore(self.settings.db_path)
        self.diagnostics = diagnostics or DiagnosticEngine(settings=self.settings)
        self.notifier = notifier or TeamsNotifier(settings=self.settings)
        self.remediation = remediation or RemediationEngine(
            settings=self.settings,
            diagnostics=self.diagnostics,
            store=self.store,
        )

    def handle_health(self) -> Dict[str, Any]:
        return {
            "status": "ok",
            "service": self.settings.service_name,
            "environment": self.settings.env,
            "checks": self.store.health(),
            "auth": self._auth_status(),
            "url_policy": self._url_policy_status(),
            "remediation": self._remediation_status(),
        }

    def handle_webhook(
        self, headers: Dict[str, str], body: bytes
    ) -> tuple[int, Dict[str, Any]]:
        self._validate_secret(headers)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PayloadValidationError("Request body must be valid JSON") from exc

        validated = validate_webhook_payload(payload)
        self._validate_webhook_urls(validated)
        if self._is_self_generated_event(validated):
            return (
                HTTPStatus.ACCEPTED,
                {
                    "status": "accepted",
                    "ignored": True,
                    "reason": "self_generated_agent_message",
                },
            )
        classification = classify_incident(validated)
        claim = self.store.claim_incident_event(validated, classification)
        if claim["outcome"] == "duplicate":
            return (
                HTTPStatus.ACCEPTED,
                {
                    "status": "accepted",
                    "duplicate": True,
                    "classification": None,
                    "incident": claim["incident"],
                },
            )

        incident = claim["incident"]
        incident = self._process_incident(incident)
        return (
            HTTPStatus.ACCEPTED,
            {
                "status": "accepted",
                "classification": classification,
                "incident": incident,
            },
        )

    def list_incidents(self) -> Dict[str, Any]:
        return {"incidents": self.store.list_incidents()}

    def get_incident(self, incident_id: int) -> Optional[Dict[str, Any]]:
        return self.store.get_incident(incident_id)

    def get_incident_audit(self, incident_id: int) -> Dict[str, Any]:
        return {"audit_events": self.store.list_audit_events(incident_id)}

    def handle_admin_list_incidents(self, headers: Dict[str, str]) -> Dict[str, Any]:
        self._validate_admin_secret(headers)
        return {
            "incidents": [
                self._redact_incident(incident)
                for incident in self.store.list_incidents()
            ]
        }

    def handle_admin_get_incident(
        self, headers: Dict[str, str], incident_id: int
    ) -> Optional[Dict[str, Any]]:
        self._validate_admin_secret(headers)
        incident = self.store.get_incident(incident_id)
        if incident is None:
            return None
        return self._redact_incident(incident)

    def handle_admin_get_incident_audit(
        self, headers: Dict[str, str], incident_id: int
    ) -> Optional[Dict[str, Any]]:
        self._validate_admin_secret(headers)
        if self.store.get_incident(incident_id) is None:
            return None
        return {"audit_events": self.store.list_audit_events(incident_id)}

    def schema_document(self) -> Dict[str, Any]:
        schema = describe_webhook_schema()
        schema["auth"] = self._auth_status()
        schema["url_policy"] = self._url_policy_status()
        schema["remediation"] = self._remediation_status()
        schema["teams_posting"] = self._teams_posting_contract()
        return schema

    def _validate_secret(self, headers: Dict[str, str]) -> None:
        expected = self.settings.workflow_shared_secret
        if not expected:
            if self.settings.env == "development":
                return
            raise PermissionError("Workflow shared secret is not configured")

        actual = self._get_header(headers, self.settings.workflow_secret_header)
        if not hmac.compare_digest(actual, expected):
            raise PermissionError("Missing or invalid workflow shared secret")

    def _validate_admin_secret(self, headers: Dict[str, str]) -> None:
        expected = self.settings.admin_shared_secret
        if not expected:
            raise PermissionError("Admin shared secret is not configured")

        actual = self._get_header(headers, "X-HCWW-Admin-Secret")
        if not hmac.compare_digest(actual, expected):
            raise PermissionError("Missing or invalid admin shared secret")

    def _validate_webhook_urls(self, validated: Dict[str, Any]) -> None:
        try:
            validate_public_url(
                validated["betterstack"]["monitor_url"],
                self.settings.allowed_public_origin_values,
                "payload.betterstack.monitor_url",
            )
        except URLPolicyError as exc:
            raise PayloadValidationError(str(exc)) from exc

    def _get_header(self, headers: Dict[str, str], name: str) -> str:
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value
        return ""

    def _remediation_status(self) -> Dict[str, Any]:
        return {
            "mode": (
                "mutating"
                if self.settings.enable_cache_purge or self.settings.enable_redeploy
                else "diagnostics_only"
            ),
            "playbooks": {
                "cloudflare_cache_purge": self.settings.enable_cache_purge,
                "known_good_redeploy": self.settings.enable_redeploy,
            },
        }

    def _auth_status(self) -> Dict[str, Any]:
        workflow_secret_configured = bool(self.settings.workflow_shared_secret)
        return {
            "workflow_webhook": {
                "required": workflow_secret_configured,
                "mode": (
                    "shared_secret"
                    if workflow_secret_configured
                    else "disabled_development_only"
                ),
                "header": self.settings.workflow_secret_header,
            },
            "admin_api": {
                "required": True,
                "mode": "shared_secret",
                "header": "X-HCWW-Admin-Secret",
                "configured": bool(self.settings.admin_shared_secret),
            },
        }

    def _url_policy_status(self) -> Dict[str, Any]:
        return {
            "allowed_public_origins": list(self.settings.allowed_public_origin_values),
            "https_required": True,
            "rejects_private_local_and_ip_literal_targets": True,
            "validates_redirect_targets": True,
        }

    def _teams_posting_contract(self) -> Dict[str, Any]:
        return {
            "mode": self.settings.teams_post_mode,
            "v1_decision": "workflow_managed_threaded_replies",
            "fallback_mode": "webhook_non_threaded_adaptive_card",
            "supported_phases": SUPPORTED_PHASES,
            "workflow_reply_target": "reply_target_message_id",
            "agent_marker": AGENT_MESSAGE_MARKER,
        }

    def _redact_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        redacted = dict(incident)
        redacted.pop("raw_payload", None)
        redacted["action_attempts"] = [
            self._redact_action_attempt(attempt)
            for attempt in incident.get("action_attempts", [])
        ]
        return redacted

    def _redact_action_attempt(self, attempt: Dict[str, Any]) -> Dict[str, Any]:
        redacted = dict(attempt)
        result = dict(redacted.get("result") or {})
        result.pop("target_url", None)
        redacted["result"] = result
        return redacted

    def _is_self_generated_event(self, validated: Dict[str, Any]) -> bool:
        betterstack = validated.get("betterstack", {})
        marker_fields = [
            betterstack.get("raw_body"),
            betterstack.get("monitor_name"),
            betterstack.get("status"),
            betterstack.get("alert_type"),
        ]
        metadata = betterstack.get("metadata") or {}
        marker_fields.append(json.dumps(metadata, sort_keys=True))
        haystack = " ".join(str(value) for value in marker_fields if value is not None)
        return AGENT_MESSAGE_MARKER in haystack

    def _process_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        acknowledged = self.notifier.send_incident_update(
            incident=incident,
            phase="acknowledged",
            message=(
                f"Incident {incident['incident_id']} acknowledged as "
                f"{incident['normalized_severity']} {incident['incident_type']}."
            ),
            details={"current_status": incident["current_status"]},
        )
        self.store.add_audit_event(
            incident_id=incident["incident_id"],
            event_type="teams.update.acknowledged",
            summary="Queued Teams acknowledgement update",
            details=acknowledged,
        )

        if incident["current_status"] != "resolved":
            incident = self.store.transition_incident_status(
                incident_id=incident["incident_id"],
                new_status="diagnosing",
                summary="Diagnostics started",
                details={"reason": "Running public HTTP and DNS checks"},
            )

        diagnostic_results = self.diagnostics.run(incident)
        self.store.add_audit_event(
            incident_id=incident["incident_id"],
            event_type="incident.diagnostics_completed",
            summary=diagnostic_results["summary"],
            details=diagnostic_results,
        )

        diagnosis_update = self.notifier.send_incident_update(
            incident=incident,
            phase="diagnosis",
            message=diagnostic_results["summary"],
            details=diagnostic_results,
        )
        self.store.add_audit_event(
            incident_id=incident["incident_id"],
            event_type="teams.update.diagnosis",
            summary="Queued Teams diagnosis update",
            details=diagnosis_update,
        )

        if diagnostic_results["outcome_status"] != "resolved":
            if self._is_in_remediation_cooldown(incident["incident_id"]):
                cooldown_details = {
                    "reason": "Recent remediation activity is still within cooldown window",
                    "cooldown_seconds": self.settings.remediation_cooldown_seconds,
                }
                incident = self.store.transition_incident_status(
                    incident_id=incident["incident_id"],
                    new_status="escalated",
                    summary="Remediation skipped due to cooldown",
                    details=cooldown_details,
                )
                cooldown_update = self.notifier.send_incident_update(
                    incident=incident,
                    phase="escalated",
                    message="Remediation cooldown is active; escalating to avoid automation loops.",
                    details=cooldown_details,
                )
                self.store.add_audit_event(
                    incident_id=incident["incident_id"],
                    event_type="teams.update.escalated",
                    summary="Queued Teams cooldown escalation update",
                    details=cooldown_update,
                )
                return incident

            incident = self.store.transition_incident_status(
                incident_id=incident["incident_id"],
                new_status="remediating",
                summary="Automated remediation started",
                details={"reason": "Initial diagnostics did not recover the incident"},
            )
            remediation_start_update = self.notifier.send_incident_update(
                incident=incident,
                phase="remediation_started",
                message="Automated remediation is starting.",
                details={"incident_type": incident["incident_type"]},
            )
            self.store.add_audit_event(
                incident_id=incident["incident_id"],
                event_type="teams.update.remediation_started",
                summary="Queued Teams remediation start update",
                details=remediation_start_update,
            )

            remediation_result = self.remediation.execute(incident, diagnostic_results)
            for step in remediation_result["steps"]:
                self.store.add_audit_event(
                    incident_id=incident["incident_id"],
                    event_type="incident.remediation_attempted",
                    summary=f"Attempted {step['playbook']}",
                    details=step,
                )

            incident = self.store.transition_incident_status(
                incident_id=incident["incident_id"],
                new_status="verifying",
                summary="Verification started after remediation",
                details={"attempt_count": len(remediation_result["steps"])},
            )
            verification_update = self.notifier.send_incident_update(
                incident=incident,
                phase="verifying",
                message="Verification is running after automated remediation.",
                details=remediation_result["final_verification"],
            )
            self.store.add_audit_event(
                incident_id=incident["incident_id"],
                event_type="teams.update.verifying",
                summary="Queued Teams verifying update",
                details=verification_update,
            )
            diagnostic_results = remediation_result["final_verification"]
            final_result_details = dict(diagnostic_results)
            final_result_details["remediation"] = {
                "attempted": remediation_result["attempted"],
                "resolved": remediation_result["resolved"],
                "reason": remediation_result["reason"],
                "step_count": len(remediation_result["steps"]),
            }

            remediation_complete_update = self.notifier.send_incident_update(
                incident=incident,
                phase="remediation_completed",
                message=remediation_result["reason"],
                details=remediation_result,
            )
            self.store.add_audit_event(
                incident_id=incident["incident_id"],
                event_type="teams.update.remediation_completed",
                summary="Queued Teams remediation completed update",
                details=remediation_complete_update,
            )

        else:
            final_result_details = dict(diagnostic_results)

        final_status = diagnostic_results["outcome_status"]
        incident = self.store.transition_incident_status(
            incident_id=incident["incident_id"],
            new_status=final_status,
            summary=f"Incident moved to {final_status}",
            details=final_result_details,
            resolved=final_status == "resolved",
        )

        final_update = self.notifier.send_incident_update(
            incident=incident,
            phase=final_status,
            message=diagnostic_results["outcome_reason"],
            details=final_result_details,
        )
        self.store.add_audit_event(
            incident_id=incident["incident_id"],
            event_type=f"teams.update.{final_status}",
            summary=f"Queued Teams {final_status} update",
            details=final_update,
        )
        return incident

    def _is_in_remediation_cooldown(self, incident_id: int) -> bool:
        recent_attempts = self.store.count_action_attempts(
            incident_id=incident_id,
            within_seconds=self.settings.remediation_cooldown_seconds,
        )
        return recent_attempts > 0


def create_http_handler(app: IncidentAgentApplication):
    class Handler(BaseHTTPRequestHandler):
        server_version = "HCWWIncidentAgent/0.1"

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path

            try:
                if path == "/healthz":
                    self._send_json(HTTPStatus.OK, app.handle_health())
                    return
                if path == "/schema/webhooks/teams/betterstack":
                    self._send_json(HTTPStatus.OK, app.schema_document())
                    return
                if path == "/incidents":
                    self._send_json(
                        HTTPStatus.OK,
                        app.handle_admin_list_incidents(dict(self.headers)),
                    )
                    return
                if path.startswith("/incidents/") and path.endswith("/audit"):
                    incident_id = self._parse_incident_id(path, suffix="/audit")
                    audit = app.handle_admin_get_incident_audit(
                        dict(self.headers),
                        incident_id,
                    )
                    if audit is None:
                        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Incident not found"})
                        return
                    self._send_json(HTTPStatus.OK, audit)
                    return
                if path.startswith("/incidents/"):
                    incident_id = self._parse_incident_id(path)
                    incident = app.handle_admin_get_incident(dict(self.headers), incident_id)
                    if incident is None:
                        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Incident not found"})
                        return
                    self._send_json(HTTPStatus.OK, {"incident": incident})
                    return
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Route not found"})
            except PermissionError as exc:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
            except ValueError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid incident identifier"})

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/webhooks/teams/betterstack":
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Route not found"})
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(content_length)
            try:
                status_code, response = app.handle_webhook(dict(self.headers), body)
                self._send_json(status_code, response)
            except PermissionError as exc:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
            except PayloadValidationError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _parse_incident_id(self, path: str, suffix: str = "") -> int:
            trimmed = path[len("/incidents/") :]
            if suffix:
                trimmed = trimmed[: -len(suffix)]
            trimmed = trimmed.strip("/")
            return int(trimmed)

        def _send_json(self, status_code: int, payload: Dict[str, Any]) -> None:
            encoded = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    return Handler


def run(settings: Optional[Settings] = None) -> None:
    app = IncidentAgentApplication(settings=settings)
    handler = create_http_handler(app)
    server = ThreadingHTTPServer((app.settings.host, app.settings.port), handler)
    print(
        f"HCWW incident agent listening on http://{app.settings.host}:{app.settings.port}",
        flush=True,
    )
    server.serve_forever()
