from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from app.classifier import classify_incident
from app.config import Settings
from app.diagnostics import DiagnosticEngine
from app.notifier import TeamsNotifier
from app.remediation import RemediationEngine
from app.schema import PayloadValidationError, describe_webhook_schema, validate_webhook_payload
from app.store import IncidentStore


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
        duplicate = self.store.get_incident_by_source_event_id(validated["event_id"])
        if duplicate is not None:
            self.store.add_audit_event(
                incident_id=duplicate["incident_id"],
                event_type="incident.duplicate_ignored",
                summary="Duplicate workflow event ignored",
                details={"event_id": validated["event_id"]},
            )
            return (
                HTTPStatus.ACCEPTED,
                {
                    "status": "accepted",
                    "duplicate": True,
                    "classification": None,
                    "incident": duplicate,
                },
            )
        classification = classify_incident(validated)
        incident = self.store.upsert_incident(validated, classification)
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

    def schema_document(self) -> Dict[str, Any]:
        return describe_webhook_schema()

    def _validate_secret(self, headers: Dict[str, str]) -> None:
        expected = self.settings.workflow_shared_secret
        if not expected:
            return

        actual = headers.get("X-HCWW-Workflow-Secret", "")
        if actual != expected:
            raise PermissionError("Missing or invalid workflow shared secret")

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
                self.store.record_action_attempt(
                    incident_id=incident["incident_id"],
                    playbook_name=step["playbook"],
                    action_type=step["action_type"],
                    inputs=step["inputs"],
                    result=step["result"],
                    verification=step["verification"],
                )
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
                    self._send_json(HTTPStatus.OK, app.list_incidents())
                    return
                if path.startswith("/incidents/") and path.endswith("/audit"):
                    incident_id = self._parse_incident_id(path, suffix="/audit")
                    incident = app.get_incident(incident_id)
                    if incident is None:
                        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Incident not found"})
                        return
                    self._send_json(HTTPStatus.OK, app.get_incident_audit(incident_id))
                    return
                if path.startswith("/incidents/"):
                    incident_id = self._parse_incident_id(path)
                    incident = app.get_incident(incident_id)
                    if incident is None:
                        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Incident not found"})
                        return
                    self._send_json(HTTPStatus.OK, {"incident": incident})
                    return
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Route not found"})
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
