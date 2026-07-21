import io
import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from app.classifier import classify_incident
from app.config import Settings
from app.diagnostics import DiagnosticEngine
from app.escalation_guidance import select_escalation_guidance
from app.notifier import AGENT_MESSAGE_MARKER, SUPPORTED_PHASES, TeamsNotifier
from app.redaction import MAX_BODY_EXCERPT_CHARS, REDACTED
from app.remediation import (
    CloudflareClient,
    DeployClient,
    RealDeployClient,
    RealCloudflareClient,
    RemediationEngine,
    build_cloudflare_client,
    build_deploy_client,
)
from app.server import IncidentAgentApplication, create_http_handler
from app.schema import PayloadValidationError, validation_example_payload
from app.structured_logging import StructuredLogger
from tools.drill_agent import (
    SCENARIOS,
    dry_run_request,
    evaluate_result,
    list_scenarios,
    load_payload,
    main as drill_main,
    request_from_payload_file,
    run_request,
    run_scenario,
)
from tools.retention import main as retention_main


class FakeCloudflareClient(CloudflareClient):
    def __init__(self) -> None:
        self.calls = []

    def purge_cache(self, urls: list) -> dict:
        self.calls.append(urls)
        return {"ok": True, "action": "cache_purge", "urls": urls}


class FakeDeployClient(DeployClient):
    def __init__(self) -> None:
        self.calls = 0

    def trigger_redeploy(self, incident: dict) -> dict:
        self.calls += 1
        return {"ok": True, "action": "redeploy", "incident_id": incident["incident_id"]}


class InspectingCloudflareClient(CloudflareClient):
    def __init__(self, app: IncidentAgentApplication) -> None:
        self.app = app
        self.started_before_mutation = False

    def purge_cache(self, urls: list) -> dict:
        attempts = self.app.store.list_action_attempts(1)
        self.started_before_mutation = (
            len(attempts) == 1
            and attempts[0]["playbook_name"] == "cloudflare_cache_purge"
            and attempts[0]["status"] == "started"
        )
        return {"ok": True, "action": "cache_purge", "urls": urls}


class RaisingCloudflareClient(CloudflareClient):
    def purge_cache(self, urls: list) -> dict:
        raise RuntimeError("Cloudflare API unavailable")


class PackagingHardeningTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.project_root = Path(__file__).resolve().parent.parent

    def test_dockerignore_excludes_secrets_and_local_state(self) -> None:
        dockerignore = (self.project_root / ".dockerignore").read_text().splitlines()

        self.assertIn(".env", dockerignore)
        self.assertIn(".env.*", dockerignore)
        self.assertIn(".git", dockerignore)
        self.assertIn("data/", dockerignore)
        self.assertIn(".codex/", dockerignore)

    def test_gitignore_does_not_hide_dockerignore(self) -> None:
        gitignore = (self.project_root / ".gitignore").read_text().splitlines()

        self.assertNotIn(".dockerignore", gitignore)

    def test_dockerfile_runs_as_non_root_user(self) -> None:
        dockerfile = (self.project_root / "Dockerfile").read_text()

        self.assertIn("adduser --system", dockerfile)
        self.assertIn("COPY --chown=hcww:hcww", dockerfile)
        self.assertIn("USER hcww", dockerfile)

    def test_docker_compose_keeps_credentials_runtime_only(self) -> None:
        compose = (self.project_root / "docker-compose.yml").read_text()

        self.assertIn("env_file:", compose)
        self.assertIn("- .env", compose)
        self.assertIn("./data:/app/data", compose)


class ApplicationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "agent_state.db")
        self.settings = Settings(
            host="127.0.0.1",
            port=8787,
            db_path=self.db_path,
            env="test",
            service_name="hcww",
            actor_email="incident-agent@hcww.local",
            public_base_url="https://agent.example.com",
            workflow_shared_secret="test-secret",
            admin_shared_secret="admin-secret",
            teams_post_mode="workflow",
            teams_webhook_url="",
            cloudflare_api_token="",
            cloudflare_zone_id="",
            deploy_base_url="",
            deploy_api_token="",
            smoke_check_url="",
            smoke_check_expected_text="Hill Country Web Works",
            max_remediation_attempts=2,
            enable_cache_purge=True,
            enable_redeploy=True,
        )
        self.notifier = TeamsNotifier(settings=self.settings)
        self.log_stream = io.StringIO()
        self.logger = StructuredLogger(stream=self.log_stream)
        self.cloudflare = FakeCloudflareClient()
        self.deploy = FakeDeployClient()
        self.fetch_calls = {}
        self.diagnostics = DiagnosticEngine(
            settings=self.settings,
            fetch=self.fake_fetch,
            resolve=self.fake_resolve,
        )
        self.remediation = RemediationEngine(
            settings=self.settings,
            diagnostics=self.diagnostics,
            cloudflare=self.cloudflare,
            deploy=self.deploy,
        )
        self.app = IncidentAgentApplication(
            settings=self.settings,
            diagnostics=self.diagnostics,
            notifier=self.notifier,
            remediation=self.remediation,
            logger=self.logger,
        )
        self.remediation.store = self.app.store

    def load_fixture(self, name: str) -> dict:
        fixture_path = Path(__file__).parent / "fixtures" / name
        return json.loads(fixture_path.read_text())

    def fake_fetch(self, url: str, timeout_seconds: float) -> dict:
        count = self.fetch_calls.get(url, 0)
        self.fetch_calls[url] = count + 1
        if "down" in url and count == 0:
            raise RuntimeError("HTTP 523 origin is unreachable")
        if "redeploy-fail" in url:
            raise RuntimeError("Origin still unavailable")
        if "route-fail" in url:
            raise RuntimeError("Required route unavailable")
        return {
            "ok": True,
            "status_code": 200,
            "final_url": url,
            "headers": {"content-type": "text/html"},
            "body_excerpt": "Hill Country Web Works homepage",
            "latency_ms": 42,
        }

    def fake_resolve(self, hostname: str) -> list:
        if hostname == "dns-fail.hcww.net":
            raise RuntimeError("Name or service not known")
        return ["203.0.113.10"]

    def log_records(self) -> list[dict]:
        return [
            json.loads(line)
            for line in self.log_stream.getvalue().splitlines()
            if line.strip()
        ]

    def age_incident_rows(self, incident_id: int, timestamp: str) -> None:
        with self.app.store._connect() as connection:
            connection.execute(
                """
                UPDATE incidents
                SET created_at = ?, updated_at = ?, resolved_at = ?
                WHERE incident_id = ?
                """,
                (timestamp, timestamp, timestamp, incident_id),
            )
            connection.execute(
                "UPDATE audit_events SET created_at = ? WHERE incident_id = ?",
                (timestamp, incident_id),
            )
            connection.execute(
                """
                UPDATE action_attempts
                SET started_at = ?, completed_at = ?
                WHERE incident_id = ?
                """,
                (timestamp, timestamp, incident_id),
            )

    def count_rows(self, table_name: str) -> int:
        with self.app.store._connect() as connection:
            row = connection.execute(f"SELECT COUNT(*) AS count FROM {table_name}").fetchone()
            return int(row["count"])

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def post_webhook_http(
        self,
        app: IncidentAgentApplication,
        body: bytes,
        headers: dict,
    ) -> tuple[int, dict]:
        handler_class = create_http_handler(app)
        handler = handler_class.__new__(handler_class)
        handler.path = "/webhooks/teams/betterstack"
        handler.headers = headers
        handler.rfile = io.BytesIO(body)
        captured = {}

        def capture_json(status_code: int, payload: dict) -> None:
            captured["status"] = status_code
            captured["payload"] = payload

        handler._send_json = capture_json
        handler_class.do_POST(handler)
        return int(captured["status"]), captured["payload"]

    def get_http(
        self,
        app: IncidentAgentApplication,
        path: str,
        headers: dict,
    ) -> tuple[int, dict]:
        handler_class = create_http_handler(app)
        handler = handler_class.__new__(handler_class)
        handler.path = path
        handler.headers = headers
        captured = {}

        def capture_json(status_code: int, payload: dict) -> None:
            captured["status"] = status_code
            captured["payload"] = payload

        handler._send_json = capture_json
        handler_class.do_GET(handler)
        return int(captured["status"]), captured["payload"]

    def test_health_endpoint_logic(self) -> None:
        body = self.app.handle_health()

        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["checks"]["database"], "ok")
        self.assertEqual(body["remediation"]["mode"], "mutating")
        self.assertTrue(body["remediation"]["playbooks"]["cloudflare_cache_purge"])
        self.assertTrue(body["remediation"]["playbooks"]["known_good_redeploy"])
        self.assertEqual(body["metrics"]["webhooks_accepted"], 0)

    def test_default_settings_start_in_diagnostics_only_mode(self) -> None:
        original_cache_purge = os.environ.pop("HCWW_ENABLE_CACHE_PURGE", None)
        original_redeploy = os.environ.pop("HCWW_ENABLE_REDEPLOY", None)
        original_remediation_disabled = os.environ.pop("HCWW_REMEDIATION_DISABLED", None)
        try:
            settings = Settings(db_path=os.path.join(self.temp_dir.name, "defaults.db"))
            app = IncidentAgentApplication(settings=settings)
            health = app.handle_health()
            schema = app.schema_document()

            self.assertFalse(settings.enable_cache_purge)
            self.assertFalse(settings.enable_redeploy)
            self.assertFalse(settings.remediation_disabled)
            self.assertEqual(health["remediation"]["mode"], "diagnostics_only")
            self.assertFalse(health["remediation"]["disabled"])
            self.assertFalse(health["remediation"]["playbooks"]["cloudflare_cache_purge"])
            self.assertFalse(health["remediation"]["playbooks"]["known_good_redeploy"])
            self.assertEqual(schema["remediation"], health["remediation"])
        finally:
            if original_cache_purge is not None:
                os.environ["HCWW_ENABLE_CACHE_PURGE"] = original_cache_purge
            if original_redeploy is not None:
                os.environ["HCWW_ENABLE_REDEPLOY"] = original_redeploy
            if original_remediation_disabled is not None:
                os.environ["HCWW_REMEDIATION_DISABLED"] = original_remediation_disabled

    def test_remediation_kill_switch_forces_playbooks_off_in_health_and_schema(self) -> None:
        settings = Settings(
            db_path=os.path.join(self.temp_dir.name, "kill_switch_health.db"),
            env="test",
            workflow_shared_secret="test-secret",
            admin_shared_secret="admin-secret",
            remediation_disabled=True,
            enable_cache_purge=True,
            enable_redeploy=True,
        )
        app = IncidentAgentApplication(
            settings=settings,
            logger=StructuredLogger(stream=io.StringIO()),
        )

        health = app.handle_health()
        schema = app.schema_document()

        self.assertTrue(settings.remediation_disabled)
        self.assertEqual(health["remediation"]["mode"], "disabled")
        self.assertTrue(health["remediation"]["disabled"])
        self.assertFalse(health["remediation"]["playbooks"]["cloudflare_cache_purge"])
        self.assertFalse(health["remediation"]["playbooks"]["known_good_redeploy"])
        self.assertTrue(health["remediation"]["configured_playbooks"]["cloudflare_cache_purge"])
        self.assertTrue(health["remediation"]["configured_playbooks"]["known_good_redeploy"])
        self.assertEqual(schema["remediation"], health["remediation"])

    def test_remediation_kill_switch_can_be_enabled_from_environment(self) -> None:
        original_value = os.environ.get("HCWW_REMEDIATION_DISABLED")
        try:
            os.environ["HCWW_REMEDIATION_DISABLED"] = "true"
            settings = Settings(
                db_path=os.path.join(self.temp_dir.name, "kill_switch_env.db"),
                env="test",
                workflow_shared_secret="test-secret",
            )

            self.assertTrue(settings.remediation_disabled)
        finally:
            if original_value is None:
                os.environ.pop("HCWW_REMEDIATION_DISABLED", None)
            else:
                os.environ["HCWW_REMEDIATION_DISABLED"] = original_value

    def test_webhook_persists_incident_and_audit(self) -> None:
        payload = self.load_fixture("edge_down.json")
        status_code, body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )

        self.assertEqual(status_code, 202)
        incident = body["incident"]
        self.assertEqual(incident["current_status"], "resolved")
        self.assertEqual(incident["betterstack"]["monitor_url"], "https://hcww.net/")
        self.assertEqual(incident["normalized_severity"], "sev1")
        self.assertEqual(incident["incident_type"], "edge")
        self.assertEqual(body["classification"]["normalized_severity"], "sev1")
        self.assertEqual(len(self.notifier.sent_messages), 3)
        self.assertEqual(len(incident["action_attempts"]), 0)

        incident_id = incident["incident_id"]
        incident_lookup = self.app.get_incident(incident_id)
        self.assertIsNotNone(incident_lookup)
        self.assertEqual(incident_lookup["external_incident_key"], "incident-789")
        self.assertEqual(incident_lookup["current_status"], "resolved")

        audit_lookup = self.app.get_incident_audit(incident_id)
        event_types = [event["event_type"] for event in audit_lookup["audit_events"]]
        self.assertIn("incident.received", event_types)
        self.assertIn("incident.triaged", event_types)
        self.assertIn("incident.diagnosing", event_types)
        self.assertIn("incident.diagnostics_completed", event_types)
        self.assertIn("incident.resolved", event_types)
        self.assertIn("teams.update.acknowledged", event_types)
        self.assertIn("teams.update.diagnosis", event_types)
        self.assertIn("teams.update.resolved", event_types)

    def test_structured_logs_capture_incident_lifecycle(self) -> None:
        payload = self.load_fixture("edge_down.json")

        status_code, body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )

        records = self.log_records()
        events = [record["event"] for record in records]
        self.assertEqual(status_code, 202)
        self.assertIn("webhook.accepted", events)
        self.assertIn("incident.claimed", events)
        self.assertIn("incident.diagnostics_completed", events)
        self.assertIn("teams.update_queued", events)
        self.assertIn("incident.resolved", events)
        incident_records = [
            record
            for record in records
            if record.get("incident_id") == body["incident"]["incident_id"]
        ]
        self.assertGreater(len(incident_records), 0)
        for record in records:
            self.assertIn("timestamp", record)
            self.assertIn("level", record)
            self.assertIn("details", record)

    def test_structured_logs_redact_sensitive_details(self) -> None:
        self.logger.info(
            "test.redaction",
            headers={"Authorization": "Bearer log-secret-token"},
            api_token="another-log-secret",
            target_url="https://deploy.example.com/hooks/redeploy",
        )

        serialized_logs = self.log_stream.getvalue()
        self.assertNotIn("log-secret-token", serialized_logs)
        self.assertNotIn("another-log-secret", serialized_logs)
        self.assertNotIn("deploy.example.com", serialized_logs)
        self.assertIn(REDACTED, serialized_logs)

    def test_structured_logs_capture_http_rejection(self) -> None:
        encoded = json.dumps(validation_example_payload()).encode("utf-8")

        status, body = self.post_webhook_http(
            self.app,
            encoded,
            {
                "Content-Type": "text/plain",
                "Content-Length": str(len(encoded)),
                "X-HCWW-Workflow-Secret": "test-secret",
            },
        )

        records = self.log_records()
        self.assertEqual(status, 415)
        self.assertIn("application/json", body["error"])
        self.assertEqual(records[-1]["event"], "webhook.rejected")
        self.assertEqual(records[-1]["level"], "warning")
        self.assertEqual(records[-1]["details"]["reason"], "unsupported_content_type")
        self.assertEqual(
            self.app.metrics.snapshot()["webhook.rejected.request_policy"],
            1,
        )

    def test_admin_incident_reads_require_shared_secret(self) -> None:
        with self.assertRaises(PermissionError):
            self.app.handle_admin_list_incidents(headers={})

        with self.assertRaises(PermissionError):
            self.app.handle_admin_list_incidents(headers={"X-HCWW-Admin-Secret": "wrong-secret"})

    def test_admin_metrics_requires_shared_secret(self) -> None:
        with self.assertRaises(PermissionError):
            self.app.handle_admin_metrics(headers={})

    def test_metrics_endpoint_requires_admin_secret(self) -> None:
        status, body = self.get_http(self.app, "/metrics", headers={})

        self.assertEqual(status, 401)
        self.assertIn("error", body)

    def test_metrics_endpoint_returns_counter_snapshot(self) -> None:
        self.app.metrics.increment("test.counter")

        status, body = self.get_http(
            self.app,
            "/metrics",
            headers={"X-HCWW-Admin-Secret": "admin-secret"},
        )

        self.assertEqual(status, 200)
        self.assertEqual(body["metrics"]["test.counter"], 1)

    def test_admin_secret_header_is_case_insensitive(self) -> None:
        body = self.app.handle_admin_list_incidents(
            headers={"x-hcww-admin-secret": "admin-secret"}
        )

        self.assertEqual(body["incidents"], [])

    def test_admin_incident_reads_are_redacted(self) -> None:
        payload = self.load_fixture("edge_down.json")
        payload["betterstack"]["metadata"]["api_token"] = "metadata-secret-token"
        payload["betterstack"]["metadata"]["raw_payload"] = {"secret": "nested-secret"}
        status_code, body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )
        incident_id = body["incident"]["incident_id"]

        list_body = self.app.handle_admin_list_incidents(
            headers={"X-HCWW-Admin-Secret": "admin-secret"}
        )
        detail = self.app.handle_admin_get_incident(
            headers={"X-HCWW-Admin-Secret": "admin-secret"},
            incident_id=incident_id,
        )
        audit = self.app.handle_admin_get_incident_audit(
            headers={"X-HCWW-Admin-Secret": "admin-secret"},
            incident_id=incident_id,
        )

        self.assertEqual(status_code, 202)
        self.assertEqual(len(list_body["incidents"]), 1)
        self.assertNotIn("raw_payload", list_body["incidents"][0])
        self.assertIsNotNone(detail)
        assert detail is not None
        self.assertNotIn("raw_payload", detail)
        self.assertEqual(detail["incident_id"], incident_id)
        self.assertIsNotNone(audit)
        assert audit is not None
        self.assertGreater(len(audit["audit_events"]), 0)
        serialized = json.dumps({"detail": detail, "audit": audit})
        self.assertNotIn("metadata-secret-token", serialized)
        self.assertNotIn("nested-secret", serialized)

    def test_admin_audit_redacts_sensitive_details_from_existing_rows(self) -> None:
        payload = self.load_fixture("edge_down.json")
        _status_code, body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )
        incident_id = body["incident"]["incident_id"]
        self.app.store.add_audit_event(
            incident_id=incident_id,
            event_type="test.sensitive",
            summary="Sensitive details",
            details={
                "headers": {
                    "Authorization": "Bearer secret-token",
                    "Cookie": "session=secret-cookie",
                    "content-type": "application/json",
                },
                "target_url": "https://deploy.example.com/hooks/redeploy",
                "raw_payload": {"secret": "payload-secret"},
                "body_excerpt": "x" * (MAX_BODY_EXCERPT_CHARS + 25),
            },
        )

        audit = self.app.handle_admin_get_incident_audit(
            headers={"X-HCWW-Admin-Secret": "admin-secret"},
            incident_id=incident_id,
        )

        self.assertIsNotNone(audit)
        assert audit is not None
        sensitive_event = next(
            event
            for event in audit["audit_events"]
            if event["event_type"] == "test.sensitive"
        )
        details = sensitive_event["details"]
        self.assertEqual(details["headers"]["Authorization"], REDACTED)
        self.assertEqual(details["headers"]["Cookie"], REDACTED)
        self.assertEqual(details["headers"]["content-type"], "application/json")
        self.assertEqual(details["target_url"], REDACTED)
        self.assertEqual(details["raw_payload"], REDACTED)
        self.assertLessEqual(
            len(details["body_excerpt"]),
            MAX_BODY_EXCERPT_CHARS + len("...[truncated]"),
        )

    def test_admin_incident_redacts_sensitive_action_attempt_details(self) -> None:
        payload = self.load_fixture("edge_down.json")
        status_code, body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )
        incident_id = body["incident"]["incident_id"]
        self.app.store.record_action_attempt(
            incident_id=incident_id,
            playbook_name="known_good_redeploy",
            action_type="redeploy",
            inputs={"target": "https://deploy.example.com/hooks/redeploy"},
            result={
                "ok": False,
                "target_url": "https://deploy.example.com/hooks/redeploy",
                "headers": {"Authorization": "Bearer deploy-secret"},
                "reason": "failed",
            },
            verification={
                "outcome_status": "escalated",
                "body_excerpt": "y" * (MAX_BODY_EXCERPT_CHARS + 10),
            },
        )

        detail = self.app.handle_admin_get_incident(
            headers={"X-HCWW-Admin-Secret": "admin-secret"},
            incident_id=incident_id,
        )

        self.assertEqual(status_code, 202)
        self.assertIsNotNone(detail)
        assert detail is not None
        serialized = json.dumps(detail)
        self.assertNotIn("deploy.example.com", serialized)
        self.assertNotIn("deploy-secret", serialized)
        attempt = detail["action_attempts"][-1]
        self.assertEqual(attempt["inputs"]["target"], REDACTED)
        self.assertEqual(attempt["result"]["target_url"], REDACTED)
        self.assertEqual(attempt["result"]["headers"]["Authorization"], REDACTED)

    def test_admin_incident_reads_fail_when_secret_is_unconfigured(self) -> None:
        settings = Settings(
            host="127.0.0.1",
            port=8787,
            db_path=os.path.join(self.temp_dir.name, "unconfigured_admin.db"),
            env="test",
            service_name="hcww",
            actor_email="incident-agent@hcww.local",
            public_base_url="https://agent.example.com",
            workflow_shared_secret="test-secret",
            admin_shared_secret="",
        )
        app = IncidentAgentApplication(
            settings=settings,
            logger=StructuredLogger(stream=io.StringIO()),
        )

        with self.assertRaises(PermissionError):
            app.handle_admin_list_incidents(headers={"X-HCWW-Admin-Secret": "admin-secret"})

    def test_webhook_requires_shared_secret_when_configured(self) -> None:
        payload = validation_example_payload()

        with self.assertRaises(PermissionError):
            self.app.handle_webhook(
                headers={},
                body=json.dumps(payload).encode("utf-8"),
            )
        self.assertEqual(self.app.metrics.snapshot()["webhook.rejected.auth"], 1)

    def test_webhook_rejects_wrong_shared_secret_when_configured(self) -> None:
        payload = validation_example_payload()

        with self.assertRaises(PermissionError):
            self.app.handle_webhook(
                headers={"X-HCWW-Workflow-Secret": "wrong-secret"},
                body=json.dumps(payload).encode("utf-8"),
            )

    def test_production_settings_require_workflow_secret(self) -> None:
        with self.assertRaises(ValueError):
            Settings(
                db_path=os.path.join(self.temp_dir.name, "missing_workflow_secret.db"),
                env="production",
                workflow_shared_secret="",
            )

    def test_settings_reject_non_positive_retention_days(self) -> None:
        with self.assertRaises(ValueError):
            Settings(
                db_path=os.path.join(self.temp_dir.name, "bad_retention.db"),
                retention_days=0,
            )

    def test_legacy_betterstack_secret_env_var_is_used_for_workflow_auth(self) -> None:
        original_teams_secret = os.environ.pop("TEAMS_WORKFLOW_SHARED_SECRET", None)
        original_teams_header = os.environ.pop("TEAMS_WORKFLOW_SECRET_HEADER", None)
        original_betterstack_secret = os.environ.get("BETTERSTACK_WEBHOOK_SHARED_SECRET")
        try:
            os.environ["BETTERSTACK_WEBHOOK_SHARED_SECRET"] = "legacy-secret"

            settings = Settings(
                db_path=os.path.join(self.temp_dir.name, "legacy_secret.db"),
                env="production",
            )

            self.assertEqual(settings.workflow_shared_secret, "legacy-secret")
            self.assertEqual(settings.workflow_secret_header, "X-HCWW-Workflow-Secret")
        finally:
            if original_teams_secret is not None:
                os.environ["TEAMS_WORKFLOW_SHARED_SECRET"] = original_teams_secret
            if original_teams_header is not None:
                os.environ["TEAMS_WORKFLOW_SECRET_HEADER"] = original_teams_header
            if original_betterstack_secret is None:
                os.environ.pop("BETTERSTACK_WEBHOOK_SHARED_SECRET", None)
            else:
                os.environ["BETTERSTACK_WEBHOOK_SHARED_SECRET"] = original_betterstack_secret

    def test_development_settings_report_disabled_webhook_auth(self) -> None:
        settings = Settings(
            db_path=os.path.join(self.temp_dir.name, "development_auth.db"),
            env="development",
            workflow_shared_secret="",
        )
        app = IncidentAgentApplication(
            settings=settings,
            logger=StructuredLogger(stream=io.StringIO()),
        )

        health = app.handle_health()
        schema = app.schema_document()

        self.assertFalse(health["auth"]["workflow_webhook"]["required"])
        self.assertEqual(
            health["auth"]["workflow_webhook"]["mode"],
            "disabled_development_only",
        )
        self.assertEqual(schema["auth"], health["auth"])

    def test_webhook_rejects_invalid_payload(self) -> None:
        payload = validation_example_payload()
        del payload["teams"]["root_message_id"]

        with self.assertRaises(PayloadValidationError):
            self.app.handle_webhook(
                headers={"X-HCWW-Workflow-Secret": "test-secret"},
                body=json.dumps(payload).encode("utf-8"),
            )

    def test_http_webhook_accepts_valid_json_request_shape(self) -> None:
        encoded = json.dumps(validation_example_payload()).encode("utf-8")

        status, body = self.post_webhook_http(
            self.app,
            encoded,
            {
                "Content-Type": "application/json; charset=utf-8",
                "Content-Length": str(len(encoded)),
                "X-HCWW-Workflow-Secret": "test-secret",
            },
        )

        self.assertEqual(status, 202)
        self.assertEqual(body["status"], "accepted")

    def test_http_webhook_rejects_oversized_body_before_read(self) -> None:
        settings = Settings(
            db_path=os.path.join(self.temp_dir.name, "small_body_limit.db"),
            env="test",
            workflow_shared_secret="test-secret",
            max_webhook_body_bytes=8,
        )
        app = IncidentAgentApplication(
            settings=settings,
            logger=StructuredLogger(stream=io.StringIO()),
        )
        body = b'{"too":"large"}'

        status, response = self.post_webhook_http(
            app,
            body,
            {
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "X-HCWW-Workflow-Secret": "test-secret",
            },
        )

        self.assertEqual(status, 413)
        self.assertEqual(response["max_bytes"], 8)
        self.assertEqual(app.list_incidents()["incidents"], [])
        self.assertEqual(
            app.metrics.snapshot()["webhook.rejected.request_policy"],
            1,
        )

    def test_http_webhook_rejects_invalid_content_length(self) -> None:
        status, body = self.post_webhook_http(
            self.app,
            b"",
            {
                "Content-Type": "application/json",
                "Content-Length": "not-a-number",
                "X-HCWW-Workflow-Secret": "test-secret",
            },
        )

        self.assertEqual(status, 400)
        self.assertIn("Content-Length", body["error"])

    def test_http_webhook_rejects_missing_content_length(self) -> None:
        status, body = self.post_webhook_http(
            self.app,
            b"",
            {
                "Content-Type": "application/json",
                "X-HCWW-Workflow-Secret": "test-secret",
            },
        )

        self.assertEqual(status, 400)
        self.assertIn("Content-Length", body["error"])

    def test_http_webhook_rejects_non_json_content_type(self) -> None:
        encoded = json.dumps(validation_example_payload()).encode("utf-8")

        status, body = self.post_webhook_http(
            self.app,
            encoded,
            {
                "Content-Type": "text/plain",
                "Content-Length": str(len(encoded)),
                "X-HCWW-Workflow-Secret": "test-secret",
            },
        )

        self.assertEqual(status, 415)
        self.assertIn("application/json", body["error"])

    def test_webhook_rejects_disallowed_monitor_url(self) -> None:
        payload = validation_example_payload()
        payload["betterstack"]["monitor_url"] = "http://169.254.169.254/latest/meta-data/"

        with self.assertRaises(PayloadValidationError):
            self.app.handle_webhook(
                headers={"X-HCWW-Workflow-Secret": "test-secret"},
                body=json.dumps(payload).encode("utf-8"),
            )

        self.assertEqual(self.app.list_incidents()["incidents"], [])
        self.assertEqual(self.fetch_calls, {})
        self.assertEqual(
            self.app.metrics.snapshot()["webhook.rejected.url_policy"],
            1,
        )

    def test_settings_reject_private_smoke_check_url(self) -> None:
        with self.assertRaises(ValueError):
            Settings(
                db_path=os.path.join(self.temp_dir.name, "private_smoke.db"),
                env="test",
                workflow_shared_secret="test-secret",
                smoke_check_url="https://127.0.0.1/",
            )

    def test_settings_reject_unexpected_core_smoke_origin(self) -> None:
        with self.assertRaises(ValueError):
            Settings(
                db_path=os.path.join(self.temp_dir.name, "bad_core_origin.db"),
                env="test",
                workflow_shared_secret="test-secret",
                core_smoke_urls="https://example.com/",
            )

    def test_self_generated_agent_message_is_ignored(self) -> None:
        payload = validation_example_payload()
        payload["event_id"] = "evt_self_generated_1"
        payload["betterstack"]["raw_body"] = (
            f"<p>{AGENT_MESSAGE_MARKER} HCWW Incident Agent | DIAGNOSIS</p>"
        )

        status_code, body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )

        self.assertEqual(status_code, 202)
        self.assertTrue(body["ignored"])
        self.assertEqual(body["reason"], "self_generated_agent_message")
        self.assertEqual(self.app.list_incidents()["incidents"], [])

    def test_classifier_sets_contact_path_to_sev2(self) -> None:
        payload = self.load_fixture("contact_down.json")
        payload["betterstack"]["monitor_url"] = "https://hcww.net/contact/"
        payload["betterstack"]["monitor_name"] = "hcww contact route"
        payload["betterstack"]["severity"] = ""
        payload["betterstack"]["alert_type"] = "monitor.down"
        payload["betterstack"]["raw_body"] = "Contact page is down"

        classification = classify_incident({"betterstack": payload["betterstack"]})

        self.assertEqual(classification["incident_type"], "contact_path")
        self.assertEqual(classification["normalized_severity"], "sev2")

    def test_classifier_marks_third_party_provider_outage(self) -> None:
        payload = self.load_fixture("edge_down.json")
        payload["betterstack"]["monitor_name"] = "hcww scheduling provider"
        payload["betterstack"]["raw_body"] = "Upstream provider outage is affecting booking embeds"

        classification = classify_incident({"betterstack": payload["betterstack"]})

        self.assertEqual(classification["incident_type"], "third_party_outage")
        self.assertEqual(classification["current_status"], "triaged")

    def test_classifier_marks_recovery_as_resolved(self) -> None:
        payload = self.load_fixture("recovery.json")

        classification = classify_incident({"betterstack": payload["betterstack"]})

        self.assertEqual(classification["incident_type"], "recovery")
        self.assertEqual(classification["normalized_severity"], "sev4")
        self.assertEqual(classification["current_status"], "resolved")

    def test_classifier_does_not_treat_recovery_substrings_as_recovery(self) -> None:
        for word in ("support", "update", "backup"):
            with self.subTest(word=word):
                payload = self.load_fixture("edge_down.json")
                payload["betterstack"]["status"] = "down"
                payload["betterstack"]["severity"] = "critical"
                payload["betterstack"]["alert_type"] = "monitor.down"
                payload["betterstack"]["raw_body"] = f"Cloudflare 523 during {word} check"

                classification = classify_incident({"betterstack": payload["betterstack"]})

                self.assertNotEqual(classification["incident_type"], "recovery")
                self.assertNotEqual(classification["current_status"], "resolved")
                self.assertNotIn("recovery-signal", classification["signals"])

    def test_classifier_treats_standalone_up_status_as_recovery(self) -> None:
        payload = self.load_fixture("edge_down.json")
        payload["betterstack"]["status"] = "up"
        payload["betterstack"]["severity"] = ""
        payload["betterstack"]["alert_type"] = "monitor.up"
        payload["betterstack"]["raw_body"] = "Monitor is up"

        classification = classify_incident({"betterstack": payload["betterstack"]})

        self.assertEqual(classification["incident_type"], "recovery")
        self.assertEqual(classification["normalized_severity"], "sev4")
        self.assertEqual(classification["current_status"], "resolved")

    def test_diagnostics_escalate_when_configured_core_route_fails(self) -> None:
        settings = Settings(
            db_path=os.path.join(self.temp_dir.name, "route_checks.db"),
            smoke_check_expected_text="Hill Country Web Works",
            core_smoke_urls="https://hcww.net/services/, https://hcww.net/route-fail/pricing/",
        )
        diagnostics = DiagnosticEngine(
            settings=settings,
            fetch=self.fake_fetch,
            resolve=self.fake_resolve,
        )
        incident = {
            "incident_type": "availability",
            "betterstack": {"monitor_url": "https://hcww.net/"},
        }

        result = diagnostics.run(incident)

        self.assertEqual(result["outcome_status"], "escalated")
        self.assertEqual(result["outcome_reason"], "One or more public route checks failed")
        self.assertEqual(len(result["http_checks"]), 3)
        self.assertEqual(result["http"]["headers"]["content-type"], "text/html")
        failed = [check for check in result["http_checks"] if not check["result"].get("ok")]
        self.assertEqual(failed[0]["url"], "https://hcww.net/route-fail/pricing/")

    def test_contact_diagnostics_validate_expected_form_action(self) -> None:
        def contact_fetch(url: str, timeout_seconds: float) -> dict:
            body = "Hill Country Web Works contact page"
            if url.endswith("/contact/"):
                body += '<form action="https://wrong.example/submit"></form>'
            return {
                "ok": True,
                "status_code": 200,
                "final_url": url,
                "headers": {"content-type": "text/html"},
                "body_excerpt": body,
                "latency_ms": 10,
            }

        settings = Settings(
            db_path=os.path.join(self.temp_dir.name, "contact_checks.db"),
            smoke_check_expected_text="Hill Country Web Works",
            contact_form_expected_action="https://forms.example/submit",
            enable_cache_purge=True,
        )
        diagnostics = DiagnosticEngine(
            settings=settings,
            fetch=contact_fetch,
            resolve=self.fake_resolve,
        )
        remediation = RemediationEngine(
            settings=settings,
            diagnostics=diagnostics,
            cloudflare=self.cloudflare,
            deploy=self.deploy,
        )
        incident = {
            "incident_id": 1,
            "incident_type": "contact_path",
            "betterstack": {"monitor_url": "https://hcww.net/contact/"},
        }

        result = diagnostics.run(incident)

        self.assertEqual(result["outcome_status"], "escalated")
        self.assertEqual(result["outcome_reason"], "Contact-path checks failed")
        self.assertFalse(result["contact"]["ok"])
        self.assertFalse(result["contact"]["form_action_present"])
        self.assertEqual(remediation.plan(incident, result), [])

    def test_diagnostics_reject_redirect_to_disallowed_origin(self) -> None:
        def redirect_fetch(url: str, timeout_seconds: float) -> dict:
            return {
                "ok": True,
                "status_code": 200,
                "final_url": "https://example.com/",
                "headers": {"content-type": "text/html"},
                "body_excerpt": "Hill Country Web Works homepage",
                "latency_ms": 10,
            }

        settings = Settings(
            db_path=os.path.join(self.temp_dir.name, "redirect_policy.db"),
            smoke_check_expected_text="Hill Country Web Works",
        )
        diagnostics = DiagnosticEngine(
            settings=settings,
            fetch=redirect_fetch,
            resolve=self.fake_resolve,
        )
        incident = {
            "incident_type": "availability",
            "betterstack": {"monitor_url": "https://hcww.net/"},
        }

        result = diagnostics.run(incident)

        self.assertEqual(result["outcome_status"], "escalated")
        self.assertFalse(result["http"]["ok"])
        self.assertIn("origin is not allowed", result["http"]["error"])

    def test_escalation_guidance_selects_dns_next_step(self) -> None:
        guidance = select_escalation_guidance(
            {"incident_type": "dns"},
            {
                "dns": {"ok": False},
                "http_checks": [],
                "outcome_reason": "DNS checks failed",
            },
        )

        self.assertEqual(guidance["failure_mode"], "dns")
        self.assertIn("Cloudflare DNS", guidance["recommended_next_step"])

    def test_escalation_guidance_selects_deploy_failure_next_step(self) -> None:
        guidance = select_escalation_guidance(
            {"incident_type": "edge"},
            {
                "dns": {"ok": True},
                "http_checks": [{"result": {"ok": False}}],
                "outcome_reason": "One or more public route checks failed",
                "remediation": {
                    "steps": [
                        {
                            "playbook": "known_good_redeploy",
                            "status": "succeeded",
                        }
                    ],
                },
            },
        )

        self.assertEqual(guidance["failure_mode"], "deploy_failure")
        self.assertIn("deploy provider", guidance["recommended_next_step"])

    def test_escalation_guidance_selects_third_party_next_step(self) -> None:
        guidance = select_escalation_guidance(
            {"incident_type": "third_party_outage"},
            {
                "dns": {"ok": True},
                "http_checks": [{"result": {"ok": False}}],
                "outcome_reason": "Third-party provider checks failed",
            },
        )

        self.assertEqual(guidance["failure_mode"], "third_party_outage")
        self.assertIn("upstream provider", guidance["recommended_next_step"])

    def test_webhook_escalates_when_public_checks_fail(self) -> None:
        payload = self.load_fixture("edge_down.json")
        payload["betterstack"]["monitor_url"] = "https://hcww.net/down/"
        payload["betterstack"]["raw_body"] = "Cloudflare 523 origin unreachable"

        status_code, body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )

        self.assertEqual(status_code, 202)
        self.assertEqual(body["incident"]["current_status"], "resolved")
        self.assertEqual(self.notifier.sent_messages[-1]["payload"]["phase"], "resolved")
        self.assertEqual(len(body["incident"]["action_attempts"]), 1)
        self.assertEqual(body["incident"]["action_attempts"][0]["playbook_name"], "cloudflare_cache_purge")
        self.assertEqual(body["incident"]["action_attempts"][0]["status"], "verified")
        self.assertEqual(len(self.cloudflare.calls), 1)
        self.assertEqual(self.deploy.calls, 0)
        metrics = self.app.metrics.snapshot()
        self.assertEqual(metrics["webhook.accepted"], 1)
        self.assertEqual(metrics["diagnostics.escalated"], 1)
        self.assertEqual(metrics["remediation.attempted"], 1)
        self.assertEqual(metrics["remediation.succeeded"], 1)

    def test_remediation_attempt_is_started_before_external_mutation(self) -> None:
        payload = self.load_fixture("edge_down.json")
        payload["betterstack"]["monitor_url"] = "https://hcww.net/down/"
        payload["betterstack"]["raw_body"] = "Cloudflare 523 origin unreachable"
        inspecting_cloudflare = InspectingCloudflareClient(self.app)
        self.remediation.cloudflare = inspecting_cloudflare

        status_code, body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )

        self.assertEqual(status_code, 202)
        self.assertTrue(inspecting_cloudflare.started_before_mutation)
        self.assertEqual(body["incident"]["action_attempts"][0]["status"], "verified")

    def test_remediation_exception_leaves_failed_attempt_record(self) -> None:
        settings = Settings(
            host="127.0.0.1",
            port=8787,
            db_path=os.path.join(self.temp_dir.name, "failed_action.db"),
            env="test",
            service_name="hcww",
            actor_email="incident-agent@hcww.local",
            public_base_url="https://agent.example.com",
            workflow_shared_secret="test-secret",
            admin_shared_secret="admin-secret",
            teams_post_mode="workflow",
            teams_webhook_url="",
            smoke_check_url="",
            smoke_check_expected_text="Hill Country Web Works",
            max_remediation_attempts=1,
            enable_cache_purge=True,
            enable_redeploy=False,
        )
        diagnostics = DiagnosticEngine(
            settings=settings,
            fetch=self.fake_fetch,
            resolve=self.fake_resolve,
        )
        remediation = RemediationEngine(
            settings=settings,
            diagnostics=diagnostics,
            cloudflare=RaisingCloudflareClient(),
            deploy=FakeDeployClient(),
        )
        app = IncidentAgentApplication(
            settings=settings,
            diagnostics=diagnostics,
            notifier=TeamsNotifier(settings=settings),
            remediation=remediation,
            logger=StructuredLogger(stream=io.StringIO()),
        )
        remediation.store = app.store
        payload = self.load_fixture("edge_down.json")
        payload["betterstack"]["monitor_url"] = "https://hcww.net/down/"
        payload["betterstack"]["raw_body"] = "Cloudflare 523 origin unreachable"

        status_code, body = app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )

        self.assertEqual(status_code, 202)
        persisted = app.get_incident(body["incident"]["incident_id"])
        self.assertIsNotNone(persisted)
        assert persisted is not None
        attempt = persisted["action_attempts"][0]
        self.assertEqual(attempt["status"], "failed")
        self.assertEqual(attempt["error"], "Cloudflare API unavailable")
        self.assertIn("Cloudflare API unavailable", attempt["result"]["reason"])

    def test_webhook_escalates_when_dns_fails(self) -> None:
        payload = self.load_fixture("dns_failure.json")
        payload["betterstack"]["monitor_url"] = "https://hcww.net/"
        self.diagnostics.resolve = lambda hostname: (_ for _ in ()).throw(
            RuntimeError("Name or service not known")
        )

        status_code, body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )

        self.assertEqual(status_code, 202)
        self.assertEqual(body["incident"]["current_status"], "escalated")
        self.assertEqual(len(body["incident"]["action_attempts"]), 0)
        metrics = self.app.metrics.snapshot()
        self.assertEqual(metrics["diagnostics.escalated"], 1)
        self.assertEqual(metrics["incident.escalated"], 1)
        final_message = self.notifier.sent_messages[-1]["payload"]
        self.assertIn("Next step:", final_message["message"])
        self.assertIn("operator_guidance", final_message["details"])
        self.assertIn(
            "Cloudflare DNS",
            final_message["details"]["operator_guidance"]["recommended_next_step"],
        )
        audit = self.app.get_incident_audit(body["incident"]["incident_id"])
        self.assertIsNotNone(audit)
        assert audit is not None
        escalated_events = [
            event
            for event in audit["audit_events"]
            if event["event_type"] == "incident.escalated"
        ]
        self.assertIn("operator_guidance", escalated_events[-1]["details"])

    def test_remediation_kill_switch_escalates_without_mutation(self) -> None:
        settings = Settings(
            host="127.0.0.1",
            port=8787,
            db_path=os.path.join(self.temp_dir.name, "kill_switch_incident.db"),
            env="test",
            service_name="hcww",
            actor_email="incident-agent@hcww.local",
            public_base_url="https://agent.example.com",
            workflow_shared_secret="test-secret",
            admin_shared_secret="admin-secret",
            teams_post_mode="workflow",
            teams_webhook_url="",
            smoke_check_url="",
            smoke_check_expected_text="Hill Country Web Works",
            remediation_disabled=True,
            max_remediation_attempts=2,
            enable_cache_purge=True,
            enable_redeploy=True,
        )
        cloudflare = FakeCloudflareClient()
        deploy = FakeDeployClient()
        diagnostics = DiagnosticEngine(
            settings=settings,
            fetch=self.fake_fetch,
            resolve=self.fake_resolve,
        )
        remediation = RemediationEngine(
            settings=settings,
            diagnostics=diagnostics,
            cloudflare=cloudflare,
            deploy=deploy,
        )
        app = IncidentAgentApplication(
            settings=settings,
            diagnostics=diagnostics,
            notifier=TeamsNotifier(settings=settings),
            remediation=remediation,
            logger=StructuredLogger(stream=io.StringIO()),
        )
        remediation.store = app.store
        payload = self.load_fixture("edge_down.json")
        payload["betterstack"]["monitor_url"] = "https://hcww.net/down/"
        payload["betterstack"]["raw_body"] = "Cloudflare 523 origin unreachable"

        status_code, body = app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )

        self.assertEqual(status_code, 202)
        self.assertEqual(body["incident"]["current_status"], "escalated")
        self.assertEqual(body["incident"]["action_attempts"], [])
        self.assertEqual(cloudflare.calls, [])
        self.assertEqual(deploy.calls, 0)
        audit = app.get_incident_audit(body["incident"]["incident_id"])
        self.assertIsNotNone(audit)
        assert audit is not None
        escalated = [
            event
            for event in audit["audit_events"]
            if event["event_type"] == "incident.escalated"
        ]
        self.assertEqual(
            escalated[-1]["details"]["reason"],
            "Global remediation kill switch is enabled",
        )
        self.assertIn("operator_guidance", escalated[-1]["details"])

    def test_retention_preview_reports_without_deleting_rows(self) -> None:
        payload = self.load_fixture("edge_down.json")
        _status_code, body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )
        incident_id = body["incident"]["incident_id"]
        self.app.store.record_action_attempt(
            incident_id=incident_id,
            playbook_name="manual_check",
            action_type="noop",
            inputs={},
            result={"ok": True},
            verification={"outcome_status": "resolved"},
        )
        self.age_incident_rows(incident_id, "2026-01-01T00:00:00Z")

        preview = self.app.store.cleanup_retention(
            retention_days=30,
            apply=False,
            now=datetime(2026, 7, 21, tzinfo=timezone.utc),
        )

        self.assertFalse(preview["applied"])
        self.assertEqual(preview["counts"]["incidents"], 1)
        self.assertEqual(preview["counts"]["action_attempts"], 1)
        self.assertGreater(preview["counts"]["audit_events"], 0)
        self.assertIsNotNone(self.app.get_incident(incident_id))
        self.assertEqual(self.count_rows("action_attempts"), 1)

    def test_retention_apply_deletes_old_terminal_incidents_child_first(self) -> None:
        payload = self.load_fixture("edge_down.json")
        _status_code, body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )
        incident_id = body["incident"]["incident_id"]
        self.app.store.record_action_attempt(
            incident_id=incident_id,
            playbook_name="manual_check",
            action_type="noop",
            inputs={},
            result={"ok": True},
            verification={"outcome_status": "resolved"},
        )
        self.age_incident_rows(incident_id, "2026-01-01T00:00:00Z")

        result = self.app.store.cleanup_retention(
            retention_days=30,
            apply=True,
            now=datetime(2026, 7, 21, tzinfo=timezone.utc),
        )

        self.assertTrue(result["applied"])
        self.assertEqual(result["counts"]["incidents"], 1)
        self.assertEqual(self.count_rows("action_attempts"), 0)
        self.assertEqual(self.count_rows("audit_events"), 0)
        self.assertEqual(self.count_rows("incidents"), 0)

    def test_retention_preserves_recent_and_active_incidents(self) -> None:
        recent_payload = self.load_fixture("edge_down.json")
        recent_payload["event_id"] = "evt_recent_retention"
        recent_payload["betterstack"]["alert_id"] = "alert-recent-retention"
        recent_payload["betterstack"]["incident_id"] = "incident-recent-retention"
        _recent_status, recent_body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(recent_payload).encode("utf-8"),
        )
        active_payload = self.load_fixture("edge_down.json")
        active_payload["event_id"] = "evt_active_retention"
        active_payload["betterstack"]["alert_id"] = "alert-active-retention"
        active_payload["betterstack"]["incident_id"] = "incident-active-retention"
        _active_status, active_body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(active_payload).encode("utf-8"),
        )
        active_id = active_body["incident"]["incident_id"]
        with self.app.store._connect() as connection:
            connection.execute(
                """
                UPDATE incidents
                SET current_status = 'remediating',
                    created_at = ?,
                    updated_at = ?,
                    resolved_at = NULL
                WHERE incident_id = ?
                """,
                ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", active_id),
            )

        result = self.app.store.cleanup_retention(
            retention_days=30,
            apply=True,
            now=datetime(2026, 7, 21, tzinfo=timezone.utc),
        )

        self.assertEqual(result["counts"]["incidents"], 0)
        self.assertIsNotNone(self.app.get_incident(recent_body["incident"]["incident_id"]))
        self.assertIsNotNone(self.app.get_incident(active_id))

    def test_retention_cli_previews_by_default(self) -> None:
        output = io.StringIO()

        with redirect_stdout(output):
            exit_code = retention_main(
                [
                    "--db-path",
                    os.path.join(self.temp_dir.name, "retention_cli.db"),
                    "--retention-days",
                    "30",
                ]
            )

        body = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertFalse(body["retention"]["applied"])
        self.assertEqual(body["retention"]["retention_days"], 30)

    def test_webhook_redeploys_when_cache_purge_does_not_recover(self) -> None:
        payload = self.load_fixture("edge_down.json")
        payload["betterstack"]["monitor_url"] = "https://hcww.net/redeploy-fail/"
        payload["betterstack"]["raw_body"] = "Cloudflare 523 origin unreachable"

        status_code, body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )

        self.assertEqual(status_code, 202)
        self.assertEqual(body["incident"]["current_status"], "escalated")
        self.assertEqual(len(body["incident"]["action_attempts"]), 2)
        self.assertEqual(body["incident"]["action_attempts"][0]["playbook_name"], "cloudflare_cache_purge")
        self.assertEqual(body["incident"]["action_attempts"][1]["playbook_name"], "known_good_redeploy")
        self.assertEqual(len(self.cloudflare.calls), 1)
        self.assertEqual(self.deploy.calls, 1)

    def test_remediation_records_action_and_verification_status_separately(self) -> None:
        payload = self.load_fixture("edge_down.json")
        payload["betterstack"]["monitor_url"] = "https://hcww.net/redeploy-fail/"
        payload["betterstack"]["raw_body"] = "Cloudflare 523 origin unreachable"

        status_code, body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )

        self.assertEqual(status_code, 202)
        attempts = body["incident"]["action_attempts"]
        self.assertEqual(attempts[0]["result"]["action_status"], "succeeded")
        self.assertEqual(attempts[0]["verification"]["verification_status"], "escalated")
        self.assertEqual(attempts[0]["status"], "succeeded")

    def test_duplicate_event_is_ignored(self) -> None:
        payload = self.load_fixture("edge_down.json")
        first_status, first_body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )
        second_status, second_body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )

        self.assertEqual(first_status, 202)
        self.assertEqual(second_status, 202)
        self.assertTrue(second_body["duplicate"])
        self.assertIsNone(second_body["classification"])
        self.assertEqual(second_body["incident"]["incident_id"], first_body["incident"]["incident_id"])
        self.assertEqual(len(self.notifier.sent_messages), 3)
        self.assertEqual(self.fetch_calls, {"https://hcww.net/": 1})

        audit_lookup = self.app.get_incident_audit(first_body["incident"]["incident_id"])
        duplicate_events = [
            event
            for event in audit_lookup["audit_events"]
            if event["event_type"] == "incident.duplicate_ignored"
        ]
        diagnostics_events = [
            event
            for event in audit_lookup["audit_events"]
            if event["event_type"] == "incident.diagnostics_completed"
        ]
        self.assertEqual(len(duplicate_events), 1)
        self.assertEqual(len(diagnostics_events), 1)
        metrics = self.app.handle_admin_metrics(
            headers={"X-HCWW-Admin-Secret": "admin-secret"}
        )["metrics"]
        self.assertEqual(metrics["webhook.accepted"], 2)
        self.assertEqual(metrics["incident.duplicate"], 1)

    def test_concurrent_duplicate_event_is_processed_once(self) -> None:
        payload = self.load_fixture("edge_down.json")
        encoded = json.dumps(payload).encode("utf-8")

        def submit() -> tuple[int, dict]:
            return self.app.handle_webhook(
                headers={"X-HCWW-Workflow-Secret": "test-secret"},
                body=encoded,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: submit(), range(2)))

        statuses = [status for status, _body in results]
        bodies = [body for _status, body in results]
        duplicate_count = sum(1 for body in bodies if body.get("duplicate"))
        processed_count = sum(1 for body in bodies if not body.get("duplicate"))
        incident_ids = {body["incident"]["incident_id"] for body in bodies}

        self.assertEqual(statuses, [202, 202])
        self.assertEqual(duplicate_count, 1)
        self.assertEqual(processed_count, 1)
        self.assertEqual(len(incident_ids), 1)
        self.assertEqual(len(self.notifier.sent_messages), 3)
        self.assertEqual(self.fetch_calls, {"https://hcww.net/": 1})

    def test_repeated_incident_with_recent_attempts_hits_cooldown(self) -> None:
        payload = self.load_fixture("edge_down.json")
        payload["event_id"] = "evt_repeat_1"
        payload["betterstack"]["incident_id"] = "incident-repeat"
        payload["betterstack"]["monitor_url"] = "https://hcww.net/redeploy-fail/"
        payload["betterstack"]["raw_body"] = "Cloudflare 523 origin unreachable"
        _, first_body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(payload).encode("utf-8"),
        )

        repeated = json.loads(json.dumps(payload))
        repeated["event_id"] = "evt_repeat_2"
        repeated["delivered_at"] = "2026-07-18T12:35:56Z"
        repeated["betterstack"]["alert_id"] = "alert-repeat-2"
        _, second_body = self.app.handle_webhook(
            headers={"X-HCWW-Workflow-Secret": "test-secret"},
            body=json.dumps(repeated).encode("utf-8"),
        )

        self.assertEqual(first_body["incident"]["current_status"], "escalated")
        self.assertEqual(second_body["incident"]["current_status"], "escalated")
        self.assertEqual(len(second_body["incident"]["action_attempts"]), 2)
        self.assertEqual(self.deploy.calls, 1)

    def test_real_cloudflare_client_builds_expected_request(self) -> None:
        captured = {}

        def fake_sender(method: str, url: str, headers: dict, payload: dict) -> dict:
            captured["method"] = method
            captured["url"] = url
            captured["headers"] = headers
            captured["payload"] = payload
            return {
                "success": True,
                "result": {"id": "purge-123"},
                "errors": [],
                "messages": [],
                "_http_status": 200,
            }

        client = RealCloudflareClient(
            api_base_url="https://api.cloudflare.com/client/v4",
            api_token="cf-token",
            zone_id="zone-123",
            sender=fake_sender,
        )

        result = client.purge_cache(["https://hcww.net/", "https://hcww.net/contact/"])

        self.assertTrue(result["ok"])
        self.assertEqual(
            captured["url"],
            "https://api.cloudflare.com/client/v4/zones/zone-123/purge_cache",
        )
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["payload"]["files"], ["https://hcww.net/", "https://hcww.net/contact/"])
        self.assertEqual(captured["headers"]["Authorization"], "Bearer cf-token")

    def test_build_cloudflare_client_uses_null_without_credentials(self) -> None:
        settings = Settings(
            host="127.0.0.1",
            port=8787,
            db_path=self.db_path,
            env="test",
            service_name="hcww",
            actor_email="incident-agent@hcww.local",
            public_base_url="https://agent.example.com",
            workflow_shared_secret="test-secret",
            cloudflare_api_token="",
            cloudflare_zone_id="",
        )
        client = build_cloudflare_client(settings)
        result = client.purge_cache(["https://hcww.net/"])

        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "cloudflare client not configured")

    def test_real_deploy_client_builds_expected_request(self) -> None:
        captured = {}

        def fake_sender(method: str, url: str, headers: dict, payload: dict) -> dict:
            captured["method"] = method
            captured["url"] = url
            captured["headers"] = headers
            captured["payload"] = payload
            return {
                "success": True,
                "result": {"deployment_id": "dep-123"},
                "errors": [],
                "messages": [],
                "_http_status": 202,
            }

        client = RealDeployClient(
            base_url="https://deploy.example.com/hooks/redeploy",
            api_token="deploy-token",
            mode="api",
            sender=fake_sender,
        )
        incident = {
            "incident_id": 42,
            "external_incident_key": "incident-42",
            "incident_type": "edge",
            "normalized_severity": "sev1",
            "betterstack": {
                "monitor_url": "https://hcww.net/",
                "monitor_name": "hcww homepage",
            },
        }

        result = client.trigger_redeploy(incident)

        self.assertTrue(result["ok"])
        self.assertEqual(captured["url"], "https://deploy.example.com/hooks/redeploy")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["headers"]["Authorization"], "Bearer deploy-token")
        self.assertEqual(captured["payload"]["action"], "redeploy")
        self.assertEqual(captured["payload"]["incident"]["incident_id"], 42)
        self.assertEqual(result["http_status"], 202)
        self.assertEqual(result["action_status"], "succeeded")
        self.assertEqual(result["success_signal"], "success_true")

    def test_real_deploy_client_requires_explicit_success_for_api_mode(self) -> None:
        def fake_sender(method: str, url: str, headers: dict, payload: dict) -> dict:
            return {
                "result": {"deployment_id": "dep-ambiguous"},
                "errors": [],
                "messages": [],
                "_http_status": 202,
            }

        client = RealDeployClient(
            base_url="https://deploy.example.com/hooks/redeploy",
            api_token="deploy-token",
            mode="api",
            sender=fake_sender,
        )
        incident = {
            "incident_id": 43,
            "external_incident_key": "incident-43",
            "incident_type": "edge",
            "normalized_severity": "sev1",
            "betterstack": {
                "monitor_url": "https://hcww.net/",
                "monitor_name": "hcww homepage",
            },
        }

        result = client.trigger_redeploy(incident)

        self.assertFalse(result["ok"])
        self.assertEqual(result["action_status"], "failed")
        self.assertEqual(result["success_signal"], "missing_success_true")
        self.assertEqual(result["reason"], "deploy response missing explicit success=true")

    def test_real_deploy_client_treats_explicit_failure_as_failed(self) -> None:
        def fake_sender(method: str, url: str, headers: dict, payload: dict) -> dict:
            return {
                "success": False,
                "errors": [{"message": "denied"}],
                "messages": [],
                "_http_status": 200,
            }

        client = RealDeployClient(
            base_url="https://deploy.example.com/hooks/redeploy",
            api_token="deploy-token",
            mode="api",
            sender=fake_sender,
        )
        incident = {
            "incident_id": 44,
            "external_incident_key": "incident-44",
            "incident_type": "edge",
            "normalized_severity": "sev1",
            "betterstack": {
                "monitor_url": "https://hcww.net/",
                "monitor_name": "hcww homepage",
            },
        }

        result = client.trigger_redeploy(incident)

        self.assertFalse(result["ok"])
        self.assertEqual(result["action_status"], "failed")
        self.assertEqual(result["reason"], "deploy response did not include success=true")

    def test_real_deploy_hook_client_omits_bearer_auth(self) -> None:
        captured = {}

        def fake_sender(method: str, url: str, headers: dict, payload: dict) -> dict:
            captured["method"] = method
            captured["url"] = url
            captured["headers"] = headers
            captured["payload"] = payload
            return {
                "success": True,
                "result": {"build_uuid": "build-123"},
                "errors": [],
                "messages": [],
                "_http_status": 200,
            }

        client = RealDeployClient(
            base_url="https://api.cloudflare.com/client/v4/pages/webhooks/deploy_hooks/hook-123",
            mode="deploy_hook",
            sender=fake_sender,
        )
        incident = {
            "incident_id": 7,
            "external_incident_key": "incident-7",
            "incident_type": "edge",
            "normalized_severity": "sev1",
            "betterstack": {
                "monitor_url": "https://hcww.net/",
                "monitor_name": "hcww homepage",
            },
        }

        result = client.trigger_redeploy(incident)

        self.assertTrue(result["ok"])
        self.assertNotIn("Authorization", captured["headers"])
        self.assertEqual(result["deploy_mode"], "deploy_hook")
        self.assertEqual(result["success_signal"], "http_2xx")

    def test_build_deploy_client_uses_real_client_with_credentials(self) -> None:
        settings = Settings(
            host="127.0.0.1",
            port=8787,
            db_path=self.db_path,
            env="test",
            service_name="hcww",
            actor_email="incident-agent@hcww.local",
            public_base_url="https://agent.example.com",
            workflow_shared_secret="test-secret",
            deploy_mode="api",
            deploy_base_url="https://deploy.example.com/hooks/redeploy",
            deploy_api_token="deploy-token",
        )
        client = build_deploy_client(settings)
        self.assertEqual(type(client).__name__, "RealDeployClient")

    def test_webhook_notifier_sends_text_payload(self) -> None:
        captured = {}

        def fake_sender(webhook_url: str, payload: dict) -> dict:
            captured["webhook_url"] = webhook_url
            captured["payload"] = payload
            return {"status_code": 202}

        settings = Settings(
            host="127.0.0.1",
            port=8787,
            db_path=self.db_path,
            env="test",
            service_name="hcww",
            actor_email="incident-agent@hcww.local",
            public_base_url="https://agent.example.com",
            workflow_shared_secret="test-secret",
            teams_post_mode="webhook",
            teams_webhook_url="https://workflow.example.test/webhook",
        )
        notifier = TeamsNotifier(settings=settings, webhook_sender=fake_sender)
        incident = {
            "incident_id": 99,
            "external_incident_key": "incident-99",
            "teams": {
                "team_id": "team-1",
                "channel_id": "channel-1",
                "root_message_id": "msg-1",
            },
        }

        result = notifier.send_incident_update(
            incident=incident,
            phase="diagnosis",
            message="TEST incident is being diagnosed.",
            details={"current_status": "diagnosing", "severity": "sev1"},
        )

        self.assertTrue(result["posted"])
        self.assertEqual(captured["webhook_url"], "https://workflow.example.test/webhook")
        self.assertEqual(captured["payload"]["type"], "message")
        self.assertEqual(len(captured["payload"]["attachments"]), 1)
        attachment = captured["payload"]["attachments"][0]
        self.assertEqual(
            attachment["contentType"],
            "application/vnd.microsoft.card.adaptive",
        )
        body = attachment["content"]["body"]
        self.assertEqual(
            captured["payload"]["summary"],
            f"{AGENT_MESSAGE_MARKER} HCWW Incident Agent | DIAGNOSIS",
        )
        self.assertEqual(
            captured["payload"]["text"],
            f"{AGENT_MESSAGE_MARKER} HCWW Incident Agent | DIAGNOSIS",
        )
        self.assertEqual(
            body[0]["text"],
            f"{AGENT_MESSAGE_MARKER} | HCWW Incident Agent | DIAGNOSIS",
        )
        self.assertEqual(body[1]["text"], "TEST incident is being diagnosed.")
        facts = body[2]["facts"]
        self.assertTrue(any(f["title"] == "Severity" and f["value"] == "sev1" for f in facts))

    def test_workflow_notifier_contract_covers_lifecycle_phases(self) -> None:
        settings = Settings(
            host="127.0.0.1",
            port=8787,
            db_path=self.db_path,
            env="test",
            service_name="hcww",
            actor_email="incident-agent@hcww.local",
            public_base_url="https://agent.example.com",
            workflow_shared_secret="test-secret",
            teams_post_mode="workflow",
        )
        notifier = TeamsNotifier(settings=settings)
        incident = {
            "incident_id": 101,
            "external_incident_key": "incident-101",
            "teams": {
                "team_id": "team-1",
                "channel_id": "channel-1",
                "root_message_id": "root-msg",
                "reply_to_message_id": "reply-msg",
            },
        }

        for phase in SUPPORTED_PHASES:
            with self.subTest(phase=phase):
                result = notifier.send_incident_update(
                    incident=incident,
                    phase=phase,
                    message=f"{phase} message",
                    details={"phase": phase},
                )
                payload = result["payload"]

                self.assertFalse(result["posted"])
                self.assertEqual(result["mode"], "workflow")
                self.assertEqual(payload["source"], "hcww_incident_agent")
                self.assertEqual(payload["marker"], AGENT_MESSAGE_MARKER)
                self.assertEqual(payload["phase"], phase)
                self.assertEqual(payload["reply_target_message_id"], "reply-msg")
                self.assertTrue(payload["delivery"]["threaded_reply_required"])
                self.assertEqual(payload["delivery"]["mode"], "workflow")
                self.assertIn(AGENT_MESSAGE_MARKER, payload["text"])
                self.assertEqual(result["raw_payload"], payload)

        self.assertEqual(len(notifier.sent_messages), len(SUPPORTED_PHASES))

    def test_workflow_notifier_uses_root_message_when_reply_target_missing(self) -> None:
        notifier = TeamsNotifier(settings=self.settings)
        incident = {
            "incident_id": 102,
            "external_incident_key": "incident-102",
            "teams": {
                "team_id": "team-1",
                "channel_id": "channel-1",
                "root_message_id": "root-msg",
                "reply_to_message_id": None,
            },
        }

        result = notifier.send_incident_update(
            incident=incident,
            phase="diagnosis",
            message="diagnosis message",
            details={},
        )

        self.assertEqual(result["payload"]["reply_target_message_id"], "root-msg")

    def test_schema_documents_teams_posting_contract(self) -> None:
        schema = self.app.schema_document()

        self.assertEqual(
            schema["teams_posting"]["v1_decision"],
            "workflow_managed_threaded_replies",
        )
        self.assertEqual(schema["teams_posting"]["supported_phases"], SUPPORTED_PHASES)
        self.assertEqual(schema["teams_posting"]["agent_marker"], AGENT_MESSAGE_MARKER)

    def test_build_deploy_client_uses_deploy_hook_without_token(self) -> None:
        settings = Settings(
            host="127.0.0.1",
            port=8787,
            db_path=self.db_path,
            env="test",
            service_name="hcww",
            actor_email="incident-agent@hcww.local",
            public_base_url="https://agent.example.com",
            workflow_shared_secret="test-secret",
            deploy_mode="deploy_hook",
            deploy_base_url="https://api.cloudflare.com/client/v4/pages/webhooks/deploy_hooks/hook-123",
            deploy_api_token="",
        )
        client = build_deploy_client(settings)
        self.assertEqual(type(client).__name__, "RealDeployClient")

    def test_drill_harness_lists_expected_scenarios(self) -> None:
        scenarios = list_scenarios(SCENARIOS.values())
        names = {scenario["name"] for scenario in scenarios}

        self.assertIn("self-recovery", names)
        self.assertIn("dns-failure", names)
        self.assertIn("duplicate-event", names)
        duplicate = next(scenario for scenario in scenarios if scenario["name"] == "duplicate-event")
        self.assertEqual(duplicate["repeat"], 2)

    def test_drill_harness_mutates_failed_redeploy_payload(self) -> None:
        payload = load_payload(SCENARIOS["failed-redeploy"])

        self.assertEqual(payload["event_id"], "evt_drill_redeploy_0001")
        self.assertEqual(payload["betterstack"]["incident_id"], "incident-drill-redeploy-789")
        self.assertEqual(payload["betterstack"]["monitor_url"], "https://hcww.net/redeploy-fail/")

    def test_drill_harness_evaluates_expected_results(self) -> None:
        scenario = SCENARIOS["self-recovery"]
        response = {
            "incident": {
                "current_status": "resolved",
                "action_attempts": [],
            }
        }
        audit = {
            "audit_events": [
                {"event_type": "incident.received"},
                {"event_type": "incident.triaged"},
                {"event_type": "incident.resolved"},
            ]
        }

        checks = evaluate_result(scenario, response, audit)

        self.assertTrue(all(check["ok"] for check in checks))

    def test_drill_harness_reports_missing_audit_secret_for_required_events(self) -> None:
        scenario = SCENARIOS["self-recovery"]
        response = {
            "incident": {
                "current_status": "resolved",
                "action_attempts": [],
            }
        }

        checks = evaluate_result(scenario, response, audit=None)

        audit_check = next(check for check in checks if check["name"] == "audit_available")
        self.assertFalse(audit_check["ok"])
        self.assertIn("--admin-secret", audit_check["hint"])

    def test_drill_harness_builds_payload_file_request(self) -> None:
        payload_file = Path(self.temp_dir.name) / "custom_payload.json"
        payload_file.write_text(json.dumps(validation_example_payload()))

        request = request_from_payload_file(
            payload_file=payload_file,
            expected_status="resolved",
            expected_duplicate=False,
            expected_action_count=0,
            expected_audit_events=["incident.received"],
            repeat=2,
        )

        self.assertEqual(request.name, "custom_payload")
        self.assertEqual(request.payload["event_id"], "evt_20260718_0001")
        self.assertEqual(request.expected_status, "resolved")
        self.assertEqual(request.expected_audit_events, ["incident.received"])
        self.assertEqual(request.repeat, 2)

    def test_drill_harness_replays_payload_file_request_with_fake_http_clients(self) -> None:
        request = request_from_payload_file(
            payload_file=Path(__file__).parent / "fixtures" / "recovery.json",
            expected_status="resolved",
            expected_duplicate=False,
            expected_action_count=0,
            expected_audit_events=["incident.received"],
        )
        calls = {"post": 0, "get": 0}

        def fake_post(url: str, payload: dict, headers: dict, timeout_seconds: float) -> dict:
            calls["post"] += 1
            return {
                "duplicate": False,
                "incident": {
                    "incident_id": 88,
                    "current_status": "resolved",
                    "action_attempts": [],
                },
            }

        def fake_get(url: str, headers: dict, timeout_seconds: float) -> dict:
            calls["get"] += 1
            return {"audit_events": [{"event_type": "incident.received"}]}

        result = run_request(
            request=request,
            agent_url="http://agent.example.test",
            workflow_secret="workflow-secret",
            admin_secret="admin-secret",
            post=fake_post,
            get=fake_get,
        )

        self.assertEqual(calls, {"post": 1, "get": 1})
        self.assertEqual(result["scenario"], "recovery")
        self.assertTrue(all(check["ok"] for check in result["checks"]))

    def test_drill_harness_dry_run_prints_request_without_secret(self) -> None:
        request = request_from_payload_file(
            payload_file=Path(__file__).parent / "fixtures" / "recovery.json",
            expected_status="resolved",
        )

        result = dry_run_request(
            request=request,
            agent_url="http://agent.example.test",
            workflow_secret="super-secret",
        )

        self.assertTrue(result["dry_run"])
        self.assertEqual(result["request"]["method"], "POST")
        self.assertEqual(
            result["request"]["url"],
            "http://agent.example.test/webhooks/teams/betterstack",
        )
        self.assertEqual(
            result["request"]["headers"]["X-HCWW-Workflow-Secret"],
            "[configured]",
        )
        self.assertNotIn("super-secret", json.dumps(result))

    def test_drill_cli_strict_fails_when_payload_file_expectation_fails(self) -> None:
        payload_file = Path(self.temp_dir.name) / "custom_payload.json"
        payload_file.write_text(json.dumps(validation_example_payload()))
        output = io.StringIO()

        with redirect_stdout(output):
            exit_code = drill_main(
                [
                    "--payload-file",
                    str(payload_file),
                    "--expect-audit-event",
                    "incident.received",
                    "--strict",
                ]
            )

        body = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(body["drills"][0]["checks"][0]["name"], "request")

    def test_drill_cli_dry_run_uses_payload_file(self) -> None:
        payload_file = Path(self.temp_dir.name) / "custom_payload.json"
        payload_file.write_text(json.dumps(validation_example_payload()))
        output = io.StringIO()

        with redirect_stdout(output):
            exit_code = drill_main(
                [
                    "--payload-file",
                    str(payload_file),
                    "--expect-status",
                    "resolved",
                    "--dry-run",
                    "--workflow-secret",
                    "super-secret",
                ]
            )

        body = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(body["drills"][0]["dry_run"])
        self.assertEqual(body["drills"][0]["expected"]["current_status"], "resolved")
        self.assertNotIn("super-secret", output.getvalue())

    def test_drill_harness_replays_with_fake_http_clients(self) -> None:
        calls = {"post": 0, "get": 0}

        def fake_post(url: str, payload: dict, headers: dict, timeout_seconds: float) -> dict:
            calls["post"] += 1
            duplicate = calls["post"] == 2
            return {
                "duplicate": duplicate,
                "incident": {
                    "incident_id": 77,
                    "current_status": "resolved",
                    "action_attempts": [],
                },
            }

        def fake_get(url: str, headers: dict, timeout_seconds: float) -> dict:
            calls["get"] += 1
            return {
                "audit_events": [
                    {"event_type": "incident.received"},
                    {"event_type": "incident.duplicate_ignored"},
                ]
            }

        result = run_scenario(
            scenario=SCENARIOS["duplicate-event"],
            agent_url="http://agent.example.test",
            workflow_secret="workflow-secret",
            admin_secret="admin-secret",
            post=fake_post,
            get=fake_get,
        )

        self.assertEqual(calls, {"post": 2, "get": 1})
        self.assertEqual(result["scenario"], "duplicate-event")
        self.assertTrue(result["responses"][-1]["duplicate"])
        self.assertTrue(all(check["ok"] for check in result["checks"]))
