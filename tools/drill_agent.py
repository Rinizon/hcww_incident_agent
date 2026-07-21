#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures"


@dataclass(frozen=True)
class DrillScenario:
    name: str
    description: str
    fixture_name: str
    expected_status: Optional[str]
    expected_duplicate: Optional[bool]
    expected_action_count: Optional[int]
    expected_audit_events: List[str]
    mutation: Optional[Callable[[Dict[str, Any]], None]] = None
    repeat: int = 1


@dataclass(frozen=True)
class DrillRequest:
    name: str
    description: str
    payload: Dict[str, Any]
    expected_status: Optional[str]
    expected_duplicate: Optional[bool]
    expected_action_count: Optional[int]
    expected_audit_events: List[str]
    repeat: int = 1


def _mutate_redeploy_failure(payload: Dict[str, Any]) -> None:
    payload["event_id"] = "evt_drill_redeploy_0001"
    payload["betterstack"]["alert_id"] = "alert-drill-redeploy-789"
    payload["betterstack"]["incident_id"] = "incident-drill-redeploy-789"
    payload["betterstack"]["monitor_url"] = "https://hcww.net/redeploy-fail/"
    payload["betterstack"]["raw_body"] = "Cloudflare 523 origin unreachable"


def _mutate_duplicate(payload: Dict[str, Any]) -> None:
    payload["event_id"] = "evt_drill_duplicate_0001"
    payload["betterstack"]["alert_id"] = "alert-drill-duplicate-789"
    payload["betterstack"]["incident_id"] = "incident-drill-duplicate-789"


SCENARIOS: Dict[str, DrillScenario] = {
    "self-recovery": DrillScenario(
        name="self-recovery",
        description="Better Stack recovery notice should resolve without remediation.",
        fixture_name="recovery.json",
        expected_status="resolved",
        expected_duplicate=False,
        expected_action_count=0,
        expected_audit_events=["incident.received", "incident.triaged", "incident.resolved"],
    ),
    "dns-failure": DrillScenario(
        name="dns-failure",
        description="DNS failure should escalate without mutating playbooks.",
        fixture_name="dns_failure.json",
        expected_status="escalated",
        expected_duplicate=False,
        expected_action_count=0,
        expected_audit_events=["incident.received", "incident.triaged", "incident.escalated"],
    ),
    "contact-down": DrillScenario(
        name="contact-down",
        description="Contact-path alert exercises contact route diagnostics.",
        fixture_name="contact_down.json",
        expected_status=None,
        expected_duplicate=False,
        expected_action_count=None,
        expected_audit_events=["incident.received", "incident.triaged", "incident.diagnostics_completed"],
    ),
    "edge-cache-purge": DrillScenario(
        name="edge-cache-purge",
        description="Edge failure drill for cache purge when diagnostics still fail and purge is enabled.",
        fixture_name="edge_down.json",
        expected_status=None,
        expected_duplicate=False,
        expected_action_count=None,
        expected_audit_events=["incident.received", "incident.triaged", "incident.diagnostics_completed"],
    ),
    "failed-redeploy": DrillScenario(
        name="failed-redeploy",
        description="Persistent edge failure should exhaust enabled mutation attempts and escalate.",
        fixture_name="edge_down.json",
        expected_status="escalated",
        expected_duplicate=False,
        expected_action_count=2,
        expected_audit_events=["incident.remediation_attempted", "incident.escalated"],
        mutation=_mutate_redeploy_failure,
    ),
    "duplicate-event": DrillScenario(
        name="duplicate-event",
        description="Duplicate workflow delivery should be accepted once and ignored on replay.",
        fixture_name="edge_down.json",
        expected_status=None,
        expected_duplicate=True,
        expected_action_count=None,
        expected_audit_events=["incident.duplicate_ignored"],
        mutation=_mutate_duplicate,
        repeat=2,
    ),
}


def load_payload(scenario: DrillScenario, fixture_dir: Path = FIXTURE_DIR) -> Dict[str, Any]:
    payload = json.loads((fixture_dir / scenario.fixture_name).read_text())
    if scenario.mutation is not None:
        scenario.mutation(payload)
    return payload


def load_payload_file(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def request_from_scenario(scenario: DrillScenario) -> DrillRequest:
    return DrillRequest(
        name=scenario.name,
        description=scenario.description,
        payload=load_payload(scenario),
        expected_status=scenario.expected_status,
        expected_duplicate=scenario.expected_duplicate,
        expected_action_count=scenario.expected_action_count,
        expected_audit_events=scenario.expected_audit_events,
        repeat=scenario.repeat,
    )


def request_from_payload_file(
    payload_file: Path,
    expected_status: Optional[str] = None,
    expected_duplicate: Optional[bool] = None,
    expected_action_count: Optional[int] = None,
    expected_audit_events: Optional[List[str]] = None,
    repeat: int = 1,
) -> DrillRequest:
    return DrillRequest(
        name=payload_file.stem,
        description=f"Replay payload file {payload_file}",
        payload=load_payload_file(payload_file),
        expected_status=expected_status,
        expected_duplicate=expected_duplicate,
        expected_action_count=expected_action_count,
        expected_audit_events=expected_audit_events or [],
        repeat=repeat,
    )


def post_json(
    url: str,
    payload: Dict[str, Any],
    headers: Dict[str, str],
    timeout_seconds: float,
) -> Dict[str, Any]:
    encoded = json.dumps(payload).encode("utf-8")
    request = Request(
        url=url,
        data=encoded,
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8", errors="replace")
        return json.loads(body) if body else {}


def get_json(url: str, headers: Dict[str, str], timeout_seconds: float) -> Dict[str, Any]:
    request = Request(url=url, headers=headers, method="GET")
    with urlopen(request, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8", errors="replace")
        return json.loads(body) if body else {}


def run_scenario(
    scenario: DrillScenario,
    agent_url: str,
    workflow_secret: str,
    admin_secret: str = "",
    timeout_seconds: float = 10,
    post: Callable[[str, Dict[str, Any], Dict[str, str], float], Dict[str, Any]] = post_json,
    get: Callable[[str, Dict[str, str], float], Dict[str, Any]] = get_json,
) -> Dict[str, Any]:
    return run_request(
        request=request_from_scenario(scenario),
        agent_url=agent_url,
        workflow_secret=workflow_secret,
        admin_secret=admin_secret,
        timeout_seconds=timeout_seconds,
        post=post,
        get=get,
    )


def run_request(
    request: DrillRequest,
    agent_url: str,
    workflow_secret: str,
    admin_secret: str = "",
    timeout_seconds: float = 10,
    post: Callable[[str, Dict[str, Any], Dict[str, str], float], Dict[str, Any]] = post_json,
    get: Callable[[str, Dict[str, str], float], Dict[str, Any]] = get_json,
) -> Dict[str, Any]:
    webhook_url = urljoin(agent_url.rstrip("/") + "/", "webhooks/teams/betterstack")
    headers = {"X-HCWW-Workflow-Secret": workflow_secret} if workflow_secret else {}
    responses = []

    for _ in range(request.repeat):
        responses.append(post(webhook_url, request.payload, headers, timeout_seconds))

    final_response = responses[-1]
    incident = final_response.get("incident") or {}
    audit = None
    if admin_secret and incident.get("incident_id"):
        audit_url = urljoin(
            agent_url.rstrip("/") + "/",
            f"incidents/{incident['incident_id']}/audit",
        )
        audit = get(audit_url, {"X-HCWW-Admin-Secret": admin_secret}, timeout_seconds)

    return {
        "scenario": request.name,
        "description": request.description,
        "expected": request_expected(request),
        "responses": responses,
        "final_incident": incident,
        "audit": audit,
        "checks": evaluate_request_result(request, final_response, audit),
    }


def scenario_expected(scenario: DrillScenario) -> Dict[str, Any]:
    return request_expected(request_from_scenario(scenario))


def request_expected(request: DrillRequest) -> Dict[str, Any]:
    return {
        "current_status": request.expected_status,
        "duplicate": request.expected_duplicate,
        "action_attempt_count": request.expected_action_count,
        "audit_events": request.expected_audit_events,
    }


def evaluate_result(
    scenario: DrillScenario,
    response: Dict[str, Any],
    audit: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    return evaluate_request_result(request_from_scenario(scenario), response, audit)


def evaluate_request_result(
    request: DrillRequest,
    response: Dict[str, Any],
    audit: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    incident = response.get("incident") or {}
    checks = []
    if request.expected_status is not None:
        checks.append(
            {
                "name": "current_status",
                "expected": request.expected_status,
                "actual": incident.get("current_status"),
                "ok": incident.get("current_status") == request.expected_status,
            }
        )
    if request.expected_duplicate is not None:
        actual_duplicate = bool(response.get("duplicate"))
        checks.append(
            {
                "name": "duplicate",
                "expected": request.expected_duplicate,
                "actual": actual_duplicate,
                "ok": actual_duplicate == request.expected_duplicate,
            }
        )
    if request.expected_action_count is not None:
        action_count = len(incident.get("action_attempts") or [])
        checks.append(
            {
                "name": "action_attempt_count",
                "expected": request.expected_action_count,
                "actual": action_count,
                "ok": action_count == request.expected_action_count,
            }
        )
    if audit is None and request.expected_audit_events:
        checks.append(
            {
                "name": "audit_available",
                "expected": True,
                "actual": False,
                "ok": False,
                "hint": "Provide --admin-secret to verify required audit events.",
            }
        )
    if audit is not None:
        actual_events = [event["event_type"] for event in audit.get("audit_events", [])]
        for expected_event in request.expected_audit_events:
            checks.append(
                {
                    "name": f"audit_event:{expected_event}",
                    "expected": True,
                    "actual": expected_event in actual_events,
                    "ok": expected_event in actual_events,
                }
            )
    return checks


def dry_run_request(request: DrillRequest, agent_url: str, workflow_secret: str) -> Dict[str, Any]:
    webhook_url = urljoin(agent_url.rstrip("/") + "/", "webhooks/teams/betterstack")
    headers = {"Content-Type": "application/json"}
    if workflow_secret:
        headers["X-HCWW-Workflow-Secret"] = "[configured]"
    encoded = json.dumps(request.payload).encode("utf-8")
    headers["Content-Length"] = str(len(encoded))
    return {
        "scenario": request.name,
        "description": request.description,
        "dry_run": True,
        "request": {
            "method": "POST",
            "url": webhook_url,
            "headers": headers,
            "payload": request.payload,
        },
        "expected": request_expected(request),
        "repeat": request.repeat,
    }


def parse_optional_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y"}:
        return True
    if normalized in {"0", "false", "no", "n"}:
        return False
    raise argparse.ArgumentTypeError("expected one of true/false, yes/no, or 1/0")


def list_scenarios(scenarios: Iterable[DrillScenario]) -> List[Dict[str, Any]]:
    return [
        {
            "name": scenario.name,
            "description": scenario.description,
            "fixture": scenario.fixture_name,
            "expected": scenario_expected(scenario),
            "repeat": scenario.repeat,
        }
        for scenario in scenarios
    ]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Replay supervised HCWW incident agent drills.")
    parser.add_argument("--agent-url", default="http://127.0.0.1:8787")
    parser.add_argument("--workflow-secret", default="")
    parser.add_argument("--admin-secret", default="")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), action="append")
    parser.add_argument("--payload-file", type=Path, help="Replay a specific JSON payload file.")
    parser.add_argument("--repeat", type=int, default=1, help="Repeat payload-file replay this many times.")
    parser.add_argument("--expect-status", default=None)
    parser.add_argument("--expect-duplicate", type=parse_optional_bool, default=None)
    parser.add_argument("--expect-action-count", type=int, default=None)
    parser.add_argument("--expect-audit-event", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true", help="Print outbound request details without posting.")
    parser.add_argument("--print-payload", action="store_true", help="Alias for --dry-run.")
    parser.add_argument("--list", action="store_true", help="List available drills and exit.")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when expectations fail.")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args(argv)

    if args.payload_file and args.scenario:
        parser.error("--payload-file cannot be combined with --scenario")
    if args.repeat <= 0:
        parser.error("--repeat must be greater than zero")

    selected = [SCENARIOS[name] for name in (args.scenario or sorted(SCENARIOS))]
    if args.list:
        print(json.dumps({"scenarios": list_scenarios(selected)}, indent=2, sort_keys=True))
        return 0

    if args.payload_file:
        try:
            requests = [
                request_from_payload_file(
                    payload_file=args.payload_file,
                    expected_status=args.expect_status,
                    expected_duplicate=args.expect_duplicate,
                    expected_action_count=args.expect_action_count,
                    expected_audit_events=args.expect_audit_event,
                    repeat=args.repeat,
                )
            ]
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            result = {
                "scenario": args.payload_file.stem,
                "error": str(exc),
                "checks": [{"name": "payload_file", "ok": False, "actual": str(exc)}],
            }
            print(json.dumps({"drills": [result]}, indent=2, sort_keys=True))
            return 1 if args.strict else 0
    else:
        requests = [request_from_scenario(scenario) for scenario in selected]

    if args.dry_run or args.print_payload:
        print(
            json.dumps(
                {
                    "drills": [
                        dry_run_request(request, args.agent_url, args.workflow_secret)
                        for request in requests
                    ]
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    results = []
    failed = False
    for request in requests:
        try:
            result = run_request(
                request=request,
                agent_url=args.agent_url,
                workflow_secret=args.workflow_secret,
                admin_secret=args.admin_secret,
                timeout_seconds=args.timeout,
            )
        except HTTPError as exc:
            result = {
                "scenario": request.name,
                "error": f"HTTP {exc.code}: {exc.reason}",
                "checks": [{"name": "request", "ok": False, "actual": exc.code}],
            }
        except URLError as exc:
            result = {
                "scenario": request.name,
                "error": f"Network error: {exc.reason}",
                "checks": [{"name": "request", "ok": False, "actual": str(exc.reason)}],
            }
        checks = result.get("checks", [])
        failed = failed or any(not check.get("ok") for check in checks)
        results.append(result)

    print(json.dumps({"drills": results}, indent=2, sort_keys=True))
    return 1 if args.strict and failed else 0


if __name__ == "__main__":
    sys.exit(main())
