#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.error import HTTPError
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
    webhook_url = urljoin(agent_url.rstrip("/") + "/", "webhooks/teams/betterstack")
    headers = {"X-HCWW-Workflow-Secret": workflow_secret} if workflow_secret else {}
    responses = []
    payload = load_payload(scenario)

    for _ in range(scenario.repeat):
        responses.append(post(webhook_url, payload, headers, timeout_seconds))

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
        "scenario": scenario.name,
        "description": scenario.description,
        "expected": scenario_expected(scenario),
        "responses": responses,
        "final_incident": incident,
        "audit": audit,
        "checks": evaluate_result(scenario, final_response, audit),
    }


def scenario_expected(scenario: DrillScenario) -> Dict[str, Any]:
    return {
        "current_status": scenario.expected_status,
        "duplicate": scenario.expected_duplicate,
        "action_attempt_count": scenario.expected_action_count,
        "audit_events": scenario.expected_audit_events,
    }


def evaluate_result(
    scenario: DrillScenario,
    response: Dict[str, Any],
    audit: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    incident = response.get("incident") or {}
    checks = []
    if scenario.expected_status is not None:
        checks.append(
            {
                "name": "current_status",
                "expected": scenario.expected_status,
                "actual": incident.get("current_status"),
                "ok": incident.get("current_status") == scenario.expected_status,
            }
        )
    if scenario.expected_duplicate is not None:
        actual_duplicate = bool(response.get("duplicate"))
        checks.append(
            {
                "name": "duplicate",
                "expected": scenario.expected_duplicate,
                "actual": actual_duplicate,
                "ok": actual_duplicate == scenario.expected_duplicate,
            }
        )
    if scenario.expected_action_count is not None:
        action_count = len(incident.get("action_attempts") or [])
        checks.append(
            {
                "name": "action_attempt_count",
                "expected": scenario.expected_action_count,
                "actual": action_count,
                "ok": action_count == scenario.expected_action_count,
            }
        )
    if audit is not None:
        actual_events = [event["event_type"] for event in audit.get("audit_events", [])]
        for expected_event in scenario.expected_audit_events:
            checks.append(
                {
                    "name": f"audit_event:{expected_event}",
                    "expected": True,
                    "actual": expected_event in actual_events,
                    "ok": expected_event in actual_events,
                }
            )
    return checks


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
    parser.add_argument("--list", action="store_true", help="List available drills and exit.")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when expectations fail.")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args(argv)

    selected = [SCENARIOS[name] for name in (args.scenario or sorted(SCENARIOS))]
    if args.list:
        print(json.dumps({"scenarios": list_scenarios(selected)}, indent=2, sort_keys=True))
        return 0

    results = []
    failed = False
    for scenario in selected:
        try:
            result = run_scenario(
                scenario=scenario,
                agent_url=args.agent_url,
                workflow_secret=args.workflow_secret,
                admin_secret=args.admin_secret,
                timeout_seconds=args.timeout,
            )
        except HTTPError as exc:
            result = {
                "scenario": scenario.name,
                "error": f"HTTP {exc.code}: {exc.reason}",
                "checks": [{"name": "request", "ok": False, "actual": exc.code}],
            }
        checks = result.get("checks", [])
        failed = failed or any(not check.get("ok") for check in checks)
        results.append(result)

    print(json.dumps({"drills": results}, indent=2, sort_keys=True))
    return 1 if args.strict and failed else 0


if __name__ == "__main__":
    sys.exit(main())
