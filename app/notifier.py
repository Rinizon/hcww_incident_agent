from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen

from app.config import Settings

AGENT_MESSAGE_MARKER = "HCWW_AGENT_AUTOMATION"
SUPPORTED_PHASES = [
    "acknowledged",
    "diagnosis",
    "remediation_started",
    "verifying",
    "remediation_completed",
    "resolved",
    "escalated",
]


def default_webhook_sender(webhook_url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    request = Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        return {"status_code": response.status}


def _stringify_detail_value(value: Any) -> str:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return str(value)
    return json.dumps(value, sort_keys=True)


def _format_title_case(key: str) -> str:
    return key.replace("_", " ").title()


@dataclass
class TeamsNotifier:
    settings: Settings
    webhook_sender: Any = default_webhook_sender
    sent_messages: List[Dict[str, Any]] = field(default_factory=list)

    def send_incident_update(
        self,
        incident: Dict[str, Any],
        phase: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        details = details or {}
        payload = {
            "source": "hcww_incident_agent",
            "marker": AGENT_MESSAGE_MARKER,
            "phase": phase,
            "message": message,
            "details": details,
            "teams": incident["teams"],
            "incident_id": incident["incident_id"],
            "external_incident_key": incident["external_incident_key"],
        }
        workflow_payload = self._build_workflow_message(payload)
        webhook_payload = workflow_payload
        if self.settings.teams_post_mode == "webhook":
            webhook_payload = self._build_webhook_message(workflow_payload)

        result = {
            "mode": self.settings.teams_post_mode,
            "posted": False,
            "payload": webhook_payload,
            "raw_payload": workflow_payload,
        }

        if self.settings.teams_post_mode == "webhook" and self.settings.teams_webhook_url:
            response = self.webhook_sender(self.settings.teams_webhook_url, webhook_payload)
            result["posted"] = True
            result["response"] = response

        self.sent_messages.append(result)
        return result

    def _build_workflow_message(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        phase_label = payload["phase"].upper().replace("_", " ")
        teams = payload["teams"]
        return {
            **payload,
            "phase_label": phase_label,
            "title": f"HCWW Incident Agent | {phase_label}",
            "text": f"{AGENT_MESSAGE_MARKER} | HCWW Incident Agent | {phase_label}\n{payload['message']}",
            "reply_target_message_id": teams.get("reply_to_message_id") or teams.get("root_message_id"),
            "delivery": {
                "mode": "workflow",
                "threaded_reply_required": True,
                "team_id": teams.get("team_id"),
                "channel_id": teams.get("channel_id"),
                "root_message_id": teams.get("root_message_id"),
                "reply_to_message_id": teams.get("reply_to_message_id"),
            },
        }

    def _build_webhook_message(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        phase = payload["phase"].upper().replace("_", " ")
        details = payload.get("details") or {}
        prioritized_keys = [
            "normalized_severity",
            "current_status",
            "outcome_status",
            "incident_type",
            "target_url",
            "outcome_reason",
        ]
        facts = [
            {"title": "Incident ID", "value": str(payload["incident_id"])},
            {"title": "External Key", "value": str(payload["external_incident_key"])},
        ]
        seen = set()
        for key in prioritized_keys:
            if key in details:
                facts.append({"title": _format_title_case(key), "value": _stringify_detail_value(details[key])})
                seen.add(key)
        for key in sorted(details.keys()):
            if key in seen:
                continue
            facts.append({"title": _format_title_case(key), "value": _stringify_detail_value(details[key])})

        return {
            "type": "message",
            "summary": f"{AGENT_MESSAGE_MARKER} HCWW Incident Agent | {phase}",
            "text": f"{AGENT_MESSAGE_MARKER} HCWW Incident Agent | {phase}",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.2",
                        "body": [
                            {
                                "type": "TextBlock",
                                "weight": "Bolder",
                                "size": "Medium",
                                "text": f"{AGENT_MESSAGE_MARKER} | HCWW Incident Agent | {phase}",
                                "wrap": True,
                            },
                            {
                                "type": "TextBlock",
                                "text": payload["message"],
                                "wrap": True,
                            },
                            {
                                "type": "FactSet",
                                "facts": facts,
                            },
                        ],
                    },
                }
            ],
        }
