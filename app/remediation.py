from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.config import Settings
from app.diagnostics import DiagnosticEngine
from app.store import IncidentStore


class CloudflareClient:
    def purge_cache(self, urls: List[str]) -> Dict[str, Any]:
        raise NotImplementedError("Cloudflare cache purge integration is not configured")


class DeployClient:
    def trigger_redeploy(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError("Deploy integration is not configured")


class NullCloudflareClient(CloudflareClient):
    def purge_cache(self, urls: List[str]) -> Dict[str, Any]:
        return {"ok": False, "reason": "cloudflare client not configured", "urls": urls}


class NullDeployClient(DeployClient):
    def trigger_redeploy(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        return {"ok": False, "reason": "deploy client not configured"}


def default_deploy_sender(
    method: str,
    url: str,
    headers: Dict[str, str],
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    request = Request(
        url=url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method=method,
    )
    with urlopen(request, timeout=20) as response:
        body = response.read().decode("utf-8", errors="replace")
        parsed = json.loads(body) if body else {}
        parsed["_http_status"] = response.status
        return parsed


@dataclass
class RealDeployClient(DeployClient):
    base_url: str
    api_token: str = ""
    mode: str = "deploy_hook"
    sender: Any = default_deploy_sender

    def trigger_redeploy(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        if not self.base_url:
            return {"ok": False, "reason": "missing deploy base url"}
        if self.mode != "deploy_hook" and not self.api_token:
            return {"ok": False, "reason": "missing deploy api token"}

        target_url = self.base_url.rstrip("/")
        headers = {"Content-Type": "application/json"}
        if self.mode != "deploy_hook":
            headers["Authorization"] = f"Bearer {self.api_token}"
        payload = {
            "action": "redeploy",
            "service": "hcww",
            "source": "hcww_incident_agent",
            "incident": {
                "incident_id": incident["incident_id"],
                "external_incident_key": incident["external_incident_key"],
                "incident_type": incident["incident_type"],
                "normalized_severity": incident["normalized_severity"],
                "monitor_url": incident["betterstack"]["monitor_url"],
                "monitor_name": incident["betterstack"]["monitor_name"],
            },
        }
        try:
            response = self.sender("POST", target_url, headers, payload)
        except HTTPError as exc:  # pragma: no cover
            return {
                "ok": False,
                "reason": f"deploy http error {exc.code}",
                "target_url": target_url,
            }
        except URLError as exc:  # pragma: no cover
            return {
                "ok": False,
                "reason": f"deploy network error: {exc.reason}",
                "target_url": target_url,
            }
        except Exception as exc:  # pragma: no cover
            return {
                "ok": False,
                "reason": f"deploy request failed: {exc}",
                "target_url": target_url,
            }

        success = bool(response.get("success", True))
        return {
            "ok": success,
            "action": "redeploy",
            "deploy_mode": self.mode,
            "target_url": target_url,
            "deploy_result": response.get("result"),
            "deploy_errors": response.get("errors", []),
            "deploy_messages": response.get("messages", []),
            "http_status": response.get("_http_status"),
        }


def default_cloudflare_sender(
    method: str,
    url: str,
    headers: Dict[str, str],
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    request = Request(
        url=url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method=method,
    )
    with urlopen(request, timeout=15) as response:
        body = response.read().decode("utf-8", errors="replace")
        parsed = json.loads(body) if body else {}
        parsed["_http_status"] = response.status
        return parsed


@dataclass
class RealCloudflareClient(CloudflareClient):
    api_base_url: str
    api_token: str
    zone_id: str
    sender: Any = default_cloudflare_sender

    def purge_cache(self, urls: List[str]) -> Dict[str, Any]:
        if not self.api_token or not self.zone_id:
            return {
                "ok": False,
                "reason": "missing cloudflare token or zone id",
                "urls": urls,
            }

        target_url = f"{self.api_base_url.rstrip('/')}/zones/{self.zone_id}/purge_cache"
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }
        payload = {"files": urls}
        try:
            response = self.sender("POST", target_url, headers, payload)
        except HTTPError as exc:  # pragma: no cover - unit tested via fake sender
            return {
                "ok": False,
                "reason": f"cloudflare http error {exc.code}",
                "urls": urls,
            }
        except URLError as exc:  # pragma: no cover - unit tested via fake sender
            return {
                "ok": False,
                "reason": f"cloudflare network error: {exc.reason}",
                "urls": urls,
            }
        except Exception as exc:  # pragma: no cover - unit tested via fake sender
            return {
                "ok": False,
                "reason": f"cloudflare request failed: {exc}",
                "urls": urls,
            }

        success = bool(response.get("success"))
        return {
            "ok": success,
            "action": "cache_purge",
            "urls": urls,
            "cloudflare_result": response.get("result"),
            "cloudflare_errors": response.get("errors", []),
            "cloudflare_messages": response.get("messages", []),
            "http_status": response.get("_http_status"),
        }


def build_cloudflare_client(settings: Settings) -> CloudflareClient:
    if settings.cloudflare_api_token and settings.cloudflare_zone_id:
        return RealCloudflareClient(
            api_base_url=settings.cloudflare_api_base_url,
            api_token=settings.cloudflare_api_token,
            zone_id=settings.cloudflare_zone_id,
        )
    return NullCloudflareClient()


def build_deploy_client(settings: Settings) -> DeployClient:
    if not settings.enable_redeploy or not settings.deploy_base_url:
        return NullDeployClient()

    if settings.deploy_mode == "deploy_hook":
        return RealDeployClient(
            base_url=settings.deploy_base_url,
            mode="deploy_hook",
        )

    if settings.deploy_api_token:
        return RealDeployClient(
            base_url=settings.deploy_base_url,
            api_token=settings.deploy_api_token,
            mode=settings.deploy_mode,
        )
    return NullDeployClient()


@dataclass
class RemediationEngine:
    settings: Settings
    diagnostics: DiagnosticEngine
    store: Optional[IncidentStore] = None
    cloudflare: Optional[CloudflareClient] = None
    deploy: Optional[DeployClient] = None

    def __post_init__(self) -> None:
        if self.cloudflare is None:
            self.cloudflare = build_cloudflare_client(self.settings)
        if self.deploy is None:
            self.deploy = build_deploy_client(self.settings)

    def plan(self, incident: Dict[str, Any], diagnostics_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if diagnostics_result["outcome_status"] == "resolved":
            return []
        if not diagnostics_result.get("dns", {}).get("ok"):
            return []
        contact_result = diagnostics_result.get("contact")
        if (
            incident["incident_type"] == "contact_path"
            and contact_result is not None
            and contact_result.get("form_action_present") is False
        ):
            return []

        incident_type = incident["incident_type"]
        route = incident["betterstack"]["monitor_url"]
        steps: List[Dict[str, Any]] = []

        if incident_type in {"edge", "availability", "contact_path"} and self.settings.enable_cache_purge:
            maybe_step = self._build_step(
                incident,
                "cloudflare_cache_purge",
                "cache_purge",
                {"urls": [route]},
            )
            if maybe_step:
                steps.append(maybe_step)

        if incident_type in {"edge", "availability"} and self.settings.enable_redeploy:
            maybe_step = self._build_step(
                incident,
                "known_good_redeploy",
                "redeploy",
                {"target": incident["betterstack"]["monitor_url"]},
            )
            if maybe_step:
                steps.append(maybe_step)

        return steps[: self.settings.max_remediation_attempts]

    def execute(
        self, incident: Dict[str, Any], diagnostics_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        steps = self.plan(incident, diagnostics_result)
        if not steps:
            return {
                "attempted": False,
                "resolved": False,
                "reason": "No safe remediation playbook available",
                "steps": [],
                "final_verification": diagnostics_result,
            }

        attempts: List[Dict[str, Any]] = []
        verification = diagnostics_result

        for step in steps:
            action_id = self._start_step_attempt(incident, step)
            action_error = None
            try:
                action_result = self._run_step(incident, step)
            except Exception as exc:  # pragma: no cover - exercised by fake clients in tests
                action_error = str(exc)
                action_result = {
                    "ok": False,
                    "reason": f"remediation action failed: {exc}",
                }
            verification = self.diagnostics.run(incident)
            action_status = self._derive_step_status(action_result, verification)
            if action_id is not None:
                self._complete_step_attempt(
                    action_id=action_id,
                    status=action_status,
                    result=action_result,
                    verification=verification,
                    error=action_error,
                )
            attempts.append(
                {
                    "action_id": action_id,
                    "playbook": step["playbook"],
                    "action_type": step["action_type"],
                    "inputs": step["inputs"],
                    "result": action_result,
                    "verification": verification,
                    "status": action_status,
                    "error": action_error,
                }
            )
            if action_result.get("ok") and verification["outcome_status"] == "resolved":
                return {
                    "attempted": True,
                    "resolved": True,
                    "reason": f"Resolved after {step['playbook']}",
                    "steps": attempts,
                    "final_verification": verification,
                }

        return {
            "attempted": True,
            "resolved": verification["outcome_status"] == "resolved",
            "reason": "Remediation attempts exhausted without verified recovery",
            "steps": attempts,
            "final_verification": verification,
        }

    def _run_step(self, incident: Dict[str, Any], step: Dict[str, Any]) -> Dict[str, Any]:
        if step["action_type"] == "cache_purge":
            assert self.cloudflare is not None
            return self.cloudflare.purge_cache(step["inputs"]["urls"])
        if step["action_type"] == "redeploy":
            assert self.deploy is not None
            return self.deploy.trigger_redeploy(incident)
        return {"ok": False, "reason": f"Unknown action type {step['action_type']}"}

    def _start_step_attempt(
        self, incident: Dict[str, Any], step: Dict[str, Any]
    ) -> Optional[int]:
        if self.store is None:
            return None
        return self.store.start_action_attempt(
            incident_id=incident["incident_id"],
            playbook_name=step["playbook"],
            action_type=step["action_type"],
            inputs=step["inputs"],
        )

    def _complete_step_attempt(
        self,
        action_id: int,
        status: str,
        result: Dict[str, Any],
        verification: Dict[str, Any],
        error: Optional[str],
    ) -> None:
        if self.store is None:
            return
        self.store.complete_action_attempt(
            action_id=action_id,
            status=status,
            result=result,
            verification=verification,
            error=error or (result.get("reason") if not result.get("ok") else None),
        )

    def _derive_step_status(
        self, action_result: Dict[str, Any], verification: Dict[str, Any]
    ) -> str:
        if not action_result.get("ok"):
            return "failed"
        if verification.get("outcome_status") == "resolved":
            return "verified"
        return "succeeded"

    def _build_step(
        self,
        incident: Dict[str, Any],
        playbook: str,
        action_type: str,
        inputs: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if self.store is not None:
            existing_attempts = self.store.count_action_attempts(
                incident_id=incident["incident_id"],
                playbook_name=playbook,
            )
            if existing_attempts >= self.settings.max_playbook_retries:
                return None
        return {
            "playbook": playbook,
            "action_type": action_type,
            "inputs": inputs,
        }
