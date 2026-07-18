from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from app.config import Settings


FetchFn = Callable[[str, float], Dict[str, Any]]
ResolveFn = Callable[[str], List[str]]


def default_fetch(url: str, timeout_seconds: float) -> Dict[str, Any]:
    start = time.monotonic()
    request = Request(url, headers={"User-Agent": "hcww-incident-agent/0.1"})
    with urlopen(request, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8", errors="replace")
        latency_ms = int((time.monotonic() - start) * 1000)
        return {
            "ok": 200 <= response.status < 400,
            "status_code": response.status,
            "body_excerpt": body[:500],
            "latency_ms": latency_ms,
        }


def default_resolve(hostname: str) -> List[str]:
    infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    addresses = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses


@dataclass
class DiagnosticEngine:
    settings: Settings
    fetch: FetchFn = default_fetch
    resolve: ResolveFn = default_resolve

    def run(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        monitor_url = incident["betterstack"]["monitor_url"]
        target_url = self.settings.smoke_check_url or monitor_url
        expected_text = self.settings.smoke_check_expected_text
        parsed = urlparse(target_url)
        hostname = parsed.hostname or ""

        dns_result = self._run_dns_check(hostname)
        http_result = self._run_http_check(target_url, expected_text)

        summary = self._build_summary(target_url, dns_result, http_result)
        outcome = self._derive_outcome(incident, dns_result, http_result)
        return {
            "target_url": target_url,
            "hostname": hostname,
            "dns": dns_result,
            "http": http_result,
            "summary": summary,
            "outcome_status": outcome["status"],
            "outcome_reason": outcome["reason"],
        }

    def _run_dns_check(self, hostname: str) -> Dict[str, Any]:
        if not hostname:
            return {"ok": False, "error": "Missing hostname", "addresses": []}
        try:
            addresses = self.resolve(hostname)
            return {"ok": bool(addresses), "addresses": addresses}
        except Exception as exc:  # pragma: no cover - exercised with fake resolver in tests
            return {"ok": False, "error": str(exc), "addresses": []}

    def _run_http_check(self, url: str, expected_text: str) -> Dict[str, Any]:
        try:
            result = self.fetch(url, self.settings.diagnostic_timeout_seconds)
        except Exception as exc:  # pragma: no cover - exercised with fake fetcher in tests
            return {"ok": False, "error": str(exc)}

        body_excerpt = result.get("body_excerpt", "")
        expected_text_present = None
        if expected_text:
            expected_text_present = expected_text in body_excerpt
            result["ok"] = bool(result.get("ok")) and expected_text_present

        result["expected_text_present"] = expected_text_present
        return result

    def _build_summary(
        self, target_url: str, dns_result: Dict[str, Any], http_result: Dict[str, Any]
    ) -> str:
        dns_state = "ok" if dns_result.get("ok") else "failed"
        http_state = "ok" if http_result.get("ok") else "failed"
        return f"Diagnostics for {target_url}: dns={dns_state}, http={http_state}"

    def _derive_outcome(
        self, incident: Dict[str, Any], dns_result: Dict[str, Any], http_result: Dict[str, Any]
    ) -> Dict[str, str]:
        if incident["incident_type"] == "recovery":
            return {"status": "resolved", "reason": "Recovery event from Better Stack"}
        if dns_result.get("ok") and http_result.get("ok"):
            return {"status": "resolved", "reason": "Public checks passed"}
        return {"status": "escalated", "reason": "Diagnostics found unresolved public failure"}
