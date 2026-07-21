from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
from urllib.error import HTTPError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from app.config import Settings
from app.url_policy import URLPolicyError, validate_public_url


FetchFn = Callable[[str, float], Dict[str, Any]]
ResolveFn = Callable[[str], List[str]]


def default_fetch(url: str, timeout_seconds: float) -> Dict[str, Any]:
    start = time.monotonic()
    request = Request(url, headers={"User-Agent": "hcww-incident-agent/0.1"})
    try:
        response = urlopen(request, timeout=timeout_seconds)
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        latency_ms = int((time.monotonic() - start) * 1000)
        return {
            "ok": False,
            "status_code": exc.code,
            "final_url": exc.geturl(),
            "headers": dict(exc.headers.items()),
            "body_excerpt": body[:2000],
            "latency_ms": latency_ms,
        }

    with response:
        body = response.read().decode("utf-8", errors="replace")
        latency_ms = int((time.monotonic() - start) * 1000)
        return {
            "ok": 200 <= response.status < 400,
            "status_code": response.status,
            "final_url": response.geturl(),
            "headers": dict(response.headers.items()),
            "body_excerpt": body[:2000],
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
        check_urls = self._build_check_urls(target_url)
        policy_error = self._validate_check_urls(monitor_url, check_urls)
        if policy_error:
            return self._policy_blocked_result(target_url, policy_error)

        parsed = urlparse(target_url)
        hostname = parsed.hostname or ""

        dns_result = self._run_dns_check(hostname)
        http_result = self._run_http_check(target_url, expected_text)
        http_checks = [
            {
                "url": url,
                "result": http_result if url == target_url else self._run_http_check(url, expected_text),
            }
            for url in check_urls
        ]
        contact = self._run_contact_checks(monitor_url) if incident["incident_type"] == "contact_path" else None

        summary = self._build_summary(target_url, dns_result, http_result, http_checks, contact)
        outcome = self._derive_outcome(incident, dns_result, http_result, http_checks, contact)
        return {
            "target_url": target_url,
            "hostname": hostname,
            "dns": dns_result,
            "http": http_result,
            "http_checks": http_checks,
            "contact": contact,
            "summary": summary,
            "outcome_status": outcome["status"],
            "outcome_reason": outcome["reason"],
        }

    def _build_check_urls(self, target_url: str) -> List[str]:
        urls = [target_url]
        for raw in self.settings.core_smoke_urls.split(","):
            url = raw.strip()
            if url and url not in urls:
                urls.append(url)
        return urls

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
            validate_public_url(
                url,
                self.settings.allowed_public_origin_values,
                "diagnostic url",
            )
        except URLPolicyError as exc:
            return {"ok": False, "error": str(exc)}

        try:
            result = self.fetch(url, self.settings.diagnostic_timeout_seconds)
        except Exception as exc:  # pragma: no cover - exercised with fake fetcher in tests
            return {"ok": False, "error": str(exc)}

        final_url = result.get("final_url")
        if isinstance(final_url, str) and final_url:
            try:
                validate_public_url(
                    final_url,
                    self.settings.allowed_public_origin_values,
                    "diagnostic final_url",
                )
            except URLPolicyError as exc:
                result["ok"] = False
                result["error"] = str(exc)
                return result

        body_excerpt = result.get("body_excerpt", "")
        expected_text_present = None
        if expected_text:
            expected_text_present = expected_text in body_excerpt
            result["ok"] = bool(result.get("ok")) and expected_text_present

        result["expected_text_present"] = expected_text_present
        return result

    def _validate_check_urls(self, monitor_url: str, check_urls: List[str]) -> Optional[str]:
        try:
            validate_public_url(
                monitor_url,
                self.settings.allowed_public_origin_values,
                "incident monitor_url",
            )
            for index, url in enumerate(check_urls, start=1):
                validate_public_url(
                    url,
                    self.settings.allowed_public_origin_values,
                    f"diagnostic check url {index}",
                )
        except URLPolicyError as exc:
            return str(exc)
        return None

    def _policy_blocked_result(self, target_url: str, reason: str) -> Dict[str, Any]:
        summary = f"Diagnostics blocked by URL policy for {target_url}: {reason}"
        return {
            "target_url": target_url,
            "hostname": "",
            "dns": {"ok": False, "error": reason, "addresses": []},
            "http": {"ok": False, "error": reason},
            "http_checks": [],
            "contact": None,
            "summary": summary,
            "outcome_status": "escalated",
            "outcome_reason": reason,
        }

    def _run_contact_checks(self, monitor_url: str) -> Dict[str, Any]:
        base_url = self._origin_for_url(monitor_url)
        contact_url = urljoin(base_url, "/contact/")
        thanks_url = urljoin(base_url, "/contact/thanks/")
        expected_action = self.settings.contact_form_expected_action
        contact_result = self._run_http_check(contact_url, self.settings.smoke_check_expected_text)
        thanks_result = self._run_http_check(thanks_url, self.settings.smoke_check_expected_text)
        body_excerpt = contact_result.get("body_excerpt", "")
        form_action_present = None
        if expected_action:
            form_action_present = expected_action in body_excerpt

        ok = bool(contact_result.get("ok")) and bool(thanks_result.get("ok"))
        if form_action_present is not None:
            ok = ok and form_action_present

        return {
            "ok": ok,
            "contact_url": contact_url,
            "thanks_url": thanks_url,
            "contact_page": contact_result,
            "thanks_page": thanks_result,
            "expected_form_action": expected_action or None,
            "form_action_present": form_action_present,
        }

    def _origin_for_url(self, url: str) -> str:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return "https://hcww.net"
        return f"{parsed.scheme}://{parsed.netloc}"

    def _build_summary(
        self,
        target_url: str,
        dns_result: Dict[str, Any],
        http_result: Dict[str, Any],
        http_checks: List[Dict[str, Any]],
        contact: Optional[Dict[str, Any]],
    ) -> str:
        dns_state = "ok" if dns_result.get("ok") else "failed"
        http_state = "ok" if http_result.get("ok") else "failed"
        failed_route_count = sum(1 for check in http_checks if not check["result"].get("ok"))
        contact_state = ""
        if contact is not None:
            contact_state = f", contact={'ok' if contact.get('ok') else 'failed'}"
        return (
            f"Diagnostics for {target_url}: dns={dns_state}, http={http_state}, "
            f"failed_routes={failed_route_count}{contact_state}"
        )

    def _derive_outcome(
        self,
        incident: Dict[str, Any],
        dns_result: Dict[str, Any],
        http_result: Dict[str, Any],
        http_checks: List[Dict[str, Any]],
        contact: Optional[Dict[str, Any]],
    ) -> Dict[str, str]:
        if incident["incident_type"] == "recovery":
            return {"status": "resolved", "reason": "Recovery event from Better Stack"}
        all_http_ok = all(check["result"].get("ok") for check in http_checks)
        contact_ok = contact is None or bool(contact.get("ok"))
        if dns_result.get("ok") and http_result.get("ok") and all_http_ok and contact_ok:
            return {"status": "resolved", "reason": "Public checks passed"}
        if not dns_result.get("ok"):
            return {"status": "escalated", "reason": "DNS checks failed"}
        if not all_http_ok:
            return {"status": "escalated", "reason": "One or more public route checks failed"}
        if not contact_ok:
            return {"status": "escalated", "reason": "Contact-path checks failed"}
        return {"status": "escalated", "reason": "Diagnostics found unresolved public failure"}
