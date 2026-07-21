from __future__ import annotations

import threading
from collections import Counter
from typing import Dict


class MetricsCollector:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Counter[str] = Counter()

    def increment(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] += amount

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(sorted(self._counters.items()))

    def summary(self) -> Dict[str, int]:
        counters = self.snapshot()
        return {
            "webhooks_accepted": counters.get("webhook.accepted", 0),
            "webhooks_rejected": _sum_prefix(counters, "webhook.rejected."),
            "duplicates": counters.get("incident.duplicate", 0),
            "diagnostics_resolved": counters.get("diagnostics.resolved", 0),
            "diagnostics_escalated": counters.get("diagnostics.escalated", 0),
            "remediation_attempted": counters.get("remediation.attempted", 0),
            "remediation_succeeded": counters.get("remediation.succeeded", 0),
            "remediation_failed": counters.get("remediation.failed", 0),
            "incidents_escalated": counters.get("incident.escalated", 0),
        }


def _sum_prefix(counters: Dict[str, int], prefix: str) -> int:
    return sum(value for key, value in counters.items() if key.startswith(prefix))
