from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Any, TextIO

from app.redaction import redact_data
from app.store import utc_now_iso


@dataclass
class StructuredLogger:
    stream: TextIO = sys.stdout

    def info(self, event: str, **details: Any) -> None:
        self.emit("info", event, details)

    def warning(self, event: str, **details: Any) -> None:
        self.emit("warning", event, details)

    def error(self, event: str, **details: Any) -> None:
        self.emit("error", event, details)

    def emit(self, level: str, event: str, details: dict[str, Any]) -> None:
        record = {
            "timestamp": utc_now_iso(),
            "level": level,
            "event": event,
            "details": redact_data(details),
        }
        incident_id = details.get("incident_id")
        if incident_id is not None:
            record["incident_id"] = incident_id
        self.stream.write(json.dumps(record, sort_keys=True) + "\n")
        self.stream.flush()
