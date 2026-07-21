from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class IncidentStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._lock:
            with self._connect() as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS incidents (
                      incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                      external_incident_key TEXT NOT NULL UNIQUE,
                      source_system TEXT NOT NULL,
                      source_event_id TEXT NOT NULL,
                      betterstack_alert_id TEXT NOT NULL,
                      betterstack_incident_id TEXT,
                      betterstack_monitor_name TEXT NOT NULL,
                      betterstack_monitor_url TEXT NOT NULL,
                      betterstack_status TEXT NOT NULL,
                      betterstack_alert_type TEXT NOT NULL,
                      betterstack_check_timestamp TEXT NOT NULL,
                      betterstack_severity TEXT,
                      normalized_severity TEXT,
                      incident_type TEXT,
                      current_status TEXT NOT NULL,
                      team_id TEXT NOT NULL,
                      channel_id TEXT NOT NULL,
                      root_message_id TEXT NOT NULL,
                      reply_to_message_id TEXT,
                      raw_payload_json TEXT NOT NULL,
                      created_at TEXT NOT NULL,
                      updated_at TEXT NOT NULL,
                      resolved_at TEXT
                    );

                    CREATE TABLE IF NOT EXISTS audit_events (
                      event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                      incident_id INTEGER NOT NULL,
                      event_type TEXT NOT NULL,
                      summary TEXT NOT NULL,
                      details_json TEXT NOT NULL,
                      created_at TEXT NOT NULL,
                      FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
                    );

                    CREATE TABLE IF NOT EXISTS action_attempts (
                      action_id INTEGER PRIMARY KEY AUTOINCREMENT,
                      incident_id INTEGER NOT NULL,
                      playbook_name TEXT NOT NULL,
                      action_type TEXT NOT NULL,
                      inputs_json TEXT NOT NULL,
                      result_json TEXT NOT NULL,
                      verification_json TEXT NOT NULL,
                      started_at TEXT NOT NULL,
                      completed_at TEXT NOT NULL,
                      FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
                    );

                    CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_source_event_id
                    ON incidents (source_event_id);
                    """
                )

    def health(self) -> Dict[str, str]:
        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()
        return {"database": "ok"}

    def get_incident_by_source_event_id(self, source_event_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE source_event_id = ?",
                (source_event_id,),
            ).fetchone()
            return self._row_to_incident(row) if row else None

    def claim_incident_event(
        self, payload: Dict[str, Any], classification: Dict[str, Any]
    ) -> Dict[str, Any]:
        now = utc_now_iso()
        external_key = payload["external_incident_key"]
        betterstack = payload["betterstack"]
        teams = payload["teams"]
        raw_payload_json = json.dumps(payload["raw_payload"], sort_keys=True)
        normalized_severity = classification["normalized_severity"]
        incident_type = classification["incident_type"]
        current_status = classification["current_status"]

        with self._lock:
            with self._connect() as connection:
                duplicate = connection.execute(
                    """
                    SELECT incident_id
                    FROM incidents
                    WHERE source_event_id = ?
                    """,
                    (payload["event_id"],),
                ).fetchone()
                if duplicate:
                    incident_id = int(duplicate["incident_id"])
                    self._insert_audit_event(
                        connection=connection,
                        incident_id=incident_id,
                        event_type="incident.duplicate_ignored",
                        summary="Duplicate workflow event ignored",
                        details={"event_id": payload["event_id"]},
                        created_at=now,
                    )
                    return {
                        "outcome": "duplicate",
                        "incident": self.get_incident(incident_id, connection=connection),
                    }

                existing = connection.execute(
                    """
                    SELECT incident_id, current_status, created_at
                    FROM incidents
                    WHERE external_incident_key = ?
                    """,
                    (external_key,),
                ).fetchone()

                if existing:
                    connection.execute(
                        """
                        UPDATE incidents
                        SET
                          source_event_id = ?,
                          betterstack_alert_id = ?,
                          betterstack_incident_id = ?,
                          betterstack_monitor_name = ?,
                          betterstack_monitor_url = ?,
                          betterstack_status = ?,
                          betterstack_alert_type = ?,
                          betterstack_check_timestamp = ?,
                          betterstack_severity = ?,
                          normalized_severity = ?,
                          incident_type = ?,
                          current_status = ?,
                          team_id = ?,
                          channel_id = ?,
                          root_message_id = ?,
                          reply_to_message_id = ?,
                          raw_payload_json = ?,
                          updated_at = ?
                        WHERE incident_id = ?
                        """,
                        (
                            payload["event_id"],
                            betterstack["alert_id"],
                            betterstack["incident_id"],
                            betterstack["monitor_name"],
                            betterstack["monitor_url"],
                            betterstack["status"],
                            betterstack["alert_type"],
                            betterstack["check_timestamp"],
                            betterstack["severity"],
                            normalized_severity,
                            incident_type,
                            current_status,
                            teams["team_id"],
                            teams["channel_id"],
                            teams["root_message_id"],
                            teams["reply_to_message_id"],
                            raw_payload_json,
                            now,
                            existing["incident_id"],
                        ),
                    )
                    incident_id = int(existing["incident_id"])
                    created = False
                else:
                    cursor = connection.execute(
                        """
                        INSERT INTO incidents (
                          external_incident_key,
                          source_system,
                          source_event_id,
                          betterstack_alert_id,
                          betterstack_incident_id,
                          betterstack_monitor_name,
                          betterstack_monitor_url,
                          betterstack_status,
                          betterstack_alert_type,
                          betterstack_check_timestamp,
                          betterstack_severity,
                          normalized_severity,
                          incident_type,
                          current_status,
                          team_id,
                          channel_id,
                          root_message_id,
                          reply_to_message_id,
                          raw_payload_json,
                          created_at,
                          updated_at,
                          resolved_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            external_key,
                            payload["source"],
                            payload["event_id"],
                            betterstack["alert_id"],
                            betterstack["incident_id"],
                            betterstack["monitor_name"],
                            betterstack["monitor_url"],
                            betterstack["status"],
                            betterstack["alert_type"],
                            betterstack["check_timestamp"],
                            betterstack["severity"],
                            normalized_severity,
                            incident_type,
                            current_status,
                            teams["team_id"],
                            teams["channel_id"],
                            teams["root_message_id"],
                            teams["reply_to_message_id"],
                            raw_payload_json,
                            now,
                            now,
                            None,
                        ),
                    )
                    incident_id = int(cursor.lastrowid)
                    created = True

                self._insert_audit_event(
                    connection=connection,
                    incident_id=incident_id,
                    event_type="incident.received" if created else "incident.updated",
                    summary="Incident payload stored from Teams workflow",
                    details={
                        "event_id": payload["event_id"],
                        "external_incident_key": external_key,
                        "betterstack_status": betterstack["status"],
                    },
                    created_at=now,
                )

                self._insert_audit_event(
                    connection=connection,
                    incident_id=incident_id,
                    event_type="incident.triaged",
                    summary=classification["summary"],
                    details={
                        "normalized_severity": normalized_severity,
                        "incident_type": incident_type,
                        "current_status": current_status,
                        "signals": classification["signals"],
                        "classifier_version": classification["classifier_version"],
                    },
                    created_at=now,
                )

                return {
                    "outcome": "created" if created else "updated",
                    "incident": self.get_incident(incident_id, connection=connection),
                }

    def upsert_incident(
        self, payload: Dict[str, Any], classification: Dict[str, Any]
    ) -> Dict[str, Any]:
        return self.claim_incident_event(payload, classification)["incident"]

    def transition_incident_status(
        self,
        incident_id: int,
        new_status: str,
        summary: str,
        details: Dict[str, Any],
        resolved: bool = False,
    ) -> Dict[str, Any]:
        now = utc_now_iso()
        resolved_at = now if resolved else None
        with self._lock:
            with self._connect() as connection:
                current = connection.execute(
                    "SELECT current_status FROM incidents WHERE incident_id = ?",
                    (incident_id,),
                ).fetchone()
                if current and current["current_status"] == new_status:
                    return self.get_incident(incident_id, connection=connection)
                connection.execute(
                    """
                    UPDATE incidents
                    SET current_status = ?, updated_at = ?, resolved_at = COALESCE(?, resolved_at)
                    WHERE incident_id = ?
                    """,
                    (new_status, now, resolved_at, incident_id),
                )
                self._insert_audit_event(
                    connection=connection,
                    incident_id=incident_id,
                    event_type=f"incident.{new_status}",
                    summary=summary,
                    details=details,
                    created_at=now,
                )
                return self.get_incident(incident_id, connection=connection)

    def count_action_attempts(
        self,
        incident_id: int,
        playbook_name: Optional[str] = None,
        within_seconds: Optional[int] = None,
    ) -> int:
        query = "SELECT COUNT(*) AS count FROM action_attempts WHERE incident_id = ?"
        params: List[Any] = [incident_id]
        if playbook_name is not None:
            query += " AND playbook_name = ?"
            params.append(playbook_name)
        if within_seconds is not None:
            threshold = (
                datetime.now(timezone.utc) - timedelta(seconds=within_seconds)
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            query += " AND completed_at >= ?"
            params.append(threshold)

        with self._connect() as connection:
            row = connection.execute(query, tuple(params)).fetchone()
            return int(row["count"]) if row else 0

    def add_audit_event(
        self,
        incident_id: int,
        event_type: str,
        summary: str,
        details: Dict[str, Any],
    ) -> None:
        with self._lock:
            with self._connect() as connection:
                self._insert_audit_event(
                    connection=connection,
                    incident_id=incident_id,
                    event_type=event_type,
                    summary=summary,
                    details=details,
                )

    def record_action_attempt(
        self,
        incident_id: int,
        playbook_name: str,
        action_type: str,
        inputs: Dict[str, Any],
        result: Dict[str, Any],
        verification: Dict[str, Any],
    ) -> None:
        now = utc_now_iso()
        with self._lock:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO action_attempts (
                      incident_id,
                      playbook_name,
                      action_type,
                      inputs_json,
                      result_json,
                      verification_json,
                      started_at,
                      completed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        playbook_name,
                        action_type,
                        json.dumps(inputs, sort_keys=True),
                        json.dumps(result, sort_keys=True),
                        json.dumps(verification, sort_keys=True),
                        now,
                        now,
                    ),
                )

    def list_action_attempts(self, incident_id: int) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM action_attempts
                WHERE incident_id = ?
                ORDER BY action_id ASC
                """,
                (incident_id,),
            ).fetchall()
        attempts: List[Dict[str, Any]] = []
        for row in rows:
            attempts.append(
                {
                    "action_id": row["action_id"],
                    "incident_id": row["incident_id"],
                    "playbook_name": row["playbook_name"],
                    "action_type": row["action_type"],
                    "inputs": json.loads(row["inputs_json"]),
                    "result": json.loads(row["result_json"]),
                    "verification": json.loads(row["verification_json"]),
                    "started_at": row["started_at"],
                    "completed_at": row["completed_at"],
                }
            )
        return attempts

    def _insert_audit_event(
        self,
        connection: sqlite3.Connection,
        incident_id: int,
        event_type: str,
        summary: str,
        details: Dict[str, Any],
        created_at: Optional[str] = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO audit_events (incident_id, event_type, summary, details_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                event_type,
                summary,
                json.dumps(details, sort_keys=True),
                created_at or utc_now_iso(),
            ),
        )

    def list_incidents(self) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM incidents
                ORDER BY updated_at DESC, incident_id DESC
                """
            ).fetchall()
            return [self._row_to_incident(row) for row in rows]

    def get_incident(
        self, incident_id: int, connection: Optional[sqlite3.Connection] = None
    ) -> Optional[Dict[str, Any]]:
        if connection is not None:
            row = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            return self._row_to_incident(row) if row else None

        with self._connect() as local_connection:
            row = local_connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            return self._row_to_incident(row) if row else None

    def list_audit_events(self, incident_id: int) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT event_id, incident_id, event_type, summary, details_json, created_at
                FROM audit_events
                WHERE incident_id = ?
                ORDER BY event_id ASC
                """,
                (incident_id,),
            ).fetchall()

        events: List[Dict[str, Any]] = []
        for row in rows:
            events.append(
                {
                    "event_id": row["event_id"],
                    "incident_id": row["incident_id"],
                    "event_type": row["event_type"],
                    "summary": row["summary"],
                    "details": json.loads(row["details_json"]),
                    "created_at": row["created_at"],
                }
            )
        return events

    def _row_to_incident(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "incident_id": row["incident_id"],
            "external_incident_key": row["external_incident_key"],
            "source_system": row["source_system"],
            "source_event_id": row["source_event_id"],
            "betterstack": {
                "alert_id": row["betterstack_alert_id"],
                "incident_id": row["betterstack_incident_id"],
                "monitor_name": row["betterstack_monitor_name"],
                "monitor_url": row["betterstack_monitor_url"],
                "status": row["betterstack_status"],
                "alert_type": row["betterstack_alert_type"],
                "check_timestamp": row["betterstack_check_timestamp"],
                "severity": row["betterstack_severity"],
            },
            "normalized_severity": row["normalized_severity"],
            "incident_type": row["incident_type"],
            "current_status": row["current_status"],
            "teams": {
                "team_id": row["team_id"],
                "channel_id": row["channel_id"],
                "root_message_id": row["root_message_id"],
                "reply_to_message_id": row["reply_to_message_id"],
            },
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "resolved_at": row["resolved_at"],
            "raw_payload": json.loads(row["raw_payload_json"]),
            "action_attempts": self.list_action_attempts(row["incident_id"]),
        }
