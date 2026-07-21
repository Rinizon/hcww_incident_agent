# Production Readiness Implementation Spec

## Goal

Move the HCWW incident agent from a hardened release candidate to an operator-friendly production service. The work focuses on observability, operational control, retention, staging drills, and clearer escalation behavior that can be implemented in this repository.

## Step 1: Add Structured JSON Logging

Status: Complete.

- Add a small logging helper that emits JSON records to stdout with timestamp, level, event name, incident ID when available, and redacted details.
- Log webhook acceptance/rejection, duplicate suppression, diagnostic completion, remediation start/completion, escalation, and Teams update queuing.
- Reuse the existing redaction helper before logging details that may include payload fragments, headers, URLs, or action results.
- Add tests for log shape and redaction of sensitive fields.

## Step 2: Add Runtime Metrics and a Metrics Endpoint

Status: Complete.

- Track in-memory counters for incident intake, duplicate events, auth failures, request-policy rejects, URL-policy rejects, diagnostics outcomes, remediation attempts, remediation successes/failures, and escalations.
- Add `GET /metrics` as an admin-secret-protected JSON endpoint.
- Include a compact metrics summary in `/healthz` without exposing sensitive incident data.
- Add tests proving counters increment on success, duplicate, rejection, remediation, and escalation paths.

## Step 3: Add a Global Remediation Kill Switch

- Add `HCWW_REMEDIATION_DISABLED`, defaulting to `false`.
- When enabled, force all mutating playbooks off even if cache purge or redeploy flags are true.
- Show kill-switch state in `/healthz` and schema output.
- Add tests proving remediation is skipped, incidents escalate with a clear reason, and no action attempts are recorded when the switch is active.

## Step 4: Add Incident and Audit Retention Controls

- Add configurable retention settings for resolved/escalated incidents and audit rows, such as `HCWW_RETENTION_DAYS`.
- Implement a store cleanup method that deletes old action attempts, audit events, and incidents in the correct order.
- Add a safe CLI command or tool mode to preview and apply cleanup.
- Add tests for retention cutoff behavior and preservation of recent incidents.

## Step 5: Improve Escalation Guidance

- Add incident-type-specific operator guidance for DNS, edge, availability, contact-path, deploy failure, third-party outage, and unknown incidents.
- Include the recommended next step in Teams update payloads and audit details when an incident escalates.
- Keep messages concise and redacted while still including the strongest diagnostic evidence.
- Add tests for escalation guidance selection by incident type and failure mode.

## Step 6: Extend the Drill Harness for Replay and Staging

- Add a `--payload-file` option to replay a specific fixture or captured redacted payload.
- Add a `--dry-run` or `--print-payload` mode to inspect the outbound request before posting.
- Add stricter validation output for expected incident status, action count, duplicate handling, and required audit events.
- Add tests for payload-file replay, dry-run behavior, and failure reporting.

## Step 7: Document Production Runtime Patterns

- Update `README.md` and `docs/OPERATIONS.md` with structured logs, metrics, kill switch, retention, and replay workflow.
- Add examples for reverse proxy expectations: TLS termination, request timeouts, access logs, and optional source IP restrictions.
- Add a secret rotation runbook for workflow, admin, Cloudflare, and deploy credentials.
- Add a backup/restore drill checklist for the SQLite data volume.

## Validation

- Run `python3 -m unittest discover -s tests` after each implementation step.
- Keep each step independently committable and reversible.
- Confirm `/healthz`, `/schema/webhooks/teams/betterstack`, and any new admin endpoints remain redacted.
- Confirm mutating playbooks stay disabled unless explicitly enabled and not blocked by the kill switch.
