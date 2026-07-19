# HCWW Incident Agent

Auto-remediation agent for `hcww.net`.

## Purpose

The agent receives Better Stack incident alerts, evaluates severity from Better Stack metadata, and attempts safe automated remediation for the HCWW website stack.

## Current Status

Version 1 is currently in specification and design.

See [docs/SPEC.md](/Users/rkane/repos/hcww_incident_agent/docs/SPEC.md) for the working v1 product and technical specification.

## Milestone 1 through 5

Milestones 1 through 5 are implemented as a zero-dependency Python service with SQLite persistence, first-pass Better Stack classification, public diagnostics, Teams update orchestration, initial remediation playbooks, and production hardening controls.

### Available endpoints

- `GET /healthz`
- `GET /schema/webhooks/betterstack/incident`
- `POST /webhooks/betterstack/incident`
- `GET /incidents`
- `GET /incidents/:incident_id`
- `GET /incidents/:incident_id/audit`

Incoming Better Stack payloads are now:

- validated against the webhook contract
- normalized into an incident type
- assigned a first-pass HCWW severity such as `sev1` to `sev4`
- stored in SQLite with triage audit events
- moved through lifecycle states including `diagnosing`, `resolved`, and `escalated`
- checked with initial DNS and HTTP diagnostics
- prepared for Teams updates through the notifier layer
- able to attempt cache purge and redeploy playbooks with verification after each action
- tracked with persisted remediation action attempts and retry-limited playbook execution
- protected by duplicate event suppression, cooldown-based loop prevention, and per-playbook retry limits
- backed by fixture-based end-to-end tests and an operations runbook in [docs/OPERATIONS.md](/Users/rkane/repos/hcww_incident_agent/docs/OPERATIONS.md)
- includes a real Cloudflare cache-purge client for production token and zone wiring
- includes a real deploy client for Cloudflare Pages deploy hooks and bearer-authenticated deployment APIs

### Better Stack intake

Use Better Stack outgoing webhooks with a custom payload template and point them at:

```text
POST /webhooks/betterstack/incident
```

Protect the endpoint with the shared secret configured by:

- `BETTERSTACK_WEBHOOK_SHARED_SECRET`
- `BETTERSTACK_WEBHOOK_SECRET_HEADER`

Recommended Better Stack configuration:

- Trigger type: `Incident webhook`
- Events: `started`, `acknowledged`, `resolved`, and `reopened`
- URL: `https://incident-agent.hcww.net/webhooks/betterstack/incident`
- Header name: match `BETTERSTACK_WEBHOOK_SECRET_HEADER`
- Header value: match `BETTERSTACK_WEBHOOK_SHARED_SECRET`

Recommended custom request body template:

```json
{
  "event_id": "$INCIDENT_ID-$STARTED_AT-$ACKNOWLEDGED_AT-$RESOLVED_AT",
  "source": "betterstack_webhook",
  "delivered_at": "$STARTED_AT",
  "betterstack": {
    "alert_id": "$INCIDENT_ID",
    "incident_id": "$INCIDENT_ID",
    "monitor_name": "$NAME",
    "monitor_url": "$URL",
    "status": "$CAUSE",
    "alert_type": "incident_change",
    "check_timestamp": "$STARTED_AT",
    "severity": "critical",
    "raw_body": "$CAUSE",
    "metadata": {
      "started_at": "$STARTED_AT",
      "acknowledged_at": "$ACKNOWLEDGED_AT",
      "resolved_at": "$RESOLVED_AT",
      "response_url": "$RESPONSE_URL",
      "screenshot_url": "$SCREENSHOT_URL"
    }
  }
}
```

See [docs/OPERATIONS.md](/Users/rkane/repos/hcww_incident_agent/docs/OPERATIONS.md) for the cutover checklist and validation steps.

### Local run

```bash
python3 app.py
```

### Docker run

```bash
docker compose up -d --build
```

### Tests

```bash
python3 -m unittest discover -s tests
```
