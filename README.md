# HCWW Incident Agent

Auto-remediation agent for `hcww.net`.

## Purpose

The agent receives Better Stack incident alerts that arrive in Microsoft Teams, evaluates severity from Better Stack metadata, attempts safe automated remediation for the HCWW website stack, and posts status updates back into the originating Teams incident thread.

## Current Status

Version 1 is implemented as a release candidate. The codebase is ready for
staging and supervised production drills before unattended remediation is
enabled.

See [docs/SPEC.md](/Users/rkane/repos/hcww_incident_agent/docs/SPEC.md) for the current security hardening implementation spec.

## Implemented Capabilities

The agent is implemented as a zero-dependency Python service with SQLite persistence, Better Stack classification, public diagnostics, Teams update orchestration, initial remediation playbooks, and production hardening controls.

### Available endpoints

- `GET /healthz`
- `GET /schema/webhooks/teams/betterstack`
- `POST /webhooks/teams/betterstack`
- `GET /incidents`
- `GET /incidents/:incident_id`
- `GET /incidents/:incident_id/audit`

Incoming Better Stack workflow payloads are now:

- validated against the webhook contract
- bounded by explicit JSON content-type and webhook request size checks
- normalized into an incident type
- assigned a first-pass HCWW severity such as `sev1` to `sev4`
- stored in SQLite with triage audit events
- moved through lifecycle states including `diagnosing`, `resolved`, and `escalated`
- checked with initial DNS and HTTP diagnostics
- able to run configurable core route and contact-path smoke checks
- restricts diagnostics, smoke checks, and redirect targets to allowed HCWW public origins
- prepared for Teams updates through the notifier layer
- able to attempt cache purge and redeploy playbooks with verification after each action
- tracked with persisted remediation action attempts and retry-limited playbook execution
- protected by duplicate event suppression, cooldown-based loop prevention, and per-playbook retry limits
- protected by fail-closed workflow webhook authentication outside explicit development mode
- packaged with `.env` and local state excluded from Docker builds and runs as a non-root container user
- starts in diagnostics-only mode unless mutating playbooks are explicitly enabled
- backed by fixture-based end-to-end tests and an operations runbook in [docs/OPERATIONS.md](/Users/rkane/repos/hcww_incident_agent/docs/OPERATIONS.md)
- includes a real Cloudflare cache-purge client for production token and zone wiring
- includes a real deploy client for Cloudflare Pages deploy hooks and bearer-authenticated deployment APIs

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

### Supervised drills

```bash
python3 tools/drill_agent.py --list
```

See [docs/OPERATIONS.md](/Users/rkane/repos/hcww_incident_agent/docs/OPERATIONS.md) for local and staging drill commands.
