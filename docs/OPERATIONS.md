# HCWW Incident Agent Operations Runbook

## Purpose

This runbook covers deployment, configuration, and day-to-day operations for the HCWW incident agent as of July 18, 2026.

## Production Responsibilities

The incident agent is responsible for:

- receiving Better Stack alerts forwarded from Teams Workflows or Power Automate
- classifying incidents for `hcww.net`
- running DNS and HTTP diagnostics
- attempting safe remediation playbooks
- posting status updates back into the originating Teams incident thread
- preserving audit history in SQLite

## Required Integrations

### Microsoft Teams / Workflows

- Standard Teams channel for Better Stack incident posts
- Teams Workflows or Power Automate flow in the default environment
- Shared secret for webhook authentication
- Teams posting mode decision:
  - `workflow` for workflow-managed posting
  - `webhook` for direct outgoing webhook style posting
  - future Graph API path if threaded reply requirements outgrow current connector limits

### Better Stack

- Uptime monitors for HCWW public routes
- Alert routing into the Teams incident channel
- Stable incident identifiers and alert metadata in the forwarded payload

### Cloudflare

- API token scoped for cache purge
- Account ID
- Zone ID
- Cloudflare API base URL

### Deploy Integration

- Deploy hook or API token capable of triggering a known-good redeploy
- Clearly documented target project and environment

## Environment Variables

Populate the values in [`.env`](/Users/rkane/repos/hcww_incident_agent/.env).

Safety-sensitive settings:

- `HCWW_ADMIN_SHARED_SECRET`
- `HCWW_MAX_REMEDIATION_ATTEMPTS`
- `HCWW_MAX_PLAYBOOK_RETRIES`
- `HCWW_REMEDIATION_COOLDOWN_SECONDS`
- `HCWW_ENABLE_CACHE_PURGE`
- `HCWW_ENABLE_REDEPLOY`

Cloudflare-specific settings:

- `CLOUDFLARE_API_BASE_URL`
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ZONE_ID`

Deploy-specific settings:

- `HCWW_DEPLOY_MODE`
- `HCWW_DEPLOY_BASE_URL`
- `HCWW_DEPLOY_API_TOKEN`

Recommended production starting values:

- `HCWW_MAX_REMEDIATION_ATTEMPTS=2`
- `HCWW_MAX_PLAYBOOK_RETRIES=1`
- `HCWW_REMEDIATION_COOLDOWN_SECONDS=300`
- `HCWW_ENABLE_CACHE_PURGE=true`
- `HCWW_ENABLE_REDEPLOY=true`

## Local Validation

Run the test suite:

```bash
python3 -m unittest discover -s tests
```

Run the service:

```bash
python3 app.py
```

Run with Docker:

```bash
docker compose up -d --build
```

Health check:

```bash
curl -s http://127.0.0.1:8787/healthz
```

Inspect the webhook schema:

```bash
curl -s http://127.0.0.1:8787/schema/webhooks/teams/betterstack
```

## Teams Workflow Contract

The workflow should `POST` to:

- `/webhooks/teams/betterstack`

Headers:

- `Content-Type: application/json`
- `X-HCWW-Workflow-Secret: <shared secret>`

Incident read endpoints require:

- `X-HCWW-Admin-Secret: <admin shared secret>`

Payload requirements:

- stable `event_id`
- Teams thread context
- Better Stack alert identifiers
- monitor URL
- alert type
- status
- check timestamp
- raw alert text

## Deployment Checklist

1. Create the production `.env` with real Teams, Better Stack, Cloudflare, and deploy credentials.
2. Validate the Teams workflow can reach the agent endpoint.
3. Confirm `GET /healthz` succeeds from the runtime host.
4. Trigger a controlled test incident from Better Stack or a fixture-driven synthetic workflow payload.
5. Confirm the agent posts acknowledgement, diagnosis, and final state updates into the same Teams thread.
6. Confirm audit records are written and retrievable with `GET /incidents/:incident_id/audit`.
7. Confirm cache purge and redeploy integrations are disabled until credentials are validated.
8. Enable one mutating playbook at a time and run a supervised drill.

## Cloudflare Hookup

The current implementation uses Cloudflare's documented zone cache purge endpoint:

- `POST /zones/{zone_id}/purge_cache`

Current behavior:

- uses bearer token authentication
- performs targeted URL purge with the `files` payload
- avoids `purge_everything`

Recommended token scope:

- `Cache Purge`

Rollout steps:

1. Create a Cloudflare API token with cache purge permission for the HCWW zone.
2. Populate `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ZONE_ID`.
3. Start with `HCWW_ENABLE_CACHE_PURGE=false` and confirm ingestion and diagnostics only.
4. Enable `HCWW_ENABLE_CACHE_PURGE=true`.
5. Run a supervised drill against a controlled stale-content scenario.

## Deploy Hookup

The current implementation expects a deploy endpoint that accepts:

- `POST <HCWW_DEPLOY_BASE_URL>`
- optional `Authorization: Bearer <HCWW_DEPLOY_API_TOKEN>` when `HCWW_DEPLOY_MODE` is not `deploy_hook`
- JSON body containing the incident context and `action: redeploy`

Current behavior:

- supports `deploy_hook` mode for Cloudflare Pages native deploy hooks
- supports bearer-token mode for generic deployment APIs
- sends a generic redeploy payload
- treats any JSON response with `success: true` or no explicit failure as successful

Recommended rollout:

1. For Cloudflare Pages, set `HCWW_DEPLOY_MODE=deploy_hook`.
2. Create a Pages Deploy Hook and set `HCWW_DEPLOY_BASE_URL` to the full hook URL.
3. Leave `HCWW_DEPLOY_API_TOKEN` blank in deploy-hook mode.
4. Keep `HCWW_ENABLE_REDEPLOY=false` until the hook is validated.
5. Run a supervised synthetic redeploy test before enabling unattended use.

## Docker Deployment

The repository now includes:

- [`Dockerfile`](/Users/rkane/repos/hcww_incident_agent/Dockerfile)
- [`docker-compose.yml`](/Users/rkane/repos/hcww_incident_agent/docker-compose.yml)

Container-specific requirements:

- set `HCWW_AGENT_HOST=0.0.0.0`
- mount `/app/data` persistently
- keep `.env` available at the project root

Recommended server-side validation:

```bash
docker compose up -d --build
curl -s http://127.0.0.1:8787/healthz
curl -s http://127.0.0.1:8787/schema/webhooks/teams/betterstack
```

If the agent must be reachable from another machine on the LAN, publish port `8787`
on all interfaces rather than only `127.0.0.1`.

## Operational Guardrails

The current implementation includes:

- duplicate event suppression by `event_id`
- per-playbook retry limits
- cooldown-based remediation loop protection
- persisted action attempts with `started`, `failed`, `succeeded`, and `verified` statuses
- persisted audit trail for notifier and lifecycle events
- playbook feature flags for risky actions

## Routine Operator Checks

- Review recent incidents via `GET /incidents`
- Review audit history for escalated incidents
- Confirm the SQLite database file is retained and backed up appropriately for the environment
- Check that Teams delivery is still functioning after any workflow or connector changes
- Revalidate Cloudflare and deploy credentials after rotation

## Incident Handling Notes

### If incidents resolve during diagnostics

The agent should close the incident as `resolved` without running remediation.

### If diagnostics fail and no safe playbook applies

The agent should escalate and provide the diagnostic evidence already gathered.

### If remediation starts but cooldown is active on a repeated alert

The agent should skip additional mutation and escalate to avoid automation loops.

## Recommended Production Rollout

1. Deploy with both mutating playbooks disabled.
2. Validate ingestion, classification, diagnostics, and Teams updates only.
3. Enable cache purge and run a supervised drill.
4. Enable redeploy only after deploy hook verification succeeds.
5. Review early incidents and adjust smoke-check markers and retry windows before relying on unattended remediation.
