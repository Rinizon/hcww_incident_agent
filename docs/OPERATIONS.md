# HCWW Incident Agent Operations Runbook

## Purpose

This runbook covers deployment, configuration, supervised rollout, and day-to-day operations for the HCWW incident agent.

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
- Shared secret for webhook authentication sent in `X-HCWW-Workflow-Secret`
- `TEAMS_POST_MODE=workflow` for V1 production threaded replies
- `TEAMS_POST_MODE=webhook` only as a non-threaded Adaptive Card fallback

### Better Stack

- Uptime monitors for HCWW public routes
- Alert routing into the Teams incident channel
- Stable incident identifiers and alert metadata in the forwarded payload

### Cloudflare

- API token scoped for cache purge
- Zone ID
- Cloudflare API base URL

### Deploy Integration

- Deploy hook or API token capable of triggering a known-good redeploy
- Clearly documented target project and environment

## Environment Variables

Populate the values in [`.env`](/Users/rkane/repos/hcww_incident_agent/.env).

Safety-sensitive settings:

- `TEAMS_WORKFLOW_SHARED_SECRET`
- `TEAMS_WORKFLOW_SECRET_HEADER`
- `BETTERSTACK_WEBHOOK_SHARED_SECRET`
- `HCWW_ADMIN_SHARED_SECRET`
- `HCWW_MAX_REMEDIATION_ATTEMPTS`
- `HCWW_MAX_PLAYBOOK_RETRIES`
- `HCWW_REMEDIATION_COOLDOWN_SECONDS`
- `HCWW_MAX_WEBHOOK_BODY_BYTES`
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

Diagnostic-specific settings:

- `HCWW_ALLOWED_PUBLIC_ORIGINS`
- `HCWW_SMOKE_CHECK_URL`
- `HCWW_CORE_SMOKE_URLS`
- `HCWW_SMOKE_CHECK_EXPECTED_TEXT`
- `HCWW_CONTACT_FORM_EXPECTED_ACTION`

Recommended production starting values:

- `HCWW_MAX_REMEDIATION_ATTEMPTS=2`
- `HCWW_MAX_PLAYBOOK_RETRIES=1`
- `HCWW_REMEDIATION_COOLDOWN_SECONDS=300`
- `HCWW_MAX_WEBHOOK_BODY_BYTES=65536`
- `HCWW_ENABLE_CACHE_PURGE=false`
- `HCWW_ENABLE_REDEPLOY=false`

`TEAMS_WORKFLOW_SHARED_SECRET` is required when `HCWW_AGENT_ENV` is anything
other than `development`. `BETTERSTACK_WEBHOOK_SHARED_SECRET` is accepted as a
legacy fallback secret name, but new deployments should use
`TEAMS_WORKFLOW_SHARED_SECRET`.

`HCWW_ALLOWED_PUBLIC_ORIGINS` defaults to `https://hcww.net,https://www.hcww.net`.
The agent rejects webhook monitor URLs, smoke-check URLs, core route URLs, and
redirect targets outside this allowlist. Only add origins after confirming they
are HCWW-owned public HTTPS surfaces and do not point at private, local, or
internal services.

Allowed origin change process:

1. Confirm the new origin is an HCWW-owned public HTTPS surface.
2. Confirm it does not resolve to localhost, private, link-local, internal, or IP-literal targets.
3. Add it to `HCWW_ALLOWED_PUBLIC_ORIGINS` in staging first.
4. Run `python3 -m unittest discover -s tests` and the diagnostics-only drill sequence.
5. Promote the exact value to production only after reviewing `/healthz` and `/schema/webhooks/teams/betterstack`.

Start production in diagnostics-only mode. Enable `HCWW_ENABLE_CACHE_PURGE` and
`HCWW_ENABLE_REDEPLOY` only after validating credentials and running supervised
drills for each mutating playbook.

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

The health response includes a `remediation` block showing whether the agent is
running in diagnostics-only mode or has mutating playbooks enabled.
It includes a `request_policy` block showing the webhook body-size limit,
required content type, and `Content-Length` requirement.
It also includes a `url_policy` block showing the currently allowed public
origins and redirect-target validation status.

Inspect the webhook schema:

```bash
curl -s http://127.0.0.1:8787/schema/webhooks/teams/betterstack
```

## Supervised Drills

The repository includes a fixture replay harness for local or staging validation:

```bash
python3 tools/drill_agent.py --list
python3 tools/drill_agent.py \
  --agent-url http://127.0.0.1:8787 \
  --workflow-secret "$TEAMS_WORKFLOW_SHARED_SECRET" \
  --admin-secret "$HCWW_ADMIN_SHARED_SECRET" \
  --scenario self-recovery \
  --strict
```

Available drills:

- `self-recovery`: recovery fixture should resolve without action attempts
- `dns-failure`: DNS failure fixture should escalate without mutation
- `contact-down`: contact fixture exercises contact-path diagnostics
- `edge-cache-purge`: edge fixture exercises cache-purge eligibility when enabled
- `failed-redeploy`: persistent edge fixture exercises cache purge plus redeploy escalation when both playbooks are enabled
- `duplicate-event`: sends the same event twice and expects duplicate suppression on replay

Recommended drill sequence:

1. Start with `HCWW_ENABLE_CACHE_PURGE=false` and `HCWW_ENABLE_REDEPLOY=false`.
2. Run `self-recovery`, `dns-failure`, `contact-down`, and `duplicate-event`.
3. Enable `HCWW_ENABLE_CACHE_PURGE=true` only after diagnostics-only drills pass, then run `edge-cache-purge`.
4. Enable `HCWW_ENABLE_REDEPLOY=true` only after cache-purge validation, then run `failed-redeploy`.
5. Review each drill's final incident status, action attempt count, and audit events before leaving mutating playbooks enabled.

## Teams Workflow Contract

The workflow should `POST` to:

- `/webhooks/teams/betterstack`

Headers:

- `Content-Type: application/json`
- `Content-Length: <byte length>` no larger than `HCWW_MAX_WEBHOOK_BODY_BYTES`
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

V1 Teams posting decision:

- production uses workflow-managed threaded replies
- the agent returns and audits a workflow payload for each lifecycle phase
- the workflow posts `text` as a reply to `reply_target_message_id`
- `reply_target_message_id` is `reply_to_message_id` when present, otherwise `root_message_id`
- direct webhook mode can post Adaptive Cards, but should not be treated as authoritative threaded reply behavior

Agent update payload fields:

- `marker`: automation marker used to suppress self-generated workflow events
- `phase`: one of `acknowledged`, `diagnosis`, `remediation_started`, `verifying`, `remediation_completed`, `resolved`, or `escalated`
- `title`: human-readable update title
- `text`: formatted message body for Teams
- `details`: structured evidence for the phase
- `teams`: original Teams context
- `reply_target_message_id`: message ID the workflow should reply to

## Deployment Checklist

1. Create the production `.env` with real Teams, Better Stack, Cloudflare, and deploy credentials.
2. Validate the Teams workflow can reach the agent endpoint.
3. Confirm `GET /healthz` succeeds from the runtime host.
4. Trigger a controlled test incident from Better Stack or a fixture-driven synthetic workflow payload.
5. Confirm the agent posts acknowledgement, diagnosis, and final state updates into the same Teams thread.
6. Confirm audit records are written and retrievable with `GET /incidents/:incident_id/audit`.
7. Confirm cache purge and redeploy integrations are disabled until credentials are validated.
8. Enable one mutating playbook at a time and run a supervised drill.

## Pre-Production Hardening Checklist

Before enabling unattended production remediation:

- Confirm `HCWW_AGENT_ENV` is not `development`.
- Confirm `TEAMS_WORKFLOW_SHARED_SECRET` and `HCWW_ADMIN_SHARED_SECRET` are present, unique, and stored outside source control.
- Confirm `/healthz` reports shared-secret workflow auth, a valid `request_policy`, the expected `url_policy`, and diagnostics-only remediation mode.
- Confirm `.dockerignore` excludes `.env`, `.git`, `data/`, caches, and local artifacts from image builds.
- Confirm the container runs as the non-root `hcww` user and only `/app/data` needs persistent write access.
- Confirm `HCWW_ALLOWED_PUBLIC_ORIGINS` contains only HCWW-owned public HTTPS origins.
- Confirm admin incident and audit endpoints return redacted payloads.
- Run `python3 -m unittest discover -s tests`.
- Run the diagnostics-only drill sequence: `self-recovery`, `dns-failure`, `contact-down`, and `duplicate-event`.
- Enable `HCWW_ENABLE_CACHE_PURGE` only after a supervised cache-purge drill succeeds.
- Enable `HCWW_ENABLE_REDEPLOY` only after a supervised redeploy drill succeeds and deploy responses show explicit success signals.

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
- treats generic API responses as successful only when they include `success: true`
- treats deploy-hook responses as successful only when the hook returns HTTP 2xx
- records action status and verification status separately before declaring recovery

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
- keep `.env` available at the project root for `docker compose` runtime injection
- keep `.env`, `.git`, `data/`, caches, and local artifacts out of the image build context through `.dockerignore`
- run the application as the non-root `hcww` user created by the image
- ensure the host `./data` directory is writable by the container user before production deployment

Recommended server-side validation:

```bash
docker compose up -d --build
curl -s http://127.0.0.1:8787/healthz
curl -s http://127.0.0.1:8787/schema/webhooks/teams/betterstack
```

If the agent must be reachable from another machine on the LAN, publish port `8787`
on all interfaces rather than only `127.0.0.1`.

## Structured Logs

The agent writes newline-delimited JSON logs to stdout. Each record includes:

- `timestamp`
- `level`
- `event`
- `incident_id` when available
- redacted `details`

Logged events include webhook acceptance/rejection, duplicate suppression,
diagnostic completion, remediation start/completion, escalation, and queued
Teams updates. Log details are passed through the shared redaction helper before
emission.

## Operational Guardrails

The current implementation includes:

- duplicate event suppression by `event_id`
- per-playbook retry limits
- cooldown-based remediation loop protection
- persisted action attempts with `started`, `failed`, `succeeded`, and `verified` statuses
- configurable route and contact-path diagnostics before mutation
- persisted audit trail for notifier and lifecycle events
- centralized redaction for raw payloads, secrets, sensitive headers, deploy/webhook URLs, and large body excerpts
- structured JSON logs for incident lifecycle and request rejection events
- playbook feature flags for risky actions

## Routine Operator Checks

- Review recent incidents via `GET /incidents`
- Review redacted audit history for escalated incidents
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
