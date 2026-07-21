# HCWW Incident Agent Next Steps Specification

## 1. Goal

Harden the current HCWW incident agent for safer production rollout by closing the highest-priority gaps found in code review:

- protect incident and audit data from unauthenticated reads
- make webhook ingestion and remediation execution idempotent under retries and concurrency
- ensure mutating playbooks are explicitly enabled only after validation
- improve classification accuracy for recovery events
- expand diagnostics and rollout confidence before unattended remediation

## 2. Scope

This specification covers incremental improvements to the existing zero-dependency Python service. It does not replace the V1 product specification in [SPEC.md](/Users/rkane/repos/hcww_incident_agent/docs/SPEC.md); it defines the next implementation sequence needed before broader production exposure.

## 3. Implementation Plan

### Step 1: Secure Read Endpoints

Protect incident history, raw Better Stack payloads, Teams context, and remediation audit data from unauthenticated access.

1. Add an admin shared-secret setting such as `HCWW_ADMIN_SHARED_SECRET`, with a documented header such as `X-HCWW-Admin-Secret`.
2. Require the admin secret for `GET /incidents`, `GET /incidents/:incident_id`, and `GET /incidents/:incident_id/audit`, while keeping `GET /healthz` public and keeping the webhook on `X-HCWW-Workflow-Secret`.
3. Redact or omit sensitive raw fields from list responses by default, especially `raw_payload`, notifier payload details, deployment target URLs, and any future provider responses that may include secrets.
4. Add tests for authorized access, missing secret rejection, invalid secret rejection, and the public health endpoint remaining available.

### Step 2: Make Webhook Ingestion Atomic

Prevent duplicate Better Stack or Teams Workflow delivery from causing repeated processing or repeated remediation.

1. Add a unique database constraint or unique index on `source_event_id`, and handle conflicts by returning the existing incident without reprocessing.
2. Replace the current pre-check duplicate flow with a single store-level claim/upsert operation that decides whether the event is new, repeated, or an update to an existing external incident.
3. Persist a clear audit event for duplicate deliveries without allowing duplicate diagnostics or remediation execution.
4. Add a concurrency-focused test that sends the same event twice through application logic and verifies only one processing path records diagnostics, Teams updates, and action attempts.

### Step 3: Persist Remediation Attempts Before Mutation

Ensure cache purge and redeploy operations remain auditable even if the process exits or fails after making an external change.

1. Extend `action_attempts` with an explicit status field such as `planned`, `started`, `succeeded`, `failed`, and `verified`, plus optional error and timing fields.
2. Insert a `started` action attempt immediately before calling Cloudflare or deploy clients, then update that same row with the result and verification outcome.
3. Update cooldown and retry-limit checks to count relevant `started`, `succeeded`, and `failed` attempts so an interrupted mutating action still prevents immediate loops.
4. Add tests for successful mutation, failed mutation, and a simulated exception path that still leaves an auditable attempt record.

### Step 4: Make Mutating Playbooks Opt-In by Default

Align code defaults with the operations runbook's supervised rollout guidance.

1. Change `HCWW_ENABLE_CACHE_PURGE` and `HCWW_ENABLE_REDEPLOY` defaults to `false` in configuration.
2. Update tests that currently depend on enabled playbooks so they opt in explicitly through `Settings`.
3. Update [README.md](/Users/rkane/repos/hcww_incident_agent/README.md) and [OPERATIONS.md](/Users/rkane/repos/hcww_incident_agent/docs/OPERATIONS.md) to state that production should start in diagnostics-only mode.
4. Add a health or schema field that reports whether mutating playbooks are enabled, so operators can confirm runtime posture without inspecting `.env`.

### Step 5: Tighten Recovery Classification

Avoid false recovery events caused by loose substring matching.

1. Replace substring matching for recovery detection with token or phrase matching for terms like `recovered`, `resolved`, `back up`, and explicit Better Stack recovery statuses.
2. Remove the bare `up` substring check or require it to appear as a standalone status/token.
3. Add classifier tests for false-positive text such as `support`, `update`, and `backup` to ensure these do not classify as recovery.
4. Add tests for valid recovery payloads so real Better Stack recovery notices still map to `incident_type=recovery`, `normalized_severity=sev4`, and `current_status=resolved`.

### Step 6: Expand Diagnostics Coverage

Improve confidence that the agent correctly distinguishes self-recovery, route-specific failures, DNS failures, and contact-path failures.

1. Add configurable core smoke routes for `/`, `/services/`, `/pricing/`, `/contact/`, and supporting assets, while preserving the alert target as the primary diagnostic URL.
2. Capture redirect target, response headers, status code, latency, and expected content marker results in diagnostic output.
3. Implement contact-path diagnostics that verify `/contact/`, `/contact/thanks/`, and the configured hosted form action in the rendered contact page.
4. Update remediation planning to use richer diagnostic evidence, such as skipping cache purge for clear DNS failures and escalating when contact form configuration is missing.

### Step 7: Finalize Teams Posting Behavior

Make Teams communication behavior explicit and verifiable before production drills.

1. Decide whether V1 production uses workflow-managed replies, direct webhook posting, or Microsoft Graph for threaded replies.
2. For the chosen mode, define the exact response contract between the agent and Teams Workflow, including phase, message, facts, and thread identifiers.
3. Add tests that verify the notifier output for acknowledgement, diagnosis, remediation started, remediation completed, verification, resolved, and escalated phases.
4. Document the Teams setup steps and any connector limitations in the operations runbook.

### Step 8: Add a Supervised Drill Harness

Create a repeatable way to validate production readiness without waiting for a real outage.

1. Add a script or documented command that can replay fixture payloads against a local or staging agent endpoint with configurable shared secrets.
2. Include drills for self-recovery, DNS failure escalation, edge failure cache purge, failed redeploy escalation, and duplicate event suppression.
3. Record expected outcomes for each drill, including final incident status, audit event types, action attempt counts, and Teams update phases.
4. Add the drill to the production rollout checklist so mutating playbooks are enabled only after diagnostics-only and one-playbook-at-a-time validation succeeds.

## 4. Recommended Sequence

1. Complete Steps 1 through 5 before exposing the service beyond a trusted local or private network.
2. Complete Step 6 before relying on automated remediation decisions for route-specific or contact-path incidents.
3. Complete Step 7 before expecting Teams to be the operator-facing source of truth.
4. Complete Step 8 before enabling unattended cache purge or redeploy in production.

## 5. Acceptance Criteria

- All existing tests pass.
- New tests cover endpoint authorization, duplicate event handling, remediation attempt lifecycle, recovery classification, and diagnostics expansion.
- Mutating playbooks are disabled unless explicitly enabled.
- Incident read endpoints no longer expose raw incident data without admin authorization.
- A supervised drill can demonstrate diagnostics-only mode and controlled playbook enablement.
