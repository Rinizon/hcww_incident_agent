# HCWW Incident Agent V1 Specification

## 1. Goal

Build an incident agent for `hcww.net` that can:

- receive Better Stack alerts from Microsoft Teams
- evaluate incident type and severity from Better Stack metadata
- diagnose likely causes across the HCWW public website and its dependencies
- perform safe automated remediation without waiting for human approval
- post progress, remediation actions, and final status back into the originating Teams incident thread
- escalate to a human in Teams when remediation is unavailable, unsafe, or unsuccessful

## 2. Context

As of July 18, 2026, the HCWW production website is a dependency-light static site hosted on Cloudflare Pages / Workers. Public monitoring is handled by Better Stack, and incident notifications are routed into Microsoft Teams.

The current public site surface includes:

- `https://hcww.net/`
- `https://hcww.net/services/`
- `https://hcww.net/pricing/`
- `https://hcww.net/contact/`
- supporting assets such as `robots.txt`, `sitemap.xml`, and `site.webmanifest`
- a hosted contact form flow on `https://hcww.net/contact/`

The incident agent must also consider surrounding dependencies, including:

- Cloudflare Pages / Workers deployment health
- Cloudflare DNS and edge delivery behavior
- Better Stack alert metadata and monitor state
- hosted contact form availability and post-submit behavior

## 3. V1 Product Decision

V1 will use Microsoft Teams as the operator-facing incident surface and Better Stack as the authoritative incident source.

The preferred entry path is:

1. Better Stack posts a root incident message into a standard Teams channel.
2. A Teams Workflows or Power Automate flow triggers from that message.
3. The workflow forwards the alert payload and Teams message context to the incident agent.
4. The incident agent diagnoses and, when safe, performs automated remediation.
5. The incident agent posts threaded updates into the same Teams incident conversation.

Important assumptions:

- The incident channel is a standard Teams channel, not a private channel.
- The Teams Workflows / Power Automate flow runs in the default environment.
- No manual approval gate exists in V1.
- Human escalation remains available when the agent cannot safely complete remediation.

## 4. Primary Objectives

- reduce mean time to detect actionable failure context
- reduce mean time to remediate common HCWW production incidents
- keep humans informed in the same Teams thread where the incident began
- avoid unsafe or ambiguous automation
- preserve a complete audit trail of what the agent saw, decided, changed, and verified

## 5. Non-Goals

V1 does not attempt to:

- replace Better Stack as the monitoring system of record
- manage incidents for systems unrelated to HCWW
- make arbitrary infrastructure changes without guardrails
- use private Teams channels as the primary workflow surface
- solve every class of outage on day one

## 6. Incident Scope

V1 must support incidents affecting:

- homepage availability
- required route availability
- HTTP error responses
- DNS resolution failures
- edge delivery issues visible from public HTTP checks
- stale or broken Cloudflare deployment state when a known-good redeploy can help
- contact page or hosted form availability problems

V1 may observe but not fully remediate:

- third-party provider outages outside HCWW control
- registrar-level domain problems
- certificate issues requiring account-level manual intervention
- Teams workflow delivery failures

## 7. Severity Model

Severity is derived from Better Stack metadata first, with HCWW-specific normalization rules.

### Proposed normalized severities

- `sev1`: full public site outage, apex domain failure, widespread DNS failure, or repeated failed remediation
- `sev2`: major route failure such as `/contact/` or multiple core route failures with partial site availability
- `sev3`: single-route degradation, dependency issue with workaround, or transient incident under active remediation
- `sev4`: informational, self-recovered, or low-risk auxiliary page issue

### Initial normalization inputs

- Better Stack monitor name
- Better Stack monitor URL
- Better Stack status
- Better Stack alert type
- Better Stack check timestamp
- failure count or persistence indicators if present
- affected route or dependency inferred from the alert target

If Better Stack explicitly provides severity-like metadata, the agent should preserve it and map it into the normalized HCWW severity model.

## 8. Auto-Remediation Policy

V1 is auto-remediation first, but not auto-remediation at any cost.

The agent may act automatically when all of the following are true:

- the incident maps to a known remediation playbook
- the required credentials and APIs are available
- the action is scoped to HCWW-owned systems
- the action is reversible or low-risk
- post-action verification is possible

The agent must not act automatically when:

- the cause is ambiguous and the action is high-risk
- the required system is unreachable or missing credentials
- the incident suggests account compromise or security abuse
- remediation would require destructive or irreversible changes without strong certainty

In these cases, the agent escalates in Teams with diagnosis, evidence, and recommended next step.

## 9. Initial Remediation Playbooks

V1 should support these first-class playbooks.

### 9.1 Public route verification

Actions:

- check `hcww.net` and required monitored routes
- confirm HTTP status, redirect behavior, response timing, and basic content markers
- compare current failures with Better Stack alert target

Outcome:

- mark as self-recovered if public checks pass again
- continue into deeper remediation if checks still fail

### 9.2 Cloudflare cache purge

Use when:

- the site is partially stale
- a recent deployment likely exists but content or asset mismatch is suspected

Actions:

- purge targeted cache first when possible
- use full cache purge only when targeted purge is insufficient or unavailable

Verification:

- re-run smoke checks on affected routes and assets

### 9.3 Known-good redeploy

Use when:

- public pages are failing but source and configuration likely remain valid
- the deployment platform indicates a recoverable bad deployment or asset publication issue

Actions:

- trigger a redeploy of the current production revision or last known-good revision

Verification:

- wait for deployment completion
- rerun public smoke checks

### 9.4 DNS and edge diagnostics

Use when:

- Better Stack indicates hostname resolution failure, connection failure, or edge-specific behavior

Actions:

- inspect DNS resolution for `hcww.net` and `www.hcww.net`
- validate expected Cloudflare-managed records
- inspect HTTP headers and edge behavior from public probes

Verification:

- confirm restored resolution and public HTTP success

### 9.5 Contact-path diagnostics

Use when:

- `/contact/` fails
- form submission dependency appears unhealthy

Actions:

- verify `/contact/` loads
- verify the success redirect target `/contact/thanks/`
- validate the hosted form endpoint configuration in rendered HTML
- perform a non-destructive configuration check of the hosted form flow where feasible

Verification:

- confirm contact page loads and configured form target is present

## 10. Human Escalation Rules

The agent escalates to a human in Teams when:

- no known playbook applies
- automated remediation fails
- repeated retries exceed configured limits
- the issue appears to involve billing, account access, security, or third-party outage management
- the incident remains unresolved after the maximum remediation window

Escalation message must include:

- normalized severity
- original Better Stack incident summary
- affected route or dependency
- what the agent checked
- what the agent attempted
- current verification results
- recommended human next step

## 11. Teams Communication Requirements

The agent must post back into the same incident conversation initiated by the Better Stack alert.

### Required update points

- incident acknowledged
- severity and initial diagnosis
- remediation started
- remediation action completed
- verification succeeded
- escalation required
- incident resolved or self-recovered

### Message qualities

- concise enough for channel readability
- explicit about action taken
- explicit about current risk
- timestamped in audit storage even if Teams already timestamps the message

## 12. Workflow Ingestion Requirements

The Better Stack outgoing webhook payload sent to the agent should include:

- stable incident event ID
- raw Better Stack alert body
- Better Stack monitor name
- Better Stack monitor URL
- Better Stack incident and alert identifiers
- status or cause text sufficient for classification

Preferred ingestion contract:

- `POST /webhooks/betterstack/incident`

The endpoint should validate:

- shared secret header configured in Better Stack
- payload schema
- deduplication identifiers

## 13. Proposed System Architecture

V1 should be organized into the following components:

### 13.1 Ingestion API

Responsibilities:

- receive Better Stack incident webhook payloads
- validate auth and schema
- create or resume an incident record
- enqueue diagnostic handling

### 13.2 Incident State Store

Responsibilities:

- persist incidents, actions, retries, audit events, and current status
- support idempotency and deduplication

SQLite is acceptable for V1.

### 13.3 Classifier

Responsibilities:

- parse Better Stack metadata
- map incident into HCWW severity and incident type
- select applicable diagnostic and remediation playbooks

### 13.4 Diagnostics Engine

Responsibilities:

- run HTTP, DNS, and platform checks
- gather evidence for remediation or escalation
- normalize results into structured findings

### 13.5 Remediation Engine

Responsibilities:

- execute playbook actions
- enforce safety checks
- record exact attempted changes
- trigger verification after each action

### 13.6 Integrations Layer

Responsibilities:

- Cloudflare API calls
- deployment hook or deployment API calls

## 14. Proposed Data Model

V1 incident storage should minimally track:

### Incident

- incident ID
- external incident key
- source system
- Better Stack monitor name
- Better Stack monitor URL
- normalized severity
- incident type
- current status
- created at
- updated at
- resolved at

### Action Attempt

- action ID
- incident ID
- playbook name
- action type
- inputs
- result
- started at
- completed at

### Audit Event

- event ID
- incident ID
- event type
- summary
- structured details
- created at

## 15. API Surface

Initial internal endpoints:

- `POST /webhooks/betterstack/incident`
- `GET /healthz`
- `GET /incidents`
- `GET /incidents/:incident_id`
- `GET /incidents/:incident_id/audit`

Optional later endpoints:

- `POST /incidents/:incident_id/retry`
- `POST /incidents/:incident_id/resolve`

## 16. Status Lifecycle

Proposed incident states:

- `received`
- `triaged`
- `diagnosing`
- `remediating`
- `verifying`
- `resolved`
- `escalated`
- `failed`

Expected lifecycle:

1. incident received from Teams workflow
2. incident classified from Better Stack metadata
3. diagnostics executed
4. remediation attempted if eligible
5. verification run
6. either resolved or escalated

## 17. Safety Controls

V1 must include:

- per-playbook retry limits
- deduplication for repeated alert deliveries
- cooldown window to avoid remediation loops
- idempotent state transitions
- audit logging for all external calls and decisions
- configuration flags to disable risky playbooks individually
- clear separation between diagnostic-only and mutating actions

## 18. Configuration Requirements

The environment should support configuration for:

- service host and port
- database path
- Better Stack API token and base URL
- Teams workflow shared secret
- Teams tenant, team, and channel context defaults where useful
- Teams posting mechanism credentials
- Cloudflare API token, account ID, and zone ID
- deployment hook or deployment API credentials
- smoke-check URLs and expected content markers
- retry limits, timeouts, and cooldown values

## 19. V1 Success Criteria

V1 is successful when it can:

- receive a Better Stack incident from Teams workflow input
- classify severity from Better Stack metadata
- run public checks for the HCWW site and surrounding dependencies
- automatically execute at least one safe remediation path
- post incident progress back into the originating Teams thread
- verify recovery and close the incident when successful
- escalate with useful operator context when unsuccessful

## 20. Implementation Milestones

### Milestone 1

- scaffold service
- define payload schema
- implement health endpoint
- implement incident persistence

### Milestone 2

- implement Teams workflow ingestion
- implement Better Stack metadata parsing
- implement severity normalization

### Milestone 3

- implement public HTTP and DNS diagnostics
- implement Teams threaded updates
- implement incident lifecycle transitions

### Milestone 4

- implement first remediation playbooks
- add verification and retry handling
- add audit views

### Milestone 5

- harden safety controls
- add end-to-end test fixtures
- document deployment and operational runbook

## 21. Open Questions

- Which exact Teams posting method will be used for threaded replies: Graph API, Power Automate action, or another supported Teams connector path?
- What deployment mechanism is authoritative for Cloudflare Pages / Workers remediation: deploy hook, Git provider integration, or direct API flow?
- Is there a first-party way to verify the hosted contact form dependency beyond markup and redirect validation?
- Which smoke-check content markers should be treated as authoritative for each core route?

## 22. Recommended Next Step

Implement Milestone 1 and 2 first:

- choose the runtime
- formalize the webhook payload contract
- define the database schema
- stub the classifier
- stub Teams update publishing

This creates a thin but testable vertical slice that can receive a real incident and record the intended workflow before mutating systems.
