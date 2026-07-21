# Security Hardening Implementation Spec

## Goal

Harden the HCWW incident agent before internet-facing or unattended production use. The work focuses on failing closed, limiting trusted inputs, reducing secret exposure, and improving operational safety around remediation and audit data.

## Step 1: Fail Closed on Webhook Authentication

Status: Complete.

- Align the documented and loaded environment variables so the service reads the same workflow secret name that operators configure.
- Require `TEAMS_WORKFLOW_SHARED_SECRET` in staging and production; startup should fail when it is missing.
- Keep local development convenient only when `HCWW_AGENT_ENV=development`, and make the unauthenticated mode explicit in health/schema output.
- Add regression tests for missing, wrong, and correctly configured workflow secrets.

## Step 2: Add Strict URL Allowlisting and SSRF Protection

Status: Complete.

- Validate `betterstack.monitor_url`, `HCWW_SMOKE_CHECK_URL`, and `HCWW_CORE_SMOKE_URLS` before any DNS, HTTP, cache purge, or redeploy use.
- Allow only expected HCWW origins such as `https://hcww.net` and `https://www.hcww.net`.
- Reject localhost, private IP ranges, link-local addresses, unsupported schemes, embedded credentials, and unexpected ports.
- Re-check final redirect targets before reading response bodies or treating diagnostics as successful.

## Step 3: Limit Inbound Request Size and Shape

Status: Complete.

- Enforce a maximum webhook body size suitable for Better Stack Teams workflow payloads.
- Return `413 Payload Too Large` for oversized requests and `400 Bad Request` for invalid or missing `Content-Length`.
- Require `Content-Type: application/json` on webhook requests.
- Add tests for oversized bodies, invalid content length, missing content type, and valid payload acceptance.

## Step 4: Harden Docker Packaging and Runtime Defaults

- Ensure `.dockerignore` is committed and excludes `.env`, `.git`, `data/`, caches, OS files, and local artifacts.
- Remove any ignore rule that prevents `.dockerignore` from being tracked.
- Run the container as a non-root user with writable access only to the application data directory.
- Keep credentials runtime-only through `env_file`, secrets management, or deployment platform environment variables.

## Step 5: Centralize Redaction for Stored and Returned Data

- Create a shared redaction helper for incident details, audit events, action attempts, diagnostics, and notifier payloads.
- Strip sensitive headers such as `Authorization`, cookies, webhook URLs, deploy URLs, API tokens, and raw payload fields that may contain secrets.
- Limit body excerpts stored in SQLite and returned from admin endpoints to the minimum needed for troubleshooting.
- Add tests proving admin incident and audit endpoints do not return raw payloads or sensitive outbound request details.

## Step 6: Make Remediation Success Criteria Explicit

- Treat deploy responses as successful only when the configured deploy mode returns an explicit success signal.
- Mark ambiguous deploy responses as failed or unknown, then rely on verification before declaring recovery.
- Store remediation result status, HTTP status, and verification outcome separately for clearer audit history.
- Add tests for successful deploy, explicit failure, ambiguous response, and post-action verification failure.

## Step 7: Add Production Guardrails and Documentation

- Update `README.md` and `docs/OPERATIONS.md` with required production environment variables and fail-closed behavior.
- Document the allowed URL origins and how to update them safely if HCWW adds monitored domains.
- Add rollout guidance: diagnostics-only first, then one mutating playbook at a time after supervised drills.
- Include a pre-production checklist covering auth, URL validation, Docker secret hygiene, tests, and audit redaction.

## Validation

- Run `python3 -m unittest discover -s tests` after each implementation step.
- Add focused tests with each hardening change instead of relying only on end-to-end fixtures.
- Confirm local development still works with explicit development settings.
- Confirm staging/production settings fail startup when required secrets or URL allowlists are invalid.
