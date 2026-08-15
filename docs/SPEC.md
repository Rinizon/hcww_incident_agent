# Environment Template Spec

## Goal

Add a tracked, secret-free `.env.example` so operators can create a valid local
or production `.env` without copying from an existing secret-bearing file.

The repository currently documents that `.env` must be populated, but `.env` is
ignored and no safe template is tracked. This creates a setup gap and increases
the chance that secrets or container-only paths get copied around manually.

## Step 1: Add A Secret-Free Template

Status: Complete.

- Add `.env.example` at the repository root.
- Include all runtime settings documented in the runbook.
- Use safe local defaults where possible.
- Use obvious placeholder values for secrets and integration URLs.
- Keep mutating playbooks disabled by default.

## Step 2: Document Template Usage

Status: Complete.

- Update `README.md` to tell operators to copy `.env.example` to `.env`.
- Update `docs/OPERATIONS.md` to reference `.env.example` before describing
  production credential population.
- Keep `.env` ignored and excluded from Docker builds.

## Step 3: Add Template Coverage

Status: Complete.

- Add packaging-hardening tests that assert `.env.example` exists.
- Assert the template includes important safety and credential settings.
- Assert the template does not contain known local secret values.

## Step 4: Validate And Publish

Status: Complete.

- Run the unit test suite.
- Commit the tracked changes.
- Push the branch.
- Confirm the branch is clean and synced before asking for the next step.

## Acceptance Criteria

- A new operator can run `cp .env.example .env` as their starting point.
- No real secrets are committed.
- `.env` remains ignored.
- Tests pass.

## Validation Results

Status: Complete.

- `python3 -m unittest discover -s tests` passes.
