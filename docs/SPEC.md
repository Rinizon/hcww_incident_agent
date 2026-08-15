# Docker Data Volume Spec

## Goal

Make Docker startup work out of the box on a fresh VM without requiring manual
ownership fixes for a host bind-mounted `./data` directory.

The previous Compose setup mounted `./data:/app/data` while the container ran as
the non-root `hcww` user. On a VM, that host directory can be owned by a
different UID, causing SQLite startup to fail with `unable to open database
file`. A Docker-managed named volume avoids host UID mismatch while preserving
database durability.

## Step 1: Use A Docker-Managed Named Volume

Status: Complete.

- Replace the host bind mount with a named volume mounted at `/app/data`.
- Keep `HCWW_AGENT_DB_PATH=/app/data/agent_state.db` in Compose.
- Define the named volume at the top level of `docker-compose.yml`.

## Step 2: Update Operator Documentation

Status: Complete.

- Update Docker deployment notes to describe the named volume.
- Remove the requirement to make host `./data` writable by the container user.
- Update backup guidance to copy the database out of the running/stopped
  Compose service instead of assuming a host path.

## Step 3: Update Tests

Status: Complete.

- Update packaging-hardening tests to assert Compose uses the named volume.
- Keep tests proving the local `.env.example` uses a host-relative DB path.

## Step 4: Validate And Publish

Status: Complete.

- Run the unit test suite.
- Commit the tracked changes.
- Push the branch.
- Confirm the branch is clean and synced before asking for the next step.

## Acceptance Criteria

- `docker compose up -d --build` no longer depends on host `./data` ownership.
- SQLite still writes to persistent `/app/data` storage inside the container.
- Backup documentation explains how to retrieve the database from the Compose
  service or named volume.
- Tests pass.

## Validation Results

Status: Complete.

- `python3 -m unittest discover -s tests` passes.
