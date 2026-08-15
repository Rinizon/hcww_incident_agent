# Runtime Path Remediation Spec

## Goal

Make local host startup and Docker startup use SQLite database paths that match
their own filesystems.

The current local `.env` points `HCWW_AGENT_DB_PATH` at `/app/data/agent_state.db`,
which is correct inside the Docker container but invalid for direct host startup
with `python3 app.py`. Docker should own the `/app/data` path, while local
development should default to `data/agent_state.db` under the repository.

## Step 1: Move The Docker DB Path Into Compose

Status: Complete.

- Set `HCWW_AGENT_DB_PATH=/app/data/agent_state.db` in `docker-compose.yml`
  under the service `environment` block.
- Keep the existing `./data:/app/data` volume mapping.
- Add or update a packaging hardening test proving compose declares the
  container database path explicitly.

## Step 2: Restore Local `.env` Host DB Path

Status: Complete.

- Update the local `.env` database path to `data/agent_state.db`.
- Do not alter secrets or unrelated operator runtime settings.
- Confirm direct local startup can create/open the SQLite file under the repo.

## Step 3: Document Local And Docker Path Ownership

Status: Complete.

- Update `README.md` so local startup notes that `HCWW_AGENT_DB_PATH` should be
  host-relative, such as `data/agent_state.db`.
- Update `docs/OPERATIONS.md` to explain that Docker Compose overrides
  `HCWW_AGENT_DB_PATH` to `/app/data/agent_state.db` while mounting host
  `./data`.
- Keep production safety settings and remediation defaults unchanged.

## Step 4: Validate Both Runtime Paths

Status: Complete.

- Run the unit test suite.
- Start the service directly with `python3 app.py` and confirm `/healthz`
  returns `status=ok`.
- Stop the local server after the smoke check.
- Confirm no tracked secret files are added.

## Acceptance Criteria

- `python3 app.py` works from the repo using the local `.env`.
- `docker-compose.yml` explicitly sets the container database path.
- Documentation names which path belongs to host startup versus Docker startup.
- Tests pass after the path ownership change.

## Validation Results

Status: Complete.

- `python3 -m unittest discover -s tests` passes.
- `python3 app.py` starts from the repo with the local `.env`.
- `/healthz` returns `status=ok` while reflecting production-mode `.env`
  settings.
