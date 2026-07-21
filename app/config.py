from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv() -> None:
    candidate_paths = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ]
    for path in candidate_paths:
        if not path.exists():
            continue
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key, value)
        break


_load_dotenv()


def _env(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


@dataclass(frozen=True)
class Settings:
    host: str = field(default_factory=lambda: _env("HCWW_AGENT_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(_env("HCWW_AGENT_PORT", "8787")))
    db_path: str = field(default_factory=lambda: _env("HCWW_AGENT_DB_PATH", "data/agent_state.db"))
    env: str = field(default_factory=lambda: _env("HCWW_AGENT_ENV", "development"))
    service_name: str = field(default_factory=lambda: _env("HCWW_AGENT_SERVICE_NAME", "hcww"))
    actor_email: str = field(default_factory=lambda: _env("HCWW_AGENT_ACTOR_EMAIL", "incident-agent@hcww.local"))
    public_base_url: str = field(default_factory=lambda: _env("HCWW_AGENT_PUBLIC_BASE_URL", "https://agent.example.com"))
    workflow_shared_secret: str = field(default_factory=lambda: _env("TEAMS_WORKFLOW_SHARED_SECRET", ""))
    admin_shared_secret: str = field(default_factory=lambda: _env("HCWW_ADMIN_SHARED_SECRET", ""))
    teams_post_mode: str = field(default_factory=lambda: _env("TEAMS_POST_MODE", "workflow"))
    teams_webhook_url: str = field(default_factory=lambda: _env("TEAMS_WEBHOOK_URL", ""))
    cloudflare_api_base_url: str = field(
        default_factory=lambda: _env("CLOUDFLARE_API_BASE_URL", "https://api.cloudflare.com/client/v4")
    )
    cloudflare_api_token: str = field(default_factory=lambda: _env("CLOUDFLARE_API_TOKEN", ""))
    cloudflare_account_id: str = field(default_factory=lambda: _env("CLOUDFLARE_ACCOUNT_ID", ""))
    cloudflare_zone_id: str = field(default_factory=lambda: _env("CLOUDFLARE_ZONE_ID", ""))
    deploy_mode: str = field(default_factory=lambda: _env("HCWW_DEPLOY_MODE", "deploy_hook"))
    deploy_base_url: str = field(default_factory=lambda: _env("HCWW_DEPLOY_BASE_URL", ""))
    deploy_api_token: str = field(default_factory=lambda: _env("HCWW_DEPLOY_API_TOKEN", ""))
    smoke_check_url: str = field(default_factory=lambda: _env("HCWW_SMOKE_CHECK_URL", ""))
    smoke_check_expected_text: str = field(default_factory=lambda: _env("HCWW_SMOKE_CHECK_EXPECTED_TEXT", ""))
    diagnostic_timeout_seconds: float = field(default_factory=lambda: float(_env("HCWW_DIAGNOSTIC_TIMEOUT_SECONDS", "10")))
    max_remediation_attempts: int = field(default_factory=lambda: int(_env("HCWW_MAX_REMEDIATION_ATTEMPTS", "2")))
    max_playbook_retries: int = field(default_factory=lambda: int(_env("HCWW_MAX_PLAYBOOK_RETRIES", "1")))
    remediation_cooldown_seconds: int = field(default_factory=lambda: int(_env("HCWW_REMEDIATION_COOLDOWN_SECONDS", "300")))
    enable_cache_purge: bool = field(default_factory=lambda: _env("HCWW_ENABLE_CACHE_PURGE", "false").lower() == "true")
    enable_redeploy: bool = field(default_factory=lambda: _env("HCWW_ENABLE_REDEPLOY", "false").lower() == "true")
