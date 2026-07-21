from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from app.url_policy import (
    DEFAULT_ALLOWED_PUBLIC_ORIGINS,
    parse_allowed_origins,
    validate_optional_public_url,
    validate_public_url_csv,
)


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


def _env_first(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name)
        if value is not None and value != "":
            return value
    return default


def _env_bool(name: str, default: str = "false") -> bool:
    return _env(name, default).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    host: str = field(default_factory=lambda: _env("HCWW_AGENT_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(_env("HCWW_AGENT_PORT", "8787")))
    db_path: str = field(default_factory=lambda: _env("HCWW_AGENT_DB_PATH", "data/agent_state.db"))
    env: str = field(default_factory=lambda: _env("HCWW_AGENT_ENV", "development"))
    service_name: str = field(default_factory=lambda: _env("HCWW_AGENT_SERVICE_NAME", "hcww"))
    actor_email: str = field(default_factory=lambda: _env("HCWW_AGENT_ACTOR_EMAIL", "incident-agent@hcww.local"))
    public_base_url: str = field(default_factory=lambda: _env("HCWW_AGENT_PUBLIC_BASE_URL", "https://agent.example.com"))
    workflow_shared_secret: str = field(
        default_factory=lambda: _env_first(
            "TEAMS_WORKFLOW_SHARED_SECRET",
            "BETTERSTACK_WEBHOOK_SHARED_SECRET",
            default="",
        )
    )
    workflow_secret_header: str = field(
        default_factory=lambda: _env_first(
            "TEAMS_WORKFLOW_SECRET_HEADER",
            default="X-HCWW-Workflow-Secret",
        )
    )
    admin_shared_secret: str = field(default_factory=lambda: _env("HCWW_ADMIN_SHARED_SECRET", ""))
    teams_post_mode: str = field(default_factory=lambda: _env("TEAMS_POST_MODE", "workflow"))
    teams_webhook_url: str = field(default_factory=lambda: _env("TEAMS_WEBHOOK_URL", ""))
    cloudflare_api_base_url: str = field(
        default_factory=lambda: _env("CLOUDFLARE_API_BASE_URL", "https://api.cloudflare.com/client/v4")
    )
    cloudflare_api_token: str = field(default_factory=lambda: _env("CLOUDFLARE_API_TOKEN", ""))
    cloudflare_zone_id: str = field(default_factory=lambda: _env("CLOUDFLARE_ZONE_ID", ""))
    deploy_mode: str = field(default_factory=lambda: _env("HCWW_DEPLOY_MODE", "deploy_hook"))
    deploy_base_url: str = field(default_factory=lambda: _env("HCWW_DEPLOY_BASE_URL", ""))
    deploy_api_token: str = field(default_factory=lambda: _env("HCWW_DEPLOY_API_TOKEN", ""))
    allowed_public_origins: str = field(
        default_factory=lambda: _env("HCWW_ALLOWED_PUBLIC_ORIGINS", DEFAULT_ALLOWED_PUBLIC_ORIGINS)
    )
    smoke_check_url: str = field(default_factory=lambda: _env("HCWW_SMOKE_CHECK_URL", ""))
    core_smoke_urls: str = field(default_factory=lambda: _env("HCWW_CORE_SMOKE_URLS", ""))
    smoke_check_expected_text: str = field(default_factory=lambda: _env("HCWW_SMOKE_CHECK_EXPECTED_TEXT", ""))
    contact_form_expected_action: str = field(default_factory=lambda: _env("HCWW_CONTACT_FORM_EXPECTED_ACTION", ""))
    diagnostic_timeout_seconds: float = field(default_factory=lambda: float(_env("HCWW_DIAGNOSTIC_TIMEOUT_SECONDS", "10")))
    max_webhook_body_bytes: int = field(default_factory=lambda: int(_env("HCWW_MAX_WEBHOOK_BODY_BYTES", "65536")))
    max_remediation_attempts: int = field(default_factory=lambda: int(_env("HCWW_MAX_REMEDIATION_ATTEMPTS", "2")))
    max_playbook_retries: int = field(default_factory=lambda: int(_env("HCWW_MAX_PLAYBOOK_RETRIES", "1")))
    remediation_cooldown_seconds: int = field(default_factory=lambda: int(_env("HCWW_REMEDIATION_COOLDOWN_SECONDS", "300")))
    remediation_disabled: bool = field(default_factory=lambda: _env_bool("HCWW_REMEDIATION_DISABLED"))
    enable_cache_purge: bool = field(default_factory=lambda: _env_bool("HCWW_ENABLE_CACHE_PURGE"))
    enable_redeploy: bool = field(default_factory=lambda: _env_bool("HCWW_ENABLE_REDEPLOY"))

    def __post_init__(self) -> None:
        if self.env != "development" and not self.workflow_shared_secret:
            raise ValueError(
                "TEAMS_WORKFLOW_SHARED_SECRET is required when "
                "HCWW_AGENT_ENV is not development"
            )
        allowed_origins = parse_allowed_origins(self.allowed_public_origins)
        validate_optional_public_url(
            self.smoke_check_url,
            allowed_origins,
            "HCWW_SMOKE_CHECK_URL",
        )
        validate_public_url_csv(
            self.core_smoke_urls,
            allowed_origins,
            "HCWW_CORE_SMOKE_URLS",
        )
        if self.max_webhook_body_bytes <= 0:
            raise ValueError("HCWW_MAX_WEBHOOK_BODY_BYTES must be greater than zero")

    @property
    def allowed_public_origin_values(self) -> tuple[str, ...]:
        return parse_allowed_origins(self.allowed_public_origins)
