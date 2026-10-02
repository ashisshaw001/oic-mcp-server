"""Server-level settings (env vars / .env). OIC credentials live in the INI config, not here."""

from __future__ import annotations

import os

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def _split_csv(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


class Settings(BaseSettings):
    # extra="ignore": unknown keys in .env must not crash startup (the upstream
    # server died on MCP_LOG_FILE because pydantic-settings forbids extras by default).
    model_config = SettingsConfigDict(
        env_file=os.getenv("MCP_ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- HTTP server ---------------------------------------------------------
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8085
    mcp_path: str = "/mcp"

    # --- Inbound security ----------------------------------------------------
    mcp_auth_tokens: str = ""  # comma-separated static Bearer tokens (rotation = list both)
    mcp_auth_disabled: bool = False  # only honoured when bound to loopback
    mcp_allowed_origins: str = ""  # requests carrying any other Origin get 403
    mcp_allowed_hosts: str = ""  # optional Host allowlist, e.g. "mcp.example.com,mcp.example.com:*"

    # --- MCP transport -------------------------------------------------------
    mcp_stateless: bool = False  # True = no Mcp-Session-Id (easier multi-replica; no sticky selection)
    mcp_json_response: bool = True  # plain JSON responses instead of SSE streams
    mcp_session_idle_timeout_secs: int = 1800

    # --- OIC environments ----------------------------------------------------
    oic_config_file: str | None = None  # server-side INI shared by all callers
    oic_config_uploads_enabled: bool = True  # POST /config
    oic_upload_ttl_secs: int = 43200  # uploaded configs expire after 12h idle
    oic_max_uploaded_configs: int = 500  # server-wide
    oic_max_uploads_per_token: int = 20  # a token only ever evicts its own uploads
    oic_max_upload_bytes: int = 65536
    oic_max_environments_per_upload: int = 50
    # Uploaded url/token_url hosts must end with one of these (empty = allow any host).
    # Stops an uploaded INI from pointing the server at internal or arbitrary hosts.
    oic_upload_allowed_host_suffixes: str = ".ocp.oraclecloud.com,.identity.oraclecloud.com"
    # Extra redirect targets that may receive the bearer token. Always allowed: the same host,
    # and the same region's shared design host (design.integration.<region>.ocp.oraclecloud.com).
    oic_redirect_allowed_suffixes: str = ""
    allow_insecure_oic_urls: bool = False  # permit http:// OIC/token URLs (local mocks only)

    # --- Outbound HTTP to OIC ------------------------------------------------
    http_timeout_secs: float = 30.0
    http_max_retries: int = 2
    catalogue_ttl_secs: int = 120
    max_response_bytes: int = 20 * 1024 * 1024  # per OIC response (archives: 50 MB)

    # --- Output / logging ----------------------------------------------------
    max_result_chars: int = 60000
    log_level: str = "INFO"
    mcp_log_file: str | None = None

    @field_validator("oic_redirect_allowed_suffixes", "oic_upload_allowed_host_suffixes")
    @classmethod
    def _suffixes_start_with_dot(cls, value: str) -> str:
        for suffix in _split_csv(value):
            if not suffix.startswith("."):
                raise ValueError(f"Domain suffixes must start with '.': {suffix!r}")
        return value

    @field_validator("oic_config_file", "mcp_log_file", mode="before")
    @classmethod
    def _blank_is_none(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @property
    def auth_tokens(self) -> list[str]:
        return _split_csv(self.mcp_auth_tokens)

    @property
    def allowed_origins(self) -> list[str]:
        return [o.rstrip("/") for o in _split_csv(self.mcp_allowed_origins)]

    @property
    def allowed_hosts(self) -> list[str]:
        return [h.lower() for h in _split_csv(self.mcp_allowed_hosts)]

    @property
    def redirect_suffixes(self) -> tuple[str, ...]:
        return tuple(s.lower() for s in _split_csv(self.oic_redirect_allowed_suffixes))

    @property
    def upload_host_suffixes(self) -> tuple[str, ...]:
        return tuple(s.lower() for s in _split_csv(self.oic_upload_allowed_host_suffixes))

    @property
    def is_loopback(self) -> bool:
        return self.mcp_host in LOOPBACK_HOSTS

    def check_security(self) -> None:
        """Refuse to start in an unsafe configuration."""
        if self.mcp_auth_disabled:
            if not self.is_loopback:
                raise RuntimeError(
                    "MCP_AUTH_DISABLED=true is only allowed when MCP_HOST is a loopback address "
                    "(127.0.0.1, localhost, ::1). Set MCP_AUTH_TOKENS for anything reachable from a network."
                )
            return
        tokens = self.auth_tokens
        if not tokens:
            raise RuntimeError(
                "No MCP_AUTH_TOKENS configured. Set at least one Bearer token (32+ random chars), "
                "or MCP_AUTH_DISABLED=true for loopback-only local development."
            )
        weak = [t for t in tokens if len(t) < 16]
        if weak:
            raise RuntimeError("Every MCP_AUTH_TOKENS entry must be at least 16 characters (use 32+ random chars).")
