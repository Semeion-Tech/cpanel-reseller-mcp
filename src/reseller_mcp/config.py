from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RESELLER_MCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    db_path: Path = Path("data/reseller-mcp.db")
    catalog_path: Path = Path("data/live_operations.json")
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    public_url: str = "http://127.0.0.1:8080"
    token_pepper: SecretStr = SecretStr("development-token-pepper-change-me")
    confirmation_secret: SecretStr = SecretStr("development-confirmation-secret-change-me")

    cpanel_base_url: str = "https://cpanel.example.com:2087"
    cpanel_reseller: str = "demo-reseller"
    cpanel_reader_token: SecretStr = SecretStr("")
    cpanel_operator_token: SecretStr = SecretStr("")
    cpanel_admin_token: SecretStr = SecretStr("")
    cpanel_verify_tls: bool = True
    cpanel_timeout_seconds: float = Field(default=30.0, gt=0, le=300)

    audit_retention_days: int = Field(default=365, ge=30, le=3650)
    preparation_ttl_seconds: int = Field(default=300, ge=60, le=3600)
    max_job_concurrency: int = Field(default=2, ge=1, le=8)
    require_second_approver: bool = False
    allow_untyped_advanced: bool = False
    allow_sensitive_file_reads: bool = False
    health_min_php_version: str = "8.2"
    mysql_egress_ip: str = ""
    database_ephemeral_ttl_seconds: int = Field(default=300, ge=60, le=1800)
    database_connect_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    database_query_timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    database_max_rows: int = Field(default=1000, ge=1, le=100000)
    memory_provider: str = "none"
    mem0_endpoint: str | None = None
    mem0_user_id: str = "kleber"

    @field_validator("cpanel_base_url", "public_url")
    @classmethod
    def strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    def upstream_token(self, profile: str) -> str:
        values = {
            "reader": self.cpanel_reader_token,
            "operator": self.cpanel_operator_token,
            "admin": self.cpanel_admin_token,
        }
        token = values[profile].get_secret_value()
        if not token:
            raise RuntimeError(f"cPanel {profile} token is not configured")
        return token

    def ensure_runtime_secrets(self) -> None:
        for name, secret in {
            "token_pepper": self.token_pepper,
            "confirmation_secret": self.confirmation_secret,
        }.items():
            value = secret.get_secret_value()
            if len(value) < 32 or "change-me" in value:
                raise RuntimeError(f"{name} must be a strong secret of at least 32 characters")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
