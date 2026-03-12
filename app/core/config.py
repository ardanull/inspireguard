from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = Field(default='SentinelGuard Enterprise', alias='APP_NAME')
    app_env: str = Field(default='development', alias='APP_ENV')
    database_url: str = Field(default='sqlite:///./sentinelguard.db', alias='DATABASE_URL')
    config_path: str = Field(default='config/default.yaml', alias='CONFIG_PATH')
    log_level: str = Field(default='INFO', alias='LOG_LEVEL')
    secret_key: str = Field(default='change-me-in-production', alias='SECRET_KEY')
    access_token_expire_minutes: int = Field(default=60, alias='ACCESS_TOKEN_EXPIRE_MINUTES')
    refresh_token_expire_minutes: int = Field(default=43200, alias='REFRESH_TOKEN_EXPIRE_MINUTES')
    redis_url: str = Field(default='redis://redis:6379/0', alias='REDIS_URL')
    celery_broker_url: str = Field(default='redis://redis:6379/1', alias='CELERY_BROKER_URL')
    celery_result_backend: str = Field(default='redis://redis:6379/2', alias='CELERY_RESULT_BACKEND')
    cors_origins: str = Field(default='*', alias='CORS_ORIGINS')
    websocket_channel: str = Field(default='alerts', alias='WEBSOCKET_CHANNEL')
    redis_fanout_channel: str = Field(default='sentinelguard.events', alias='REDIS_FANOUT_CHANNEL')
    default_admin_email: str = Field(default='admin@sentinelguard.local', alias='DEFAULT_ADMIN_EMAIL')
    default_admin_password: str = Field(default='ChangeThisPassword!123', alias='DEFAULT_ADMIN_PASSWORD')
    sso_default_redirect_uri: str = Field(default='http://localhost:8000/sso/callback', alias='SSO_DEFAULT_REDIRECT_URI')
    mtls_ca_name: str = Field(default='SentinelGuard Root CA', alias='MTLS_CA_NAME')
    mtls_ca_common_name: str = Field(default='SentinelGuard Enterprise Root CA', alias='MTLS_CA_COMMON_NAME')
    pki_dir: str = Field(default='data/pki', alias='PKI_DIR')
    evidence_dir: str = Field(default='data/evidence', alias='EVIDENCE_DIR')
    tenant_header_name: str = Field(default='X-Tenant-ID', alias='TENANT_HEADER_NAME')
    oidc_base_url: str = Field(default='http://localhost:8000', alias='OIDC_BASE_URL')
    metrics_enabled: bool = Field(default=True, alias='METRICS_ENABLED')

    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


@lru_cache(maxsize=1)
def load_yaml_config() -> dict[str, Any]:
    settings = get_settings()
    path = Path(settings.config_path)
    if not path.exists():
        return {}
    with path.open('r', encoding='utf-8') as f:
        return yaml.safe_load(f) or {}
