"""Configuration management for OpenGov-Grants."""

import os
from typing import Optional

from pydantic import Field
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings for OpenGov-Grants."""

    # Application
    app_name: str = "OpenGov-Grants"
    version: str = "1.0.0"
    debug: bool = False

    # Database
    database_url: str = Field(
        default="sqlite:///data/opengovgrants.db",
        env="OPENGRANTS_DATABASE_URL"
    )

    # AI/LLM Providers
    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4", env="OPENGRANTS_OPENAI_MODEL")

    ollama_base_url: str = Field(
        default="http://localhost:11434",
        env="OPENGRANTS_OLLAMA_BASE_URL"
    )
    ollama_model: str = Field(default="llama2:7b", env="OPENGRANTS_OLLAMA_MODEL")

    # Domain-specific settings
    # Add domain-specific configuration fields here

    # Logging
    log_level: str = Field(default="INFO", env="OPENGRANTS_LOG_LEVEL")
    structured_logging: bool = Field(
        default=True,
        env="OPENGRANTS_STRUCTURED_LOGGING"
    )

    # Performance
    max_concurrent_analyses: int = Field(
        default=5,
        env="OPENGRANTS_MAX_CONCURRENT_ANALYSES"
    )
    request_timeout: int = Field(
        default=300,
        env="OPENGRANTS_REQUEST_TIMEOUT"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="OPENGRANTS_",
        case_sensitive=False,
    )

    @field_validator("debug", mode="before")
    @classmethod
    def coerce_debug_from_env(cls, v):
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.strip().lower() in {"1", "true", "yes", "on"}
        return bool(v)


def get_settings() -> Settings:
    """Get application settings."""
    return Settings()