"""Configuration for the presentation layer.

This module provides configuration settings specific to the presentation layer
including API settings, CORS configuration, and server options.
"""

from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class PresentationConfig(BaseSettings):
    """Configuration settings for the presentation layer.

    Includes settings for the FastAPI application, CORS, GraphQL,
    and server configuration.
    """

    model_config = SettingsConfigDict(
        env_prefix="IDENTITY_PRESENTATION_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # API Configuration
    api_title: str = Field(
        default="Identity Module API",
        description="API title for documentation"
    )

    api_description: str = Field(
        default="REST and GraphQL API for user identity management",
        description="API description for documentation"
    )

    api_version: str = Field(
        default="1.0.0",
        description="API version"
    )

    # Server Configuration
    host: str = Field(
        default="0.0.0.0",
        description="Host to bind the server to"
    )

    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="Port to bind the server to"
    )

    debug: bool = Field(
        default=False,
        description="Enable debug mode"
    )

    reload: bool = Field(
        default=False,
        description="Enable auto-reload in development"
    )

    # CORS Configuration
    cors_origins: list[str] = Field(
        default=["*"],
        description="Allowed CORS origins"
    )

    cors_credentials: bool = Field(
        default=True,
        description="Allow credentials in CORS requests"
    )

    cors_methods: list[str] = Field(
        default=["*"],
        description="Allowed CORS methods"
    )

    cors_headers: list[str] = Field(
        default=["*"],
        description="Allowed CORS headers"
    )

    # GraphQL Configuration
    graphql_path: str = Field(
        default="/graphql",
        description="GraphQL endpoint path"
    )

    graphql_playground: bool = Field(
        default=True,
        description="Enable GraphQL playground"
    )

    graphql_introspection: bool = Field(
        default=True,
        description="Enable GraphQL introspection"
    )

    # Documentation Configuration
    docs_url: Optional[str] = Field(
        default="/docs",
        description="OpenAPI documentation URL (None to disable)"
    )

    redoc_url: Optional[str] = Field(
        default="/redoc",
        description="ReDoc documentation URL (None to disable)"
    )

    openapi_url: Optional[str] = Field(
        default="/openapi.json",
        description="OpenAPI schema URL (None to disable)"
    )

    # Pagination Configuration
    default_page_size: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Default page size for paginated endpoints"
    )

    max_page_size: int = Field(
        default=1000,
        ge=1,
        le=10000,
        description="Maximum page size for paginated endpoints"
    )

    # Rate Limiting Configuration
    rate_limit_enabled: bool = Field(
        default=False,
        description="Enable rate limiting"
    )

    rate_limit_requests: int = Field(
        default=100,
        ge=1,
        description="Number of requests per rate limit window"
    )

    rate_limit_window: int = Field(
        default=60,
        ge=1,
        description="Rate limit window in seconds"
    )

    # Logging Configuration
    log_level: str = Field(
        default="INFO",
        description="Logging level"
    )

    log_format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log message format"
    )

    access_log: bool = Field(
        default=True,
        description="Enable access logging"
    )

    # Health Check Configuration
    health_check_path: str = Field(
        default="/health",
        description="Health check endpoint path"
    )

    # Security Configuration
    trusted_hosts: list[str] = Field(
        default=["*"],
        description="List of trusted hosts"
    )

    # Response Configuration
    response_timeout: int = Field(
        default=30,
        ge=1,
        le=300,
        description="Response timeout in seconds"
    )

    max_request_size: int = Field(
        default=16 * 1024 * 1024,  # 16MB
        ge=1024,
        description="Maximum request size in bytes"
    )


def get_presentation_config() -> PresentationConfig:
    """Get presentation layer configuration.

    Returns:
        Presentation configuration instance
    """
    return PresentationConfig()
