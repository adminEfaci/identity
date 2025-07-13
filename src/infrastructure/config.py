"""Configuration for Infrastructure Components.

This module provides configuration classes for all infrastructure components
including database, cache, messaging, and security settings.
"""

from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class DatabaseConfig(BaseSettings):
    """Database configuration settings."""

    # Connection settings
    host: str = Field(default="localhost", description="Database host")
    port: int = Field(default=5432, description="Database port")
    username: str = Field(default="identity", description="Database username")
    password: str = Field(default="password", description="Database password")
    database: str = Field(default="identity", description="Database name")

    # Connection pool settings
    pool_size: int = Field(default=5, description="Connection pool size")
    max_overflow: int = Field(default=10, description="Maximum overflow connections")
    pool_timeout: int = Field(default=30, description="Pool timeout in seconds")
    pool_recycle: int = Field(default=3600, description="Pool recycle time in seconds")

    # Development settings
    echo_sql: bool = Field(default=False, description="Echo SQL queries")

    @property
    def url(self) -> str:
        """Build database URL from configuration."""
        return f"postgresql+asyncpg://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"

    class Config:
        env_prefix = "DB_"


class RedisConfig(BaseSettings):
    """Redis configuration settings."""

    # Connection settings
    host: str = Field(default="localhost", description="Redis host")
    port: int = Field(default=6379, description="Redis port")
    password: Optional[str] = Field(default=None, description="Redis password")
    database: int = Field(default=0, description="Redis database number")

    # Connection pool settings
    max_connections: int = Field(default=10, description="Maximum connections")
    retry_on_timeout: bool = Field(default=True, description="Retry on timeout")
    socket_timeout: int = Field(default=5, description="Socket timeout in seconds")
    socket_connect_timeout: int = Field(
        default=5, description="Socket connect timeout in seconds"
    )

    # Cache settings
    default_ttl: int = Field(default=3600, description="Default TTL in seconds")
    key_prefix: str = Field(default="identity:", description="Key prefix")

    @property
    def url(self) -> str:
        """Build Redis URL from configuration."""
        auth = f":{self.password}@" if self.password else ""
        return f"redis://{auth}{self.host}:{self.port}/{self.database}"

    class Config:
        env_prefix = "REDIS_"


class CeleryConfig(BaseSettings):
    """Celery configuration settings."""

    # Broker settings
    broker_host: str = Field(default="localhost", description="Broker host")
    broker_port: int = Field(default=6379, description="Broker port")
    broker_password: Optional[str] = Field(default=None, description="Broker password")
    broker_database: int = Field(default=1, description="Broker database number")

    # Result backend settings
    result_backend_host: str = Field(
        default="localhost", description="Result backend host"
    )
    result_backend_port: int = Field(default=6379, description="Result backend port")
    result_backend_password: Optional[str] = Field(
        default=None, description="Result backend password"
    )
    result_backend_database: int = Field(
        default=2, description="Result backend database number"
    )

    # Worker settings
    worker_concurrency: int = Field(default=4, description="Worker concurrency")
    task_serializer: str = Field(default="json", description="Task serializer")
    result_serializer: str = Field(default="json", description="Result serializer")
    accept_content: list[str] = Field(
        default=["json"], description="Accepted content types"
    )

    # Task settings
    task_always_eager: bool = Field(
        default=False, description="Execute tasks eagerly (for testing)"
    )
    task_eager_propagates: bool = Field(
        default=True, description="Propagate exceptions in eager mode"
    )
    result_expires: int = Field(
        default=3600, description="Result expiration in seconds"
    )

    @property
    def broker_url(self) -> str:
        """Build broker URL from configuration."""
        auth = f":{self.broker_password}@" if self.broker_password else ""
        return f"redis://{auth}{self.broker_host}:{self.broker_port}/{self.broker_database}"

    @property
    def result_backend_url(self) -> str:
        """Build result backend URL from configuration."""
        auth = (
            f":{self.result_backend_password}@" if self.result_backend_password else ""
        )
        return f"redis://{auth}{self.result_backend_host}:{self.result_backend_port}/{self.result_backend_database}"

    class Config:
        env_prefix = "CELERY_"


class SecurityConfig(BaseSettings):
    """Security configuration settings."""

    # JWT settings
    jwt_secret_key: str = Field(
        default="your-secret-key-change-in-production",
        description="JWT secret key",
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_access_token_expire_minutes: int = Field(
        default=30, description="Access token expiration in minutes"
    )
    jwt_refresh_token_expire_days: int = Field(
        default=7, description="Refresh token expiration in days"
    )

    # Password hashing settings
    password_hash_algorithm: str = Field(
        default="argon2", description="Password hashing algorithm"
    )
    argon2_time_cost: int = Field(default=3, description="Argon2 time cost")
    argon2_memory_cost: int = Field(default=65536, description="Argon2 memory cost")
    argon2_parallelism: int = Field(default=1, description="Argon2 parallelism")
    argon2_hash_len: int = Field(default=32, description="Argon2 hash length")
    argon2_salt_len: int = Field(default=16, description="Argon2 salt length")

    # Security settings
    bcrypt_rounds: int = Field(default=12, description="BCrypt rounds")
    max_login_attempts: int = Field(default=5, description="Maximum login attempts")
    lockout_duration_minutes: int = Field(
        default=15, description="Account lockout duration in minutes"
    )

    class Config:
        env_prefix = "SECURITY_"


class InfrastructureConfig(BaseSettings):
    """Main infrastructure configuration combining all components."""

    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    celery: CeleryConfig = Field(default_factory=CeleryConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)

    # Environment settings
    environment: str = Field(default="development", description="Environment name")
    debug: bool = Field(default=False, description="Debug mode")
    log_level: str = Field(default="INFO", description="Log level")

    class Config:
        env_prefix = "INFRA_"
