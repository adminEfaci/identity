"""Tests for Infrastructure Layer.

This module contains comprehensive tests for all infrastructure components
including repositories, cache, messaging, and security features.
"""

from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import pytest

from domain.entities import Permission, Role, User
from domain.enums import PermissionScope, RoleType
from domain.value_objects import (
    Email,
    PasswordHash,
)
from infrastructure.cache import CacheService, RedisCache
from infrastructure.config import (
    CeleryConfig,
    DatabaseConfig,
    InfrastructureConfig,
    RedisConfig,
    SecurityConfig,
)
from infrastructure.messaging import CeleryMessageBus
from infrastructure.repositories import (
    SqlAlchemyPermissionRepository,
    SqlAlchemyRoleRepository,
    SqlAlchemyUserRepository,
)
from infrastructure.security import (
    Argon2PasswordHasher,
    JWTTokenService,
    SecurityError,
    SecurityService,
)


class TestDatabaseConfig:
    """Test database configuration."""

    def test_database_config_defaults(self):
        """Test database configuration with default values."""
        config = DatabaseConfig()

        assert config.host == "localhost"
        assert config.port == 5432
        assert config.username == "identity"
        assert config.database == "identity"
        assert config.pool_size == 5
        assert not config.echo_sql

    def test_database_url_generation(self):
        """Test database URL generation."""
        config = DatabaseConfig(
            host="testhost",
            port=5433,
            username="testuser",
            password="testpass",
            database="testdb",
        )

        expected_url = "postgresql+asyncpg://testuser:testpass@testhost:5433/testdb"
        assert config.url == expected_url


class TestRedisConfig:
    """Test Redis configuration."""

    def test_redis_config_defaults(self):
        """Test Redis configuration with default values."""
        config = RedisConfig()

        assert config.host == "localhost"
        assert config.port == 6379
        assert config.database == 0
        assert config.default_ttl == 3600
        assert config.key_prefix == "identity:"

    def test_redis_url_generation(self):
        """Test Redis URL generation."""
        config = RedisConfig(
            host="testhost",
            port=6380,
            password="testpass",
            database=1,
        )

        expected_url = "redis://:testpass@testhost:6380/1"
        assert config.url == expected_url

    def test_redis_url_without_password(self):
        """Test Redis URL generation without password."""
        config = RedisConfig(host="testhost", port=6380, database=1)

        expected_url = "redis://testhost:6380/1"
        assert config.url == expected_url


class TestSecurityConfig:
    """Test security configuration."""

    def test_security_config_defaults(self):
        """Test security configuration with default values."""
        config = SecurityConfig()

        assert config.jwt_algorithm == "HS256"
        assert config.jwt_access_token_expire_minutes == 30
        assert config.jwt_refresh_token_expire_days == 7
        assert config.password_hash_algorithm == "argon2"
        assert config.argon2_time_cost == 3
        assert config.bcrypt_rounds == 12


@pytest.mark.asyncio
class TestRedisCache:
    """Test Redis cache implementation."""

    @pytest.fixture
    def redis_config(self):
        """Redis configuration fixture."""
        return RedisConfig(
            host="localhost",
            port=6379,
            database=0,
            default_ttl=3600,
        )

    @pytest.fixture
    def redis_cache(self, redis_config):
        """Redis cache fixture."""
        return RedisCache(redis_config)

    async def test_redis_cache_initialization(self, redis_cache):
        """Test Redis cache initialization."""
        with patch("redis.asyncio.from_url") as mock_redis:
            mock_redis_instance = AsyncMock()
            mock_redis.return_value = mock_redis_instance

            await redis_cache.initialize()

            mock_redis.assert_called_once()
            mock_redis_instance.ping.assert_called_once()

    async def test_redis_cache_get_set(self, redis_cache):
        """Test Redis cache get and set operations."""
        with patch("redis.asyncio.from_url") as mock_redis:
            mock_redis_instance = AsyncMock()
            mock_redis.return_value = mock_redis_instance
            mock_redis_instance.get.return_value = '"test_value"'
            mock_redis_instance.setex.return_value = True

            await redis_cache.initialize()

            # Test set operation
            result = await redis_cache.set("test_key", "test_value", 300)
            assert result is True
            mock_redis_instance.setex.assert_called_once()

            # Test get operation
            value = await redis_cache.get("test_key")
            assert value == "test_value"
            mock_redis_instance.get.assert_called_once()

    async def test_redis_cache_delete(self, redis_cache):
        """Test Redis cache delete operation."""
        with patch("redis.asyncio.from_url") as mock_redis:
            mock_redis_instance = AsyncMock()
            mock_redis.return_value = mock_redis_instance
            mock_redis_instance.delete.return_value = 1

            await redis_cache.initialize()

            result = await redis_cache.delete("test_key")
            assert result is True
            mock_redis_instance.delete.assert_called_once()

    async def test_cache_service_user_operations(self, redis_cache):
        """Test cache service user operations."""
        with patch("redis.asyncio.from_url") as mock_redis:
            mock_redis_instance = AsyncMock()
            mock_redis.return_value = mock_redis_instance
            mock_redis_instance.get.return_value = None
            mock_redis_instance.setex.return_value = True

            await redis_cache.initialize()
            cache_service = CacheService(redis_cache)

            user_id = str(uuid4())
            user_data = {"id": user_id, "email": "test@example.com"}

            # Test cache user
            result = await cache_service.cache_user_by_id(user_id, user_data)
            assert result is True

            # Test get user (cache miss)
            cached_user = await cache_service.get_user_by_id(user_id)
            assert cached_user is None


class TestArgon2PasswordHasher:
    """Test Argon2 password hasher."""

    @pytest.fixture
    def security_config(self):
        """Security configuration fixture."""
        return SecurityConfig()

    @pytest.fixture
    def password_hasher(self, security_config):
        """Password hasher fixture."""
        return Argon2PasswordHasher(security_config)

    def test_password_hashing(self, password_hasher):
        """Test password hashing."""
        password = "test_password_123"

        password_hash = password_hasher.hash_password(password)

        assert password_hash.algorithm == "argon2"
        assert password_hash.hash_value
        assert len(password_hash.hash_value) > 50  # Argon2 hashes are long

    def test_password_verification_success(self, password_hasher):
        """Test successful password verification."""
        password = "test_password_123"
        password_hash = password_hasher.hash_password(password)

        result = password_hasher.verify_password(password, password_hash)
        assert result is True

    def test_password_verification_failure(self, password_hasher):
        """Test failed password verification."""
        password = "test_password_123"
        wrong_password = "wrong_password"
        password_hash = password_hasher.hash_password(password)

        result = password_hasher.verify_password(wrong_password, password_hash)
        assert result is False

    def test_password_too_short(self, password_hasher):
        """Test password too short error."""
        with pytest.raises(SecurityError):
            password_hasher.hash_password("short")

    def test_empty_password(self, password_hasher):
        """Test empty password error."""
        with pytest.raises(SecurityError):
            password_hasher.hash_password("")


class TestJWTTokenService:
    """Test JWT token service."""

    @pytest.fixture
    def security_config(self):
        """Security configuration fixture."""
        return SecurityConfig(jwt_secret_key="test_secret_key")

    @pytest.fixture
    def token_service(self, security_config):
        """Token service fixture."""
        return JWTTokenService(security_config)

    def test_access_token_generation(self, token_service):
        """Test access token generation."""
        user_id = str(uuid4())
        email = "test@example.com"
        roles = ["user", "admin"]

        token = token_service.generate_access_token(user_id, email, roles)

        assert token
        assert isinstance(token, str)
        assert len(token) > 100  # JWT tokens are long

    def test_refresh_token_generation(self, token_service):
        """Test refresh token generation."""
        user_id = str(uuid4())

        token = token_service.generate_refresh_token(user_id)

        assert token
        assert isinstance(token, str)

    def test_token_validation(self, token_service):
        """Test token validation."""
        user_id = str(uuid4())
        email = "test@example.com"
        roles = ["user"]

        token = token_service.generate_access_token(user_id, email, roles)
        claims = token_service.validate_token(token)

        assert claims["sub"] == user_id
        assert claims["email"] == email
        assert claims["roles"] == roles
        assert claims["type"] == "access"

    def test_token_revocation(self, token_service):
        """Test token revocation."""
        user_id = str(uuid4())
        email = "test@example.com"
        roles = ["user"]

        token = token_service.generate_access_token(user_id, email, roles)

        # Token should be valid initially
        claims = token_service.validate_token(token)
        assert claims["sub"] == user_id

        # Revoke token
        result = token_service.revoke_token(token)
        assert result is True

        # Token should be invalid after revocation
        with pytest.raises(SecurityError):
            token_service.validate_token(token)


class TestSecurityService:
    """Test security service."""

    @pytest.fixture
    def security_config(self):
        """Security configuration fixture."""
        return SecurityConfig(jwt_secret_key="test_secret_key")

    @pytest.fixture
    def password_hasher(self, security_config):
        """Password hasher fixture."""
        return Argon2PasswordHasher(security_config)

    @pytest.fixture
    def token_service(self, security_config):
        """Token service fixture."""
        return JWTTokenService(security_config)

    @pytest.fixture
    def security_service(self, password_hasher, token_service, security_config):
        """Security service fixture."""
        return SecurityService(password_hasher, token_service, security_config)

    def test_generate_tokens(self, security_service):
        """Test token generation."""
        user_id = str(uuid4())
        email = "test@example.com"
        roles = ["user"]

        tokens = security_service.generate_tokens(user_id, email, roles)

        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert tokens["access_token"]
        assert tokens["refresh_token"]

    def test_validate_access_token(self, security_service):
        """Test access token validation."""
        user_id = str(uuid4())
        email = "test@example.com"
        roles = ["user"]

        tokens = security_service.generate_tokens(user_id, email, roles)
        claims = security_service.validate_access_token(tokens["access_token"])

        assert claims["sub"] == user_id
        assert claims["email"] == email
        assert claims["type"] == "access"

    def test_password_strength_validation(self, security_service):
        """Test password strength validation."""
        # Strong password
        strong_result = security_service.validate_password_strength("StrongPass123!")
        assert strong_result["is_valid"] is True
        assert strong_result["score"] >= 4

        # Weak password
        weak_result = security_service.validate_password_strength("weak")
        assert weak_result["is_valid"] is False
        assert len(weak_result["errors"]) > 0

    def test_logout_user(self, security_service):
        """Test user logout."""
        user_id = str(uuid4())
        email = "test@example.com"
        roles = ["user"]

        tokens = security_service.generate_tokens(user_id, email, roles)

        result = security_service.logout_user(
            tokens["access_token"], tokens["refresh_token"]
        )
        assert result is True


class TestCeleryMessageBus:
    """Test Celery message bus."""

    @pytest.fixture
    def celery_config(self):
        """Celery configuration fixture."""
        return CeleryConfig(task_always_eager=True)

    @pytest.fixture
    def message_bus(self, celery_config):
        """Message bus fixture."""
        return CeleryMessageBus(celery_config)

    def test_message_bus_initialization(self, message_bus):
        """Test message bus initialization."""
        with patch("celery.Celery") as mock_celery:
            mock_celery_instance = Mock()
            mock_celery.return_value = mock_celery_instance

            message_bus.initialize()

            mock_celery.assert_called_once_with("identity_module")
            mock_celery_instance.conf.update.assert_called_once()

    @pytest.mark.asyncio
    async def test_schedule_task(self, message_bus):
        """Test task scheduling."""
        with patch("celery.Celery") as mock_celery:
            mock_celery_instance = Mock()
            mock_celery.return_value = mock_celery_instance
            mock_task = Mock()
            mock_task.id = "test_task_id"
            mock_celery_instance.send_task.return_value = mock_task

            message_bus.initialize()

            task_id = await message_bus.schedule_task(
                "test.task", args=("arg1", "arg2"), kwargs={"key": "value"}
            )

            assert task_id == "test_task_id"
            mock_celery_instance.send_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_email_notification(self, message_bus):
        """Test email notification sending."""
        with patch("celery.Celery") as mock_celery:
            mock_celery_instance = Mock()
            mock_celery.return_value = mock_celery_instance
            mock_task = Mock()
            mock_task.id = "email_task_id"
            mock_celery_instance.send_task.return_value = mock_task

            message_bus.initialize()

            task_id = await message_bus.send_email_notification(
                "test@example.com", "Test Subject", "Test Body"
            )

            assert task_id == "email_task_id"


@pytest.mark.asyncio
class TestSqlAlchemyRepositories:
    """Test SQLAlchemy repository implementations."""

    @pytest.fixture
    def mock_session(self):
        """Mock SQLAlchemy session fixture."""
        return AsyncMock()

    @pytest.fixture
    def user_repository(self, mock_session):
        """User repository fixture."""
        return SqlAlchemyUserRepository(mock_session)

    @pytest.fixture
    def role_repository(self, mock_session):
        """Role repository fixture."""
        return SqlAlchemyRoleRepository(mock_session)

    @pytest.fixture
    def permission_repository(self, mock_session):
        """Permission repository fixture."""
        return SqlAlchemyPermissionRepository(mock_session)

    @pytest.fixture
    def sample_user(self):
        """Sample user entity fixture."""
        return User.create(
            email=Email("test@example.com"),
            password_hash=PasswordHash.from_plaintext("password123"),
            created_by=uuid4(),
        )

    @pytest.fixture
    def sample_role(self):
        """Sample role entity fixture."""
        return Role.create(
            name="Test Role",
            role_type=RoleType.CUSTOM,
            created_by=uuid4(),
        )

    @pytest.fixture
    def sample_permission(self):
        """Sample permission entity fixture."""
        return Permission.create(
            name="Test Permission",
            resource="test_resource",
            action="read",
            scope=PermissionScope.GLOBAL,
            created_by=uuid4(),
        )

    async def test_user_repository_save(self, user_repository, sample_user, mock_session):
        """Test user repository save operation."""
        mock_session.get.return_value = None  # User doesn't exist

        await user_repository.save(sample_user)

        mock_session.add.assert_called_once()
        mock_session.flush.assert_called_once()

    async def test_user_repository_find_by_email(self, user_repository, mock_session):
        """Test user repository find by email."""
        email = Email("test@example.com")

        # Mock the query result
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        user = await user_repository.find_by_email(email)

        assert user is None
        mock_session.execute.assert_called_once()

    async def test_role_repository_save(self, role_repository, sample_role, mock_session):
        """Test role repository save operation."""
        mock_session.get.return_value = None  # Role doesn't exist

        await role_repository.save(sample_role)

        mock_session.add.assert_called_once()
        mock_session.flush.assert_called_once()

    async def test_permission_repository_save(
        self, permission_repository, sample_permission, mock_session
    ):
        """Test permission repository save operation."""
        mock_session.get.return_value = None  # Permission doesn't exist

        await permission_repository.save(sample_permission)

        mock_session.add.assert_called_once()
        mock_session.flush.assert_called_once()


class TestInfrastructureConfig:
    """Test infrastructure configuration."""

    def test_infrastructure_config_creation(self):
        """Test infrastructure configuration creation."""
        config = InfrastructureConfig()

        assert isinstance(config.database, DatabaseConfig)
        assert isinstance(config.redis, RedisConfig)
        assert isinstance(config.celery, CeleryConfig)
        assert isinstance(config.security, SecurityConfig)
        assert config.environment == "development"
        assert config.debug is False


# Integration tests would go here in a real implementation
# These would test actual database connections, Redis connections, etc.
# For now, we focus on unit tests with mocked dependencies
