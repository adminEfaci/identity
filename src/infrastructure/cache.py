"""Redis Cache Implementation for Identity Module.

This module provides Redis-based caching infrastructure with explicit
integration for performance optimization of domain operations.
"""

import json
import logging
from typing import TYPE_CHECKING, Any, Optional

import redis.asyncio as redis

from .config import RedisConfig

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = logging.getLogger(__name__)


class RedisCache:
    """Redis cache implementation with async support.

    Provides high-performance caching with automatic serialization,
    TTL management, and connection pooling for the Identity module.
    """

    def __init__(self, config: RedisConfig) -> None:
        """Initialize Redis cache with configuration.

        Args:
            config: Redis configuration settings
        """
        self._config = config
        self._redis: Optional[Redis] = None

    async def initialize(self) -> None:
        """Initialize Redis connection with connection pooling."""
        if self._redis is not None:
            logger.warning("Redis cache already initialized")
            return

        logger.info("Initializing Redis cache connection")

        # Create Redis connection with connection pooling
        self._redis = redis.from_url(
            self._config.url,
            max_connections=self._config.max_connections,
            retry_on_timeout=self._config.retry_on_timeout,
            socket_timeout=self._config.socket_timeout,
            socket_connect_timeout=self._config.socket_connect_timeout,
            decode_responses=True,
        )

        # Test connection
        try:
            await self._redis.ping()
            logger.info("Redis cache connection initialized successfully")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self._redis = None
            raise

    async def shutdown(self) -> None:
        """Shutdown Redis connections gracefully."""
        if self._redis is None:
            return

        logger.info("Shutting down Redis cache connections")
        await self._redis.aclose()
        self._redis = None
        logger.info("Redis cache connections closed")

    def _build_key(self, key: str) -> str:
        """Build full cache key with prefix.

        Args:
            key: Base cache key

        Returns:
            Full cache key with prefix
        """
        return f"{self._config.key_prefix}{key}"

    def _serialize_value(self, value: Any) -> str:
        """Serialize value for storage in Redis.

        Args:
            value: Value to serialize

        Returns:
            Serialized value as JSON string
        """
        if isinstance(value, (str, int, float, bool)):
            return json.dumps(value)
        elif value is None:
            return json.dumps(None)
        else:
            # For complex objects, use JSON serialization
            return json.dumps(value, default=str)

    def _deserialize_value(self, value: str) -> Any:
        """Deserialize value from Redis storage.

        Args:
            value: Serialized value from Redis

        Returns:
            Deserialized value
        """
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            # Return as string if JSON parsing fails
            return value

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value if found, None otherwise
        """
        if self._redis is None:
            raise RuntimeError("Redis cache not initialized")

        try:
            full_key = self._build_key(key)
            value = await self._redis.get(full_key)

            if value is None:
                logger.debug(f"Cache miss for key: {key}")
                return None

            logger.debug(f"Cache hit for key: {key}")
            return self._deserialize_value(value)

        except Exception as e:
            logger.error(f"Failed to get cache value for key {key}: {e}")
            return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
    ) -> bool:
        """Set value in cache with optional TTL.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds (uses default if not provided)

        Returns:
            True if successful, False otherwise
        """
        if self._redis is None:
            raise RuntimeError("Redis cache not initialized")

        try:
            full_key = self._build_key(key)
            serialized_value = self._serialize_value(value)
            cache_ttl = ttl or self._config.default_ttl

            result = await self._redis.setex(full_key, cache_ttl, serialized_value)
            logger.debug(f"Cached value for key: {key} (TTL: {cache_ttl}s)")
            return bool(result)

        except Exception as e:
            logger.error(f"Failed to set cache value for key {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete value from cache.

        Args:
            key: Cache key to delete

        Returns:
            True if key was deleted, False if key didn't exist
        """
        if self._redis is None:
            raise RuntimeError("Redis cache not initialized")

        try:
            full_key = self._build_key(key)
            result = await self._redis.delete(full_key)
            logger.debug(f"Deleted cache key: {key}")
            return bool(result)

        except Exception as e:
            logger.error(f"Failed to delete cache key {key}: {e}")
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists in cache.

        Args:
            key: Cache key to check

        Returns:
            True if key exists, False otherwise
        """
        if self._redis is None:
            raise RuntimeError("Redis cache not initialized")

        try:
            full_key = self._build_key(key)
            result = await self._redis.exists(full_key)
            return bool(result)

        except Exception as e:
            logger.error(f"Failed to check cache key existence {key}: {e}")
            return False

    async def expire(self, key: str, ttl: int) -> bool:
        """Set expiration time for a key.

        Args:
            key: Cache key
            ttl: Time to live in seconds

        Returns:
            True if successful, False otherwise
        """
        if self._redis is None:
            raise RuntimeError("Redis cache not initialized")

        try:
            full_key = self._build_key(key)
            result = await self._redis.expire(full_key, ttl)
            logger.debug(f"Set expiration for key: {key} (TTL: {ttl}s)")
            return bool(result)

        except Exception as e:
            logger.error(f"Failed to set expiration for key {key}: {e}")
            return False

    async def clear_pattern(self, pattern: str) -> int:
        """Clear all keys matching a pattern.

        Args:
            pattern: Key pattern (supports wildcards)

        Returns:
            Number of keys deleted
        """
        if self._redis is None:
            raise RuntimeError("Redis cache not initialized")

        try:
            full_pattern = self._build_key(pattern)
            keys = await self._redis.keys(full_pattern)

            if not keys:
                return 0

            deleted_count = await self._redis.delete(*keys)
            logger.info(f"Deleted {deleted_count} keys matching pattern: {pattern}")
            return deleted_count

        except Exception as e:
            logger.error(f"Failed to clear keys with pattern {pattern}: {e}")
            return 0

    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment a numeric value in cache.

        Args:
            key: Cache key
            amount: Amount to increment by

        Returns:
            New value after increment, None if failed
        """
        if self._redis is None:
            raise RuntimeError("Redis cache not initialized")

        try:
            full_key = self._build_key(key)
            result = await self._redis.incrby(full_key, amount)
            logger.debug(f"Incremented key: {key} by {amount} (new value: {result})")
            return result

        except Exception as e:
            logger.error(f"Failed to increment key {key}: {e}")
            return None

    async def get_ttl(self, key: str) -> Optional[int]:
        """Get remaining TTL for a key.

        Args:
            key: Cache key

        Returns:
            Remaining TTL in seconds, None if key doesn't exist or has no expiration
        """
        if self._redis is None:
            raise RuntimeError("Redis cache not initialized")

        try:
            full_key = self._build_key(key)
            ttl = await self._redis.ttl(full_key)

            if ttl == -2 or ttl == -1:  # Key doesn't exist
                return None
            else:
                return ttl

        except Exception as e:
            logger.error(f"Failed to get TTL for key {key}: {e}")
            return None


class CacheService:
    """High-level cache service for Identity module operations.

    Provides domain-specific caching operations with proper key management,
    cache invalidation strategies, and performance optimization.
    """

    def __init__(self, redis_cache: RedisCache) -> None:
        """Initialize cache service.

        Args:
            redis_cache: Redis cache implementation
        """
        self._cache = redis_cache

    # User caching operations

    async def get_user_by_id(self, user_id: str) -> Optional[dict]:
        """Get cached user by ID.

        Args:
            user_id: User ID

        Returns:
            Cached user data if found, None otherwise
        """
        return await self._cache.get(f"user:id:{user_id}")

    async def cache_user_by_id(
        self, user_id: str, user_data: dict, ttl: int = 3600
    ) -> bool:
        """Cache user data by ID.

        Args:
            user_id: User ID
            user_data: User data to cache
            ttl: Time to live in seconds

        Returns:
            True if successful, False otherwise
        """
        return await self._cache.set(f"user:id:{user_id}", user_data, ttl)

    async def get_user_by_email(self, email: str) -> Optional[dict]:
        """Get cached user by email.

        Args:
            email: User email

        Returns:
            Cached user data if found, None otherwise
        """
        return await self._cache.get(f"user:email:{email}")

    async def cache_user_by_email(
        self, email: str, user_data: dict, ttl: int = 3600
    ) -> bool:
        """Cache user data by email.

        Args:
            email: User email
            user_data: User data to cache
            ttl: Time to live in seconds

        Returns:
            True if successful, False otherwise
        """
        return await self._cache.set(f"user:email:{email}", user_data, ttl)

    async def invalidate_user_cache(self, user_id: str, email: str) -> None:
        """Invalidate all cache entries for a user.

        Args:
            user_id: User ID
            email: User email
        """
        await self._cache.delete(f"user:id:{user_id}")
        await self._cache.delete(f"user:email:{email}")
        await self._cache.clear_pattern(f"user:roles:{user_id}:*")

    # Role caching operations

    async def get_role_by_id(self, role_id: str) -> Optional[dict]:
        """Get cached role by ID.

        Args:
            role_id: Role ID

        Returns:
            Cached role data if found, None otherwise
        """
        return await self._cache.get(f"role:id:{role_id}")

    async def cache_role_by_id(
        self, role_id: str, role_data: dict, ttl: int = 7200
    ) -> bool:
        """Cache role data by ID.

        Args:
            role_id: Role ID
            role_data: Role data to cache
            ttl: Time to live in seconds

        Returns:
            True if successful, False otherwise
        """
        return await self._cache.set(f"role:id:{role_id}", role_data, ttl)

    async def get_role_by_name(self, name: str) -> Optional[dict]:
        """Get cached role by name.

        Args:
            name: Role name

        Returns:
            Cached role data if found, None otherwise
        """
        return await self._cache.get(f"role:name:{name}")

    async def cache_role_by_name(
        self, name: str, role_data: dict, ttl: int = 7200
    ) -> bool:
        """Cache role data by name.

        Args:
            name: Role name
            role_data: Role data to cache
            ttl: Time to live in seconds

        Returns:
            True if successful, False otherwise
        """
        return await self._cache.set(f"role:name:{name}", role_data, ttl)

    async def invalidate_role_cache(self, role_id: str, name: str) -> None:
        """Invalidate all cache entries for a role.

        Args:
            role_id: Role ID
            name: Role name
        """
        await self._cache.delete(f"role:id:{role_id}")
        await self._cache.delete(f"role:name:{name}")
        await self._cache.clear_pattern(f"role:permissions:{role_id}:*")

    # Permission caching operations

    async def get_permission_by_id(self, permission_id: str) -> Optional[dict]:
        """Get cached permission by ID.

        Args:
            permission_id: Permission ID

        Returns:
            Cached permission data if found, None otherwise
        """
        return await self._cache.get(f"permission:id:{permission_id}")

    async def cache_permission_by_id(
        self, permission_id: str, permission_data: dict, ttl: int = 7200
    ) -> bool:
        """Cache permission data by ID.

        Args:
            permission_id: Permission ID
            permission_data: Permission data to cache
            ttl: Time to live in seconds

        Returns:
            True if successful, False otherwise
        """
        return await self._cache.set(
            f"permission:id:{permission_id}", permission_data, ttl
        )

    async def invalidate_permission_cache(self, permission_id: str, name: str) -> None:
        """Invalidate all cache entries for a permission.

        Args:
            permission_id: Permission ID
            name: Permission name
        """
        await self._cache.delete(f"permission:id:{permission_id}")
        await self._cache.delete(f"permission:name:{name}")

    # Authorization caching operations

    async def get_user_permissions(self, user_id: str) -> Optional[list]:
        """Get cached user permissions.

        Args:
            user_id: User ID

        Returns:
            Cached permissions list if found, None otherwise
        """
        return await self._cache.get(f"user:permissions:{user_id}")

    async def cache_user_permissions(
        self, user_id: str, permissions: list, ttl: int = 1800
    ) -> bool:
        """Cache user permissions.

        Args:
            user_id: User ID
            permissions: List of permissions
            ttl: Time to live in seconds

        Returns:
            True if successful, False otherwise
        """
        return await self._cache.set(f"user:permissions:{user_id}", permissions, ttl)

    async def invalidate_user_permissions(self, user_id: str) -> None:
        """Invalidate cached user permissions.

        Args:
            user_id: User ID
        """
        await self._cache.delete(f"user:permissions:{user_id}")

    # Session and authentication caching

    async def cache_session(
        self, session_id: str, session_data: dict, ttl: int = 1800
    ) -> bool:
        """Cache session data.

        Args:
            session_id: Session ID
            session_data: Session data
            ttl: Time to live in seconds

        Returns:
            True if successful, False otherwise
        """
        return await self._cache.set(f"session:{session_id}", session_data, ttl)

    async def get_session(self, session_id: str) -> Optional[dict]:
        """Get cached session data.

        Args:
            session_id: Session ID

        Returns:
            Cached session data if found, None otherwise
        """
        return await self._cache.get(f"session:{session_id}")

    async def invalidate_session(self, session_id: str) -> None:
        """Invalidate session cache.

        Args:
            session_id: Session ID
        """
        await self._cache.delete(f"session:{session_id}")

    # Rate limiting operations

    async def increment_rate_limit(self, key: str, window_seconds: int) -> int:
        """Increment rate limit counter.

        Args:
            key: Rate limit key
            window_seconds: Time window in seconds

        Returns:
            Current count after increment
        """
        rate_key = f"rate_limit:{key}"
        count = await self._cache.increment(rate_key, 1)

        if count == 1:  # First request in window
            await self._cache.expire(rate_key, window_seconds)

        return count or 0

    async def get_rate_limit_count(self, key: str) -> int:
        """Get current rate limit count.

        Args:
            key: Rate limit key

        Returns:
            Current count
        """
        rate_key = f"rate_limit:{key}"
        count = await self._cache.get(rate_key)
        return count or 0

    async def reset_rate_limit(self, key: str) -> None:
        """Reset rate limit counter.

        Args:
            key: Rate limit key
        """
        await self._cache.delete(f"rate_limit:{key}")

    # Health check operations

    async def health_check(self) -> dict:
        """Perform cache health check.

        Returns:
            Health check results
        """
        try:
            # Test basic operations
            test_key = "health_check_test"
            test_value = "test_value"

            # Test set operation
            set_result = await self._cache.set(test_key, test_value, 60)
            if not set_result:
                return {"status": "unhealthy", "error": "Failed to set test value"}

            # Test get operation
            get_result = await self._cache.get(test_key)
            if get_result != test_value:
                return {"status": "unhealthy", "error": "Failed to get test value"}

            # Test delete operation
            delete_result = await self._cache.delete(test_key)
            if not delete_result:
                return {"status": "unhealthy", "error": "Failed to delete test value"}

            return {"status": "healthy", "message": "All cache operations successful"}

        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
