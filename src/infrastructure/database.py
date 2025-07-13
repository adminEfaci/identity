"""Database Infrastructure Components.

This module provides SQLAlchemy-based database management, session handling,
and database configuration for the Identity module.
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any, Optional

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from .config import DatabaseConfig

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    pass


class DatabaseManager:
    """Database manager for handling SQLAlchemy engine and session configuration.

    Provides centralized database connection management with proper async support,
    connection pooling, and configuration management.
    """

    def __init__(self, config: DatabaseConfig) -> None:
        """Initialize database manager with configuration.

        Args:
            config: Database configuration settings
        """
        self._config = config
        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[async_sessionmaker[AsyncSession]] = None

    async def initialize(self) -> None:
        """Initialize database engine and session factory."""
        if self._engine is not None:
            logger.warning("Database manager already initialized")
            return

        logger.info("Initializing database connection")

        # Create async engine with connection pooling
        self._engine = create_async_engine(
            self._config.url,
            echo=self._config.echo_sql,
            pool_size=self._config.pool_size,
            max_overflow=self._config.max_overflow,
            pool_timeout=self._config.pool_timeout,
            pool_recycle=self._config.pool_recycle,
            pool_pre_ping=True,  # Validate connections before use
        )

        # Create session factory
        self._session_factory = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        logger.info("Database connection initialized successfully")

    async def shutdown(self) -> None:
        """Shutdown database connections gracefully."""
        if self._engine is None:
            return

        logger.info("Shutting down database connections")
        await self._engine.dispose()
        self._engine = None
        self._session_factory = None
        logger.info("Database connections closed")

    @property
    def engine(self) -> AsyncEngine:
        """Get the database engine.

        Returns:
            SQLAlchemy async engine

        Raises:
            RuntimeError: If database manager is not initialized
        """
        if self._engine is None:
            raise RuntimeError("Database manager not initialized")
        return self._engine

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Get the session factory.

        Returns:
            SQLAlchemy async session factory

        Raises:
            RuntimeError: If database manager is not initialized
        """
        if self._session_factory is None:
            raise RuntimeError("Database manager not initialized")
        return self._session_factory

    async def create_all_tables(self) -> None:
        """Create all database tables.

        This should only be used in development/testing.
        In production, use Alembic migrations.
        """
        if self._engine is None:
            raise RuntimeError("Database manager not initialized")

        logger.info("Creating all database tables")
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("All database tables created")

    async def drop_all_tables(self) -> None:
        """Drop all database tables.

        This should only be used in development/testing.
        """
        if self._engine is None:
            raise RuntimeError("Database manager not initialized")

        logger.warning("Dropping all database tables")
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        logger.warning("All database tables dropped")


class SessionManager:
    """Session manager for handling database sessions with proper lifecycle management.

    Provides context managers for database sessions with automatic transaction
    handling, rollback on errors, and proper resource cleanup.
    """

    def __init__(self, database_manager: DatabaseManager) -> None:
        """Initialize session manager.

        Args:
            database_manager: Database manager instance
        """
        self._database_manager = database_manager

    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session with automatic transaction management.

        Yields:
            SQLAlchemy async session

        The session is automatically committed on successful completion
        and rolled back on any exception.
        """
        session_factory = self._database_manager.session_factory
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    @asynccontextmanager
    async def get_read_only_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a read-only database session.

        Yields:
            SQLAlchemy async session configured for read-only operations

        This session automatically rolls back any changes and is optimized
        for read operations.
        """
        session_factory = self._database_manager.session_factory
        async with session_factory() as session:
            try:
                # Configure session for read-only operations
                session.info["read_only"] = True
                yield session
            finally:
                await session.rollback()  # Always rollback for read-only
                await session.close()

    async def execute_in_transaction(
        self,
        operation: callable,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Execute an operation within a database transaction.

        Args:
            operation: Async function to execute
            *args: Positional arguments for the operation
            **kwargs: Keyword arguments for the operation

        Returns:
            Result of the operation

        The operation receives the session as its first argument.
        """
        async with self.get_session() as session:
            return await operation(session, *args, **kwargs)
