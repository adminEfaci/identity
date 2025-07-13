"""SQLAlchemy Models for Identity Module.

This module contains SQLAlchemy ORM models that map domain entities
to database tables. The models are designed to support the domain
layer without leaking persistence concerns into the domain.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    String,
    Table,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..domain.enums import PermissionScope, RoleType, UserStatus
from .database import Base

# Association table for user-role many-to-many relationship
user_roles = Table(
    "user_roles",
    Base.metadata,
    mapped_column(
        "user_id", PostgresUUID(as_uuid=True), ForeignKey("users.id"), primary_key=True
    ),
    mapped_column(
        "role_id", PostgresUUID(as_uuid=True), ForeignKey("roles.id"), primary_key=True
    ),
    mapped_column("assigned_at", DateTime(timezone=True), server_default=func.now()),
    mapped_column("assigned_by", PostgresUUID(as_uuid=True), nullable=False),
)

# Association table for role-permission many-to-many relationship
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    mapped_column(
        "role_id", PostgresUUID(as_uuid=True), ForeignKey("roles.id"), primary_key=True
    ),
    mapped_column(
        "permission_id",
        PostgresUUID(as_uuid=True),
        ForeignKey("permissions.id"),
        primary_key=True,
    ),
    mapped_column("assigned_at", DateTime(timezone=True), server_default=func.now()),
)


class UserModel(Base):
    """SQLAlchemy model for User entity.

    Maps the User domain entity to the users database table with proper
    constraints, indexes, and relationships.
    """

    __tablename__ = "users"

    # Primary key
    id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        comment="Unique identifier for the user",
    )

    # User attributes
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="User's email address (unique)",
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Hashed password",
    )

    password_algorithm: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="argon2",
        comment="Password hashing algorithm used",
    )

    password_salt: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Password salt (if applicable)",
    )

    status: Mapped[UserStatus] = mapped_column(
        Enum(UserStatus),
        nullable=False,
        default=UserStatus.PENDING_VERIFICATION,
        index=True,
        comment="Current user status",
    )

    # Audit fields
    created_by: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        nullable=False,
        comment="ID of user who created this record",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="Timestamp when record was created",
    )

    modified_by: Mapped[Optional[UUID]] = mapped_column(
        PostgresUUID(as_uuid=True),
        nullable=True,
        comment="ID of user who last modified this record",
    )

    modified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when record was last modified",
    )

    # Relationships
    roles: Mapped[list["RoleModel"]] = relationship(
        "RoleModel",
        secondary=user_roles,
        back_populates="users",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        """String representation of the user model."""
        return f"<UserModel(id={self.id}, email={self.email}, status={self.status})>"


class RoleModel(Base):
    """SQLAlchemy model for Role entity.

    Maps the Role domain entity to the roles database table with proper
    constraints, indexes, and relationships.
    """

    __tablename__ = "roles"

    # Primary key
    id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        comment="Unique identifier for the role",
    )

    # Role attributes
    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
        comment="Role name (unique)",
    )

    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Role description",
    )

    role_type: Mapped[RoleType] = mapped_column(
        Enum(RoleType),
        nullable=False,
        default=RoleType.CUSTOM,
        index=True,
        comment="Type of role (system or custom)",
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="Whether the role is active",
    )

    # Audit fields
    created_by: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        nullable=False,
        comment="ID of user who created this record",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="Timestamp when record was created",
    )

    modified_by: Mapped[Optional[UUID]] = mapped_column(
        PostgresUUID(as_uuid=True),
        nullable=True,
        comment="ID of user who last modified this record",
    )

    modified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when record was last modified",
    )

    # Relationships
    users: Mapped[list[UserModel]] = relationship(
        "UserModel",
        secondary=user_roles,
        back_populates="roles",
        lazy="selectin",
    )

    permissions: Mapped[list["PermissionModel"]] = relationship(
        "PermissionModel",
        secondary=role_permissions,
        back_populates="roles",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        """String representation of the role model."""
        return f"<RoleModel(id={self.id}, name={self.name}, type={self.role_type})>"


class PermissionModel(Base):
    """SQLAlchemy model for Permission entity.

    Maps the Permission domain entity to the permissions database table with proper
    constraints, indexes, and relationships.
    """

    __tablename__ = "permissions"

    # Primary key
    id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        comment="Unique identifier for the permission",
    )

    # Permission attributes
    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
        comment="Permission name (unique)",
    )

    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Permission description",
    )

    resource: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Resource the permission applies to",
    )

    action: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Action the permission allows",
    )

    scope: Mapped[PermissionScope] = mapped_column(
        Enum(PermissionScope),
        nullable=False,
        default=PermissionScope.RESOURCE,
        index=True,
        comment="Scope of the permission",
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="Whether the permission is active",
    )

    # Audit fields
    created_by: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        nullable=False,
        comment="ID of user who created this record",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="Timestamp when record was created",
    )

    modified_by: Mapped[Optional[UUID]] = mapped_column(
        PostgresUUID(as_uuid=True),
        nullable=True,
        comment="ID of user who last modified this record",
    )

    modified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when record was last modified",
    )

    # Relationships
    roles: Mapped[list[RoleModel]] = relationship(
        "RoleModel",
        secondary=role_permissions,
        back_populates="permissions",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        """String representation of the permission model."""
        return f"<PermissionModel(id={self.id}, name={self.name}, resource={self.resource}, action={self.action})>"
