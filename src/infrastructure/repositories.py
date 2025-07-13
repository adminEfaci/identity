"""SQLAlchemy Repository Implementations.

This module provides concrete implementations of domain repository interfaces
using SQLAlchemy for data persistence. The repositories handle the mapping
between domain entities and SQLAlchemy models.
"""

import logging
from typing import Optional

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..domain.entities import Permission, Role, User
from ..domain.enums import PermissionScope, RoleType, UserStatus
from ..domain.repositories import PermissionRepository, RoleRepository, UserRepository
from ..domain.value_objects import Email, PermissionId, RoleId, UserId
from .models import PermissionModel, RoleModel, UserModel

logger = logging.getLogger(__name__)


class SqlAlchemyUserRepository(UserRepository):
    """SQLAlchemy implementation of UserRepository.

    Provides data access operations for User entities using SQLAlchemy ORM
    with proper async support and domain entity mapping.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: SQLAlchemy async session
        """
        self._session = session

    def _model_to_entity(self, model: UserModel) -> User:
        """Convert SQLAlchemy model to domain entity.

        Args:
            model: SQLAlchemy user model

        Returns:
            User domain entity
        """
        from ..domain.value_objects import AuditInfo, Email, PasswordHash

        # Convert role models to role IDs
        role_ids = {RoleId(role.id) for role in model.roles}

        # Create audit info
        audit_info = AuditInfo(
            created_by=model.created_by,
            created_at=model.created_at,
            modified_by=model.modified_by,
            modified_at=model.modified_at,
        )

        # Create password hash
        password_hash = PasswordHash(
            hash_value=model.password_hash,
            algorithm=model.password_algorithm,
            salt=model.password_salt,
        )

        # Create user entity
        user = User(
            id=UserId(model.id),
            email=Email(model.email),
            password_hash=password_hash,
            status=model.status,
            audit_info=audit_info,
            role_ids=role_ids,
        )

        # Clear domain events as they're already persisted
        user.clear_domain_events()
        return user

    def _entity_to_model(self, entity: User) -> UserModel:
        """Convert domain entity to SQLAlchemy model.

        Args:
            entity: User domain entity

        Returns:
            SQLAlchemy user model
        """
        return UserModel(
            id=entity.id.value,
            email=entity.email.value,
            password_hash=entity.password_hash.hash_value,
            password_algorithm=entity.password_hash.algorithm,
            password_salt=entity.password_hash.salt,
            status=entity.status,
            created_by=entity.audit_info.created_by,
            created_at=entity.audit_info.created_at,
            modified_by=entity.audit_info.modified_by,
            modified_at=entity.audit_info.modified_at,
        )

    async def save(self, user: User) -> None:
        """Save a user entity.

        Args:
            user: User entity to save

        Raises:
            RepositoryError: If the save operation fails
        """
        try:
            # Check if user exists
            existing = await self._session.get(UserModel, user.id.value)

            if existing:
                # Update existing user
                existing.email = user.email.value
                existing.password_hash = user.password_hash.hash_value
                existing.password_algorithm = user.password_hash.algorithm
                existing.password_salt = user.password_hash.salt
                existing.status = user.status
                existing.modified_by = user.audit_info.modified_by
                existing.modified_at = user.audit_info.modified_at

                # Update role relationships
                # First, load existing roles
                await self._session.refresh(existing, ["roles"])

                # Clear existing roles and add new ones
                existing.roles.clear()
                for role_id in user.role_ids:
                    role_model = await self._session.get(RoleModel, role_id.value)
                    if role_model:
                        existing.roles.append(role_model)

                logger.debug(f"Updated user {user.id}")
            else:
                # Create new user
                model = self._entity_to_model(user)

                # Add role relationships
                for role_id in user.role_ids:
                    role_model = await self._session.get(RoleModel, role_id.value)
                    if role_model:
                        model.roles.append(role_model)

                self._session.add(model)
                logger.debug(f"Created user {user.id}")

            await self._session.flush()

        except Exception as e:
            logger.error(f"Failed to save user {user.id}: {e}")
            raise

    async def find_by_id(self, user_id: UserId) -> Optional[User]:
        """Find a user by their ID.

        Args:
            user_id: User ID to search for

        Returns:
            User entity if found, None otherwise
        """
        try:
            stmt = (
                select(UserModel)
                .options(selectinload(UserModel.roles))
                .where(UserModel.id == user_id.value)
            )
            result = await self._session.execute(stmt)
            model = result.scalar_one_or_none()

            if model:
                return self._model_to_entity(model)
            return None

        except Exception as e:
            logger.error(f"Failed to find user by ID {user_id}: {e}")
            raise

    async def find_by_email(self, email: Email) -> Optional[User]:
        """Find a user by their email address.

        Args:
            email: Email address to search for

        Returns:
            User entity if found, None otherwise
        """
        try:
            stmt = (
                select(UserModel)
                .options(selectinload(UserModel.roles))
                .where(UserModel.email == email.value)
            )
            result = await self._session.execute(stmt)
            model = result.scalar_one_or_none()

            if model:
                return self._model_to_entity(model)
            return None

        except Exception as e:
            logger.error(f"Failed to find user by email {email}: {e}")
            raise

    async def find_by_status(self, status: UserStatus) -> list[User]:
        """Find all users with a specific status.

        Args:
            status: User status to filter by

        Returns:
            List of users with the specified status
        """
        try:
            stmt = (
                select(UserModel)
                .options(selectinload(UserModel.roles))
                .where(UserModel.status == status)
                .order_by(UserModel.created_at.desc())
            )
            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._model_to_entity(model) for model in models]

        except Exception as e:
            logger.error(f"Failed to find users by status {status}: {e}")
            raise

    async def find_by_role(self, role_id: RoleId) -> list[User]:
        """Find all users with a specific role.

        Args:
            role_id: Role ID to filter by

        Returns:
            List of users with the specified role
        """
        try:
            stmt = (
                select(UserModel)
                .options(selectinload(UserModel.roles))
                .join(UserModel.roles)
                .where(RoleModel.id == role_id.value)
                .order_by(UserModel.created_at.desc())
            )
            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._model_to_entity(model) for model in models]

        except Exception as e:
            logger.error(f"Failed to find users by role {role_id}: {e}")
            raise

    async def find_all(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> list[User]:
        """Find all users with optional pagination.

        Args:
            limit: Maximum number of users to return
            offset: Number of users to skip

        Returns:
            List of users
        """
        try:
            stmt = (
                select(UserModel)
                .options(selectinload(UserModel.roles))
                .order_by(UserModel.created_at.desc())
            )

            if offset:
                stmt = stmt.offset(offset)
            if limit:
                stmt = stmt.limit(limit)

            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._model_to_entity(model) for model in models]

        except Exception as e:
            logger.error(f"Failed to find all users: {e}")
            raise

    async def exists_by_email(self, email: Email) -> bool:
        """Check if a user exists with the given email.

        Args:
            email: Email address to check

        Returns:
            True if user exists, False otherwise
        """
        try:
            stmt = select(func.count(UserModel.id)).where(
                UserModel.email == email.value
            )
            result = await self._session.execute(stmt)
            count = result.scalar()
            return count > 0

        except Exception as e:
            logger.error(f"Failed to check if user exists by email {email}: {e}")
            raise

    async def count_by_status(self, status: UserStatus) -> int:
        """Count users by status.

        Args:
            status: User status to count

        Returns:
            Number of users with the specified status
        """
        try:
            stmt = select(func.count(UserModel.id)).where(UserModel.status == status)
            result = await self._session.execute(stmt)
            return result.scalar()

        except Exception as e:
            logger.error(f"Failed to count users by status {status}: {e}")
            raise

    async def delete(self, user_id: UserId) -> bool:
        """Delete a user by ID.

        Args:
            user_id: ID of the user to delete

        Returns:
            True if user was deleted, False if not found
        """
        try:
            model = await self._session.get(UserModel, user_id.value)
            if model:
                await self._session.delete(model)
                await self._session.flush()
                logger.debug(f"Deleted user {user_id}")
                return True
            return False

        except Exception as e:
            logger.error(f"Failed to delete user {user_id}: {e}")
            raise

    async def search_by_email_pattern(self, pattern: str) -> list[User]:
        """Search users by email pattern.

        Args:
            pattern: Email pattern to search for (supports wildcards)

        Returns:
            List of users matching the pattern
        """
        try:
            # Convert wildcards to SQL LIKE pattern
            sql_pattern = pattern.replace("*", "%").replace("?", "_")

            stmt = (
                select(UserModel)
                .options(selectinload(UserModel.roles))
                .where(UserModel.email.like(sql_pattern))
                .order_by(UserModel.created_at.desc())
            )
            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._model_to_entity(model) for model in models]

        except Exception as e:
            logger.error(f"Failed to search users by email pattern {pattern}: {e}")
            raise


class SqlAlchemyRoleRepository(RoleRepository):
    """SQLAlchemy implementation of RoleRepository.

    Provides data access operations for Role entities using SQLAlchemy ORM
    with proper async support and domain entity mapping.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: SQLAlchemy async session
        """
        self._session = session

    def _model_to_entity(self, model: RoleModel) -> Role:
        """Convert SQLAlchemy model to domain entity.

        Args:
            model: SQLAlchemy role model

        Returns:
            Role domain entity
        """
        from ..domain.value_objects import AuditInfo

        # Convert permission models to permission IDs
        permission_ids = {PermissionId(perm.id) for perm in model.permissions}

        # Create audit info
        audit_info = AuditInfo(
            created_by=model.created_by,
            created_at=model.created_at,
            modified_by=model.modified_by,
            modified_at=model.modified_at,
        )

        # Create role entity
        role = Role(
            id=RoleId(model.id),
            name=model.name,
            description=model.description,
            role_type=model.role_type,
            audit_info=audit_info,
            permission_ids=permission_ids,
            is_active=model.is_active,
        )

        return role

    def _entity_to_model(self, entity: Role) -> RoleModel:
        """Convert domain entity to SQLAlchemy model.

        Args:
            entity: Role domain entity

        Returns:
            SQLAlchemy role model
        """
        return RoleModel(
            id=entity.id.value,
            name=entity.name,
            description=entity.description,
            role_type=entity.role_type,
            is_active=entity.is_active,
            created_by=entity.audit_info.created_by,
            created_at=entity.audit_info.created_at,
            modified_by=entity.audit_info.modified_by,
            modified_at=entity.audit_info.modified_at,
        )

    async def save(self, role: Role) -> None:
        """Save a role entity.

        Args:
            role: Role entity to save
        """
        try:
            # Check if role exists
            existing = await self._session.get(RoleModel, role.id.value)

            if existing:
                # Update existing role
                existing.name = role.name
                existing.description = role.description
                existing.role_type = role.role_type
                existing.is_active = role.is_active
                existing.modified_by = role.audit_info.modified_by
                existing.modified_at = role.audit_info.modified_at

                # Update permission relationships
                await self._session.refresh(existing, ["permissions"])
                existing.permissions.clear()
                for permission_id in role.permission_ids:
                    permission_model = await self._session.get(
                        PermissionModel, permission_id.value
                    )
                    if permission_model:
                        existing.permissions.append(permission_model)

                logger.debug(f"Updated role {role.id}")
            else:
                # Create new role
                model = self._entity_to_model(role)

                # Add permission relationships
                for permission_id in role.permission_ids:
                    permission_model = await self._session.get(
                        PermissionModel, permission_id.value
                    )
                    if permission_model:
                        model.permissions.append(permission_model)

                self._session.add(model)
                logger.debug(f"Created role {role.id}")

            await self._session.flush()

        except Exception as e:
            logger.error(f"Failed to save role {role.id}: {e}")
            raise

    async def find_by_id(self, role_id: RoleId) -> Optional[Role]:
        """Find a role by its ID.

        Args:
            role_id: Role ID to search for

        Returns:
            Role entity if found, None otherwise
        """
        try:
            stmt = (
                select(RoleModel)
                .options(selectinload(RoleModel.permissions))
                .where(RoleModel.id == role_id.value)
            )
            result = await self._session.execute(stmt)
            model = result.scalar_one_or_none()

            if model:
                return self._model_to_entity(model)
            return None

        except Exception as e:
            logger.error(f"Failed to find role by ID {role_id}: {e}")
            raise

    async def find_by_name(self, name: str) -> Optional[Role]:
        """Find a role by its name.

        Args:
            name: Role name to search for

        Returns:
            Role entity if found, None otherwise
        """
        try:
            stmt = (
                select(RoleModel)
                .options(selectinload(RoleModel.permissions))
                .where(RoleModel.name == name)
            )
            result = await self._session.execute(stmt)
            model = result.scalar_one_or_none()

            if model:
                return self._model_to_entity(model)
            return None

        except Exception as e:
            logger.error(f"Failed to find role by name {name}: {e}")
            raise

    async def find_by_type(self, role_type: RoleType) -> list[Role]:
        """Find all roles of a specific type.

        Args:
            role_type: Role type to filter by

        Returns:
            List of roles with the specified type
        """
        try:
            stmt = (
                select(RoleModel)
                .options(selectinload(RoleModel.permissions))
                .where(RoleModel.role_type == role_type)
                .order_by(RoleModel.name)
            )
            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._model_to_entity(model) for model in models]

        except Exception as e:
            logger.error(f"Failed to find roles by type {role_type}: {e}")
            raise

    async def find_by_permission(self, permission_id: PermissionId) -> list[Role]:
        """Find all roles that have a specific permission.

        Args:
            permission_id: Permission ID to filter by

        Returns:
            List of roles with the specified permission
        """
        try:
            stmt = (
                select(RoleModel)
                .options(selectinload(RoleModel.permissions))
                .join(RoleModel.permissions)
                .where(PermissionModel.id == permission_id.value)
                .order_by(RoleModel.name)
            )
            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._model_to_entity(model) for model in models]

        except Exception as e:
            logger.error(f"Failed to find roles by permission {permission_id}: {e}")
            raise

    async def find_all_active(self) -> list[Role]:
        """Find all active roles.

        Returns:
            List of active roles
        """
        try:
            stmt = (
                select(RoleModel)
                .options(selectinload(RoleModel.permissions))
                .where(RoleModel.is_active)
                .order_by(RoleModel.name)
            )
            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._model_to_entity(model) for model in models]

        except Exception:
            logger.error("Failed to find all active roles: {e}")
            raise

    async def find_all(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> list[Role]:
        """Find all roles with optional pagination.

        Args:
            limit: Maximum number of roles to return
            offset: Number of roles to skip

        Returns:
            List of roles
        """
        try:
            stmt = (
                select(RoleModel)
                .options(selectinload(RoleModel.permissions))
                .order_by(RoleModel.name)
            )

            if offset:
                stmt = stmt.offset(offset)
            if limit:
                stmt = stmt.limit(limit)

            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._model_to_entity(model) for model in models]

        except Exception as e:
            logger.error(f"Failed to find all roles: {e}")
            raise

    async def exists_by_name(self, name: str) -> bool:
        """Check if a role exists with the given name.

        Args:
            name: Role name to check

        Returns:
            True if role exists, False otherwise
        """
        try:
            stmt = select(func.count(RoleModel.id)).where(RoleModel.name == name)
            result = await self._session.execute(stmt)
            count = result.scalar()
            return count > 0

        except Exception as e:
            logger.error(f"Failed to check if role exists by name {name}: {e}")
            raise

    async def delete(self, role_id: RoleId) -> bool:
        """Delete a role by ID.

        Args:
            role_id: ID of the role to delete

        Returns:
            True if role was deleted, False if not found
        """
        try:
            model = await self._session.get(RoleModel, role_id.value)
            if model:
                await self._session.delete(model)
                await self._session.flush()
                logger.debug(f"Deleted role {role_id}")
                return True
            return False

        except Exception as e:
            logger.error(f"Failed to delete role {role_id}: {e}")
            raise

    async def find_system_roles(self) -> list[Role]:
        """Find all system roles.

        Returns:
            List of system roles
        """
        try:
            stmt = (
                select(RoleModel)
                .options(selectinload(RoleModel.permissions))
                .where(RoleModel.role_type == RoleType.SYSTEM)
                .order_by(RoleModel.name)
            )
            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._model_to_entity(model) for model in models]

        except Exception as e:
            logger.error(f"Failed to find system roles: {e}")
            raise


class SqlAlchemyPermissionRepository(PermissionRepository):
    """SQLAlchemy implementation of PermissionRepository.

    Provides data access operations for Permission entities using SQLAlchemy ORM
    with proper async support and domain entity mapping.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: SQLAlchemy async session
        """
        self._session = session

    def _model_to_entity(self, model: PermissionModel) -> Permission:
        """Convert SQLAlchemy model to domain entity.

        Args:
            model: SQLAlchemy permission model

        Returns:
            Permission domain entity
        """
        from ..domain.value_objects import AuditInfo

        # Create audit info
        audit_info = AuditInfo(
            created_by=model.created_by,
            created_at=model.created_at,
            modified_by=model.modified_by,
            modified_at=model.modified_at,
        )

        # Create permission entity
        permission = Permission(
            id=PermissionId(model.id),
            name=model.name,
            description=model.description,
            resource=model.resource,
            action=model.action,
            scope=model.scope,
            audit_info=audit_info,
            is_active=model.is_active,
        )

        return permission

    def _entity_to_model(self, entity: Permission) -> PermissionModel:
        """Convert domain entity to SQLAlchemy model.

        Args:
            entity: Permission domain entity

        Returns:
            SQLAlchemy permission model
        """
        return PermissionModel(
            id=entity.id.value,
            name=entity.name,
            description=entity.description,
            resource=entity.resource,
            action=entity.action,
            scope=entity.scope,
            is_active=entity.is_active,
            created_by=entity.audit_info.created_by,
            created_at=entity.audit_info.created_at,
            modified_by=entity.audit_info.modified_by,
            modified_at=entity.audit_info.modified_at,
        )

    async def save(self, permission: Permission) -> None:
        """Save a permission entity.

        Args:
            permission: Permission entity to save
        """
        try:
            # Check if permission exists
            existing = await self._session.get(PermissionModel, permission.id.value)

            if existing:
                # Update existing permission
                existing.name = permission.name
                existing.description = permission.description
                existing.resource = permission.resource
                existing.action = permission.action
                existing.scope = permission.scope
                existing.is_active = permission.is_active
                existing.modified_by = permission.audit_info.modified_by
                existing.modified_at = permission.audit_info.modified_at

                logger.debug(f"Updated permission {permission.id}")
            else:
                # Create new permission
                model = self._entity_to_model(permission)
                self._session.add(model)
                logger.debug(f"Created permission {permission.id}")

            await self._session.flush()

        except Exception as e:
            logger.error(f"Failed to save permission {permission.id}: {e}")
            raise

    async def find_by_id(self, permission_id: PermissionId) -> Optional[Permission]:
        """Find a permission by its ID.

        Args:
            permission_id: Permission ID to search for

        Returns:
            Permission entity if found, None otherwise
        """
        try:
            model = await self._session.get(PermissionModel, permission_id.value)
            if model:
                return self._model_to_entity(model)
            return None

        except Exception as e:
            logger.error(f"Failed to find permission by ID {permission_id}: {e}")
            raise

    async def find_by_name(self, name: str) -> Optional[Permission]:
        """Find a permission by its name.

        Args:
            name: Permission name to search for

        Returns:
            Permission entity if found, None otherwise
        """
        try:
            stmt = select(PermissionModel).where(PermissionModel.name == name)
            result = await self._session.execute(stmt)
            model = result.scalar_one_or_none()

            if model:
                return self._model_to_entity(model)
            return None

        except Exception as e:
            logger.error(f"Failed to find permission by name {name}: {e}")
            raise

    async def find_by_resource_and_action(
        self,
        resource: str,
        action: str,
    ) -> list[Permission]:
        """Find permissions by resource and action.

        Args:
            resource: Resource name to filter by
            action: Action name to filter by

        Returns:
            List of permissions matching the criteria
        """
        try:
            stmt = (
                select(PermissionModel)
                .where(
                    and_(
                        PermissionModel.resource == resource,
                        PermissionModel.action == action,
                    )
                )
                .order_by(PermissionModel.scope)
            )
            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._model_to_entity(model) for model in models]

        except Exception as e:
            logger.error(
                f"Failed to find permissions by resource {resource} and action {action}: {e}"
            )
            raise

    async def find_by_scope(self, scope: PermissionScope) -> list[Permission]:
        """Find all permissions with a specific scope.

        Args:
            scope: Permission scope to filter by

        Returns:
            List of permissions with the specified scope
        """
        try:
            stmt = (
                select(PermissionModel)
                .where(PermissionModel.scope == scope)
                .order_by(PermissionModel.resource, PermissionModel.action)
            )
            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._model_to_entity(model) for model in models]

        except Exception as e:
            logger.error(f"Failed to find permissions by scope {scope}: {e}")
            raise

    async def find_by_resource(self, resource: str) -> list[Permission]:
        """Find all permissions for a specific resource.

        Args:
            resource: Resource name to filter by

        Returns:
            List of permissions for the specified resource
        """
        try:
            stmt = (
                select(PermissionModel)
                .where(PermissionModel.resource == resource)
                .order_by(PermissionModel.action, PermissionModel.scope)
            )
            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._model_to_entity(model) for model in models]

        except Exception as e:
            logger.error(f"Failed to find permissions by resource {resource}: {e}")
            raise

    async def find_all_active(self) -> list[Permission]:
        """Find all active permissions.

        Returns:
            List of active permissions
        """
        try:
            stmt = (
                select(PermissionModel)
                .where(PermissionModel.is_active)
                .order_by(
                    PermissionModel.resource,
                    PermissionModel.action,
                    PermissionModel.scope,
                )
            )
            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._model_to_entity(model) for model in models]

        except Exception as e:
            logger.error(f"Failed to find all active permissions: {e}")
            raise

    async def find_all(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> list[Permission]:
        """Find all permissions with optional pagination.

        Args:
            limit: Maximum number of permissions to return
            offset: Number of permissions to skip

        Returns:
            List of permissions
        """
        try:
            stmt = select(PermissionModel).order_by(
                PermissionModel.resource,
                PermissionModel.action,
                PermissionModel.scope,
            )

            if offset:
                stmt = stmt.offset(offset)
            if limit:
                stmt = stmt.limit(limit)

            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._model_to_entity(model) for model in models]

        except Exception as e:
            logger.error(f"Failed to find all permissions: {e}")
            raise

    async def exists_by_name(self, name: str) -> bool:
        """Check if a permission exists with the given name.

        Args:
            name: Permission name to check

        Returns:
            True if permission exists, False otherwise
        """
        try:
            stmt = select(func.count(PermissionModel.id)).where(
                PermissionModel.name == name
            )
            result = await self._session.execute(stmt)
            count = result.scalar()
            return count > 0

        except Exception as e:
            logger.error(f"Failed to check if permission exists by name {name}: {e}")
            raise

    async def delete(self, permission_id: PermissionId) -> bool:
        """Delete a permission by ID.

        Args:
            permission_id: ID of the permission to delete

        Returns:
            True if permission was deleted, False if not found
        """
        try:
            model = await self._session.get(PermissionModel, permission_id.value)
            if model:
                await self._session.delete(model)
                await self._session.flush()
                logger.debug(f"Deleted permission {permission_id}")
                return True
            return False

        except Exception as e:
            logger.error(f"Failed to delete permission {permission_id}: {e}")
            raise

    async def find_by_ids(self, permission_ids: set[PermissionId]) -> list[Permission]:
        """Find permissions by a set of IDs.

        Args:
            permission_ids: Set of permission IDs to find

        Returns:
            List of permissions found
        """
        try:
            if not permission_ids:
                return []

            ids = [pid.value for pid in permission_ids]
            stmt = (
                select(PermissionModel)
                .where(PermissionModel.id.in_(ids))
                .order_by(
                    PermissionModel.resource,
                    PermissionModel.action,
                    PermissionModel.scope,
                )
            )
            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._model_to_entity(model) for model in models]

        except Exception as e:
            logger.error(f"Failed to find permissions by IDs: {e}")
            raise
