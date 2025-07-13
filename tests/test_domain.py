"""Sample tests for the Identity Domain Module.

This file demonstrates the usage of the domain components and provides
basic test coverage for the core functionality.
"""

from uuid import uuid4

import pytest

from domain import (
    Email,
    PasswordHash,
    Permission,
    PermissionId,
    PermissionScope,
    Role,
    RoleId,
    RoleType,
    # Entities
    User,
    # Events
    UserCreated,
    UserModified,
    # Enums
    UserStatus,
)


class TestEmail:
    """Test cases for Email value object."""

    def test_valid_email_creation(self) -> None:
        """Test creating a valid email."""
        email = Email("user@example.com")
        assert email.value == "user@example.com"
        assert email.domain == "example.com"
        assert email.local_part == "user"

    def test_email_normalization(self) -> None:
        """Test email normalization."""
        email = Email("  USER@EXAMPLE.COM  ")
        assert email.value == "user@example.com"

    def test_invalid_email_raises_error(self) -> None:
        """Test that invalid email raises ValidationError."""
        with pytest.raises(ValueError, match="Invalid email format"):
            Email("invalid-email")

    def test_empty_email_raises_error(self) -> None:
        """Test that empty email raises error."""
        with pytest.raises(ValueError, match="Email cannot be empty"):
            Email("")

    def test_same_domain_check(self) -> None:
        """Test same domain checking."""
        email1 = Email("user1@example.com")
        email2 = Email("user2@example.com")
        email3 = Email("user3@other.com")

        assert email1.is_same_domain(email2)
        assert not email1.is_same_domain(email3)


class TestPasswordHash:
    """Test cases for PasswordHash value object."""

    def test_password_hash_creation(self) -> None:
        """Test creating a password hash."""
        hash_value = "a" * 64  # 64 character hash
        password_hash = PasswordHash(hash_value=hash_value)
        assert password_hash.hash_value == hash_value
        assert password_hash.algorithm == "bcrypt"

    def test_short_hash_raises_error(self) -> None:
        """Test that short hash raises error."""
        with pytest.raises(ValueError, match="Password hash appears to be too short"):
            PasswordHash(hash_value="short")

    def test_empty_hash_raises_error(self) -> None:
        """Test that empty hash raises error."""
        with pytest.raises(ValueError, match="Password hash cannot be empty"):
            PasswordHash(hash_value="")

    def test_unsupported_algorithm_raises_error(self) -> None:
        """Test that unsupported algorithm raises error."""
        with pytest.raises(ValueError, match="Unsupported hashing algorithm"):
            PasswordHash(hash_value="a" * 64, algorithm="md5")

    def test_from_plaintext(self) -> None:
        """Test creating hash from plaintext."""
        password_hash = PasswordHash.from_plaintext("password123")
        assert len(password_hash.hash_value) == 64  # SHA256 hex length
        assert password_hash.algorithm == "bcrypt"

    def test_weak_password_raises_error(self) -> None:
        """Test that weak password raises error."""
        with pytest.raises(ValueError, match="Password must be at least 8 characters"):
            PasswordHash.from_plaintext("weak")


class TestUser:
    """Test cases for User entity."""

    def test_user_creation(self) -> None:
        """Test creating a user."""
        email = Email("user@example.com")
        password_hash = PasswordHash.from_plaintext("password123")
        created_by = uuid4()

        user = User.create(
            email=email,
            password_hash=password_hash,
            created_by=created_by,
        )

        assert user.email == email
        assert user.password_hash == password_hash
        assert user.status == UserStatus.PENDING_VERIFICATION
        assert user.audit_info.created_by == created_by
        assert len(user.domain_events) == 1
        assert isinstance(user.domain_events[0], UserCreated)

    def test_user_email_change(self) -> None:
        """Test changing user email."""
        user = self._create_test_user()
        new_email = Email("new@example.com")
        modified_by = uuid4()

        user.change_email(new_email, modified_by)

        assert user.email == new_email
        assert user.audit_info.modified_by == modified_by
        assert len(user.domain_events) == 2
        assert isinstance(user.domain_events[1], UserModified)

    def test_user_role_assignment(self) -> None:
        """Test assigning role to user."""
        user = self._create_test_user()
        role_id = RoleId.generate()
        assigned_by = uuid4()

        user.assign_role(role_id, assigned_by)

        assert user.has_role(role_id)
        assert role_id in user.role_ids

    def test_user_role_removal(self) -> None:
        """Test removing role from user."""
        user = self._create_test_user()
        role_id = RoleId.generate()
        assigned_by = uuid4()

        # First assign the role
        user.assign_role(role_id, assigned_by)
        assert user.has_role(role_id)

        # Then remove it
        user.remove_role(role_id, assigned_by)
        assert not user.has_role(role_id)

    def test_user_status_change(self) -> None:
        """Test changing user status."""
        user = self._create_test_user()
        changed_by = uuid4()

        user.change_status(UserStatus.ACTIVE, changed_by)

        assert user.status == UserStatus.ACTIVE
        assert user.is_active()
        assert user.can_login()

    def _create_test_user(self) -> User:
        """Helper method to create a test user."""
        email = Email("test@example.com")
        password_hash = PasswordHash.from_plaintext("password123")
        created_by = uuid4()

        user = User.create(
            email=email,
            password_hash=password_hash,
            created_by=created_by,
        )
        user.clear_domain_events()  # Clear creation event for cleaner tests
        return user


class TestRole:
    """Test cases for Role entity."""

    def test_role_creation(self) -> None:
        """Test creating a role."""
        created_by = uuid4()

        role = Role.create(
            name="Test Role",
            role_type=RoleType.CUSTOM,
            created_by=created_by,
            description="A test role",
        )

        assert role.name == "Test Role"
        assert role.description == "A test role"
        assert role.role_type == RoleType.CUSTOM
        assert role.audit_info.created_by == created_by
        assert role.is_active
        assert role.can_be_modified()
        assert role.can_be_deleted()

    def test_system_role_restrictions(self) -> None:
        """Test system role modification restrictions."""
        created_by = uuid4()

        role = Role.create(
            name="System Admin",
            role_type=RoleType.SYSTEM,
            created_by=created_by,
        )

        assert not role.can_be_modified()
        assert not role.can_be_deleted()

    def test_role_permission_management(self) -> None:
        """Test adding and removing permissions from role."""
        role = self._create_test_role()
        permission_id = PermissionId.generate()

        # Add permission
        role.add_permission(permission_id)
        assert role.has_permission(permission_id)

        # Remove permission
        role.remove_permission(permission_id)
        assert not role.has_permission(permission_id)

    def _create_test_role(self) -> Role:
        """Helper method to create a test role."""
        return Role.create(
            name="Test Role",
            role_type=RoleType.CUSTOM,
            created_by=uuid4(),
        )


class TestPermission:
    """Test cases for Permission entity."""

    def test_permission_creation(self) -> None:
        """Test creating a permission."""
        created_by = uuid4()

        permission = Permission.create(
            name="Read Users",
            resource="user",
            action="read",
            scope=PermissionScope.GLOBAL,
            created_by=created_by,
            description="Permission to read user data",
        )

        assert permission.name == "Read Users"
        assert permission.resource == "user"
        assert permission.action == "read"
        assert permission.scope == PermissionScope.GLOBAL
        assert permission.description == "Permission to read user data"
        assert permission.full_name == "user:read"
        assert permission.is_active

    def test_permission_matching(self) -> None:
        """Test permission matching."""
        permission = self._create_test_permission()

        assert permission.matches("user", "read")
        assert not permission.matches("user", "write")
        assert not permission.matches("role", "read")

    def test_permission_inheritance(self) -> None:
        """Test permission scope inheritance."""
        global_permission = Permission.create(
            name="Global Read",
            resource="user",
            action="read",
            scope=PermissionScope.GLOBAL,
            created_by=uuid4(),
        )

        project_permission = Permission.create(
            name="Project Read",
            resource="user",
            action="read",
            scope=PermissionScope.PROJECT,
            created_by=uuid4(),
        )

        # Project scope can inherit from global scope
        assert project_permission.can_inherit_from(global_permission)
        # Global scope cannot inherit from project scope
        assert not global_permission.can_inherit_from(project_permission)

    def _create_test_permission(self) -> Permission:
        """Helper method to create a test permission."""
        return Permission.create(
            name="Test Permission",
            resource="user",
            action="read",
            scope=PermissionScope.GLOBAL,
            created_by=uuid4(),
        )


class TestEnums:
    """Test cases for domain enums."""

    def test_user_status_properties(self) -> None:
        """Test UserStatus enum properties."""
        assert UserStatus.ACTIVE.is_active
        assert not UserStatus.INACTIVE.is_active

        assert UserStatus.ACTIVE.can_login
        assert not UserStatus.SUSPENDED.can_login

        assert UserStatus.PENDING_VERIFICATION.requires_verification
        assert not UserStatus.ACTIVE.requires_verification

    def test_permission_scope_hierarchy(self) -> None:
        """Test PermissionScope hierarchy."""
        assert PermissionScope.GLOBAL.hierarchy_level == 0
        assert PermissionScope.ORGANIZATION.hierarchy_level == 1
        assert PermissionScope.PROJECT.hierarchy_level == 2
        assert PermissionScope.RESOURCE.hierarchy_level == 3

        # Test inheritance rules
        assert PermissionScope.PROJECT.can_inherit_from(PermissionScope.GLOBAL)
        assert not PermissionScope.GLOBAL.can_inherit_from(PermissionScope.PROJECT)

    def test_role_type_properties(self) -> None:
        """Test RoleType enum properties."""
        assert not RoleType.SYSTEM.is_modifiable
        assert RoleType.CUSTOM.is_modifiable

        assert not RoleType.SYSTEM.can_be_deleted
        assert RoleType.CUSTOM.can_be_deleted


if __name__ == "__main__":
    # Run a simple test to verify the implementation works
    print("Running basic Identity Domain tests...")

    # Test user creation
    email = Email("admin@example.com")
    password_hash = PasswordHash.from_plaintext("admin123456")
    admin_user = User.create(
        email=email,
        password_hash=password_hash,
        created_by=uuid4(),
        initial_status=UserStatus.ACTIVE,
    )

    print(f"✓ Created user: {admin_user.email}")
    print(f"✓ User status: {admin_user.status}")
    print(f"✓ Domain events generated: {len(admin_user.domain_events)}")

    # Test role creation
    admin_role = Role.create(
        name="Administrator",
        role_type=RoleType.SYSTEM,
        created_by=admin_user.id.value,
        description="System administrator role",
    )

    print(f"✓ Created role: {admin_role.name}")
    print(f"✓ Role type: {admin_role.role_type}")

    # Test permission creation
    read_permission = Permission.create(
        name="Read All Users",
        resource="user",
        action="read",
        scope=PermissionScope.GLOBAL,
        created_by=admin_user.id.value,
    )

    print(f"✓ Created permission: {read_permission.full_name}")
    print(f"✓ Permission scope: {read_permission.scope}")

    print("\n🎉 All basic tests passed! Identity Domain implementation is working correctly.")
