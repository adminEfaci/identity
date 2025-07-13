"""Integration adapters for bridging identity-module with main app's identity system.

This module provides concrete implementations that adapt between the two
identity systems while maintaining clean separation of concerns.
"""

import logging
from typing import Any, Optional
from uuid import UUID

from ..core.auth import JWTManager
from ..core.mfa import BackupCodeManager, HardwareTokenManager, TOTPManager
from ..core.permissions import PermissionChecker, RBACManager
from ..domain.events import DomainEvent
from ..infrastructure.audit.processors import AuditEventProcessor
from ..infrastructure.notifications.service import NotificationService

logger = logging.getLogger(__name__)


class IdentityModuleBridge:
    """Bridge adapter for the identity-module to integrate with main app."""

    def __init__(
        self,
        jwt_manager: JWTManager,
        totp_manager: TOTPManager,
        hardware_token_manager: HardwareTokenManager,
        backup_code_manager: BackupCodeManager,
        rbac_manager: RBACManager,
        permission_checker: PermissionChecker,
        audit_processor: AuditEventProcessor,
        notification_service: NotificationService,
    ) -> None:
        """Initialize the bridge adapter.

        Args:
            jwt_manager: JWT token management
            totp_manager: TOTP authentication management
            hardware_token_manager: Hardware token management
            backup_code_manager: Backup code management
            rbac_manager: Role-based access control management
            permission_checker: Permission checking service
            audit_processor: Audit event processing
            notification_service: Notification service
        """
        self._jwt_manager = jwt_manager
        self._totp_manager = totp_manager
        self._hardware_token_manager = hardware_token_manager
        self._backup_code_manager = backup_code_manager
        self._rbac_manager = rbac_manager
        self._permission_checker = permission_checker
        self._audit_processor = audit_processor
        self._notification_service = notification_service

    async def handle_authentication_event(
        self,
        event_type: str,
        user_id: UUID,
        context: dict[str, Any],
    ) -> bool:
        """Handle authentication events from main app.

        Args:
            event_type: Type of authentication event
            user_id: User ID involved in the event
            context: Additional context data

        Returns:
            True if event was handled successfully
        """
        try:
            if event_type == "login_success":
                await self._handle_login_success(user_id, context)
            elif event_type == "login_failure":
                await self._handle_login_failure(user_id, context)
            elif event_type == "mfa_challenge_required":
                await self._handle_mfa_challenge(user_id, context)
            elif event_type == "password_change":
                await self._handle_password_change(user_id, context)
            else:
                logger.warning(f"Unknown authentication event type: {event_type}")
                return False

            return True

        except Exception as e:
            logger.error(f"Error handling authentication event {event_type}: {e}")
            return False

    async def _handle_login_success(self, user_id: UUID, context: dict[str, Any]) -> None:
        """Handle successful login event."""
        # Update session tracking
        session_id = context.get("session_id")
        ip_address = context.get("ip_address")
        user_agent = context.get("user_agent")

        # Log audit event
        await self._audit_processor.process_api_request(
            method="POST",
            path="/api/auth/login",
            status_code=200,
            occurred_at=context.get("timestamp"),
            user_id=str(user_id),
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Check if MFA verification is needed
        mfa_configured = await self._totp_manager.is_totp_configured(str(user_id))
        if mfa_configured and not context.get("mfa_verified", False):
            logger.info(f"MFA verification required for user {user_id}")

    async def _handle_login_failure(self, user_id: UUID, context: dict[str, Any]) -> None:
        """Handle failed login event."""
        # Log security event
        await self._audit_processor.process_api_request(
            method="POST",
            path="/api/auth/login",
            status_code=401,
            occurred_at=context.get("timestamp"),
            user_id=str(user_id) if user_id else None,
            ip_address=context.get("ip_address"),
            user_agent=context.get("user_agent"),
        )

        # Check for potential brute force
        failure_count = context.get("failure_count", 1)
        if failure_count >= 5:
            logger.warning(f"Multiple login failures for user {user_id}")

    async def _handle_mfa_challenge(self, user_id: UUID, context: dict[str, Any]) -> None:
        """Handle MFA challenge requirement."""
        # Check available MFA methods
        totp_configured = await self._totp_manager.is_totp_configured(str(user_id))
        hardware_tokens = await self._hardware_token_manager.get_user_tokens(str(user_id))
        backup_codes_count = await self._backup_code_manager.get_remaining_codes_count(str(user_id))

        available_methods = []
        if totp_configured:
            available_methods.append("totp")
        if hardware_tokens:
            available_methods.append("hardware_token")
        if backup_codes_count > 0:
            available_methods.append("backup_code")

        logger.info(f"MFA challenge for user {user_id}, available methods: {available_methods}")

    async def _handle_password_change(self, user_id: UUID, context: dict[str, Any]) -> None:
        """Handle password change event."""
        # Send notification
        from ..domain.events import UserPasswordChanged

        password_changed_event = UserPasswordChanged(
            user_id=user_id,
            changed_by=context.get("changed_by", user_id),
            is_self_change=context.get("is_self_change", True),
            occurred_at=context.get("timestamp"),
        )

        await self._notification_service.handle_domain_event(password_changed_event)

    async def check_user_permission(
        self,
        user_id: UUID,
        resource: str,
        action: str,
        scope: Optional[str] = None,
    ) -> dict[str, Any]:
        """Check user permission and return detailed result.

        Args:
            user_id: User ID to check permissions for
            resource: Resource to check access to
            action: Action to perform on resource
            scope: Optional scope for permission

        Returns:
            Permission check result with details
        """
        try:
            result = await self._permission_checker.check_permission(
                user_id=str(user_id),
                resource=resource,
                action=action,
                scope=scope,
            )

            return {
                "granted": result.granted,
                "reason": result.reason,
                "matching_permissions": [perm.name for perm in result.matching_permissions],
                "user_roles": [role.name for role in await self._rbac_manager.get_user_roles(str(user_id))],
            }

        except Exception as e:
            logger.error(f"Error checking permission for user {user_id}: {e}")
            return {
                "granted": False,
                "reason": f"Permission check failed: {e}",
                "matching_permissions": [],
                "user_roles": [],
            }

    async def get_user_mfa_status(self, user_id: UUID) -> dict[str, Any]:
        """Get comprehensive MFA status for user.

        Args:
            user_id: User ID to get MFA status for

        Returns:
            MFA status information
        """
        try:
            totp_configured = await self._totp_manager.is_totp_configured(str(user_id))
            hardware_tokens = await self._hardware_token_manager.get_user_tokens(str(user_id))
            backup_codes_count = await self._backup_code_manager.get_remaining_codes_count(str(user_id))
            last_used = await self._totp_manager.get_last_used(str(user_id))

            return {
                "mfa_enabled": totp_configured or len(hardware_tokens) > 0,
                "totp_configured": totp_configured,
                "hardware_tokens_count": len(hardware_tokens),
                "backup_codes_remaining": backup_codes_count,
                "last_used": last_used.isoformat() if last_used else None,
                "available_methods": self._get_available_mfa_methods(
                    totp_configured, hardware_tokens, backup_codes_count
                ),
            }

        except Exception as e:
            logger.error(f"Error getting MFA status for user {user_id}: {e}")
            return {
                "mfa_enabled": False,
                "totp_configured": False,
                "hardware_tokens_count": 0,
                "backup_codes_remaining": 0,
                "last_used": None,
                "available_methods": [],
            }

    def _get_available_mfa_methods(
        self,
        totp_configured: bool,
        hardware_tokens: list,
        backup_codes_count: int,
    ) -> list[str]:
        """Get list of available MFA methods."""
        methods = []

        if totp_configured:
            methods.append("totp")
        if hardware_tokens:
            methods.append("hardware_token")
        if backup_codes_count > 0:
            methods.append("backup_code")

        return methods

    async def sync_user_roles(
        self,
        user_id: UUID,
        external_roles: list[str],
    ) -> bool:
        """Synchronize user roles with external system.

        Args:
            user_id: User ID to sync roles for
            external_roles: List of role names from external system

        Returns:
            True if sync was successful
        """
        try:
            # Get current roles
            current_roles = await self._rbac_manager.get_user_roles(str(user_id))
            current_role_names = {role.name for role in current_roles}
            external_role_names = set(external_roles)

            # Remove roles not in external system
            roles_to_remove = current_role_names - external_role_names
            for role_name in roles_to_remove:
                await self._rbac_manager.remove_role(str(user_id), role_name)
                logger.info(f"Removed role '{role_name}' from user {user_id}")

            # Add new roles from external system
            roles_to_add = external_role_names - current_role_names
            for role_name in roles_to_add:
                # Check if role exists, create if not
                role = await self._rbac_manager.get_role_by_name(role_name)
                if not role:
                    # Create basic role - could be enhanced with external role details
                    role = await self._rbac_manager.create_role(
                        name=role_name,
                        description="Role synchronized from external system",
                        permission_names=[],
                    )

                await self._rbac_manager.assign_role(str(user_id), role_name)
                logger.info(f"Added role '{role_name}' to user {user_id}")

            return True

        except Exception as e:
            logger.error(f"Error syncing roles for user {user_id}: {e}")
            return False

    async def validate_token(self, token: str) -> Optional[dict[str, Any]]:
        """Validate JWT token and return claims.

        Args:
            token: JWT token to validate

        Returns:
            Token claims if valid, None otherwise
        """
        try:
            claims = await self._jwt_manager.decode_token(token)
            return {
                "user_id": claims.user_id,
                "session_id": claims.session_id,
                "mfa_verified": claims.mfa_verified,
                "expires_at": claims.expires_at.isoformat(),
                "issued_at": claims.issued_at.isoformat(),
            }

        except Exception as e:
            logger.warning(f"Token validation failed: {e}")
            return None

    async def create_access_token(
        self,
        user_id: UUID,
        session_id: UUID,
        mfa_verified: bool = False,
        additional_claims: Optional[dict[str, Any]] = None,
    ) -> str:
        """Create access token with identity-module's JWT manager.

        Args:
            user_id: User ID for the token
            session_id: Session ID for the token
            mfa_verified: Whether MFA has been verified
            additional_claims: Additional claims to include

        Returns:
            JWT access token
        """
        try:
            token = await self._jwt_manager.create_access_token(
                user_id=str(user_id),
                session_id=str(session_id),
                mfa_verified=mfa_verified,
                additional_claims=additional_claims or {},
            )

            logger.debug(f"Created access token for user {user_id}")
            return token

        except Exception as e:
            logger.error(f"Error creating access token: {e}")
            raise

    async def publish_domain_event(self, event: DomainEvent) -> bool:
        """Publish domain event through notification system.

        Args:
            event: Domain event to publish

        Returns:
            True if event was published successfully
        """
        try:
            return await self._notification_service.handle_domain_event(event)

        except Exception as e:
            logger.error(f"Error publishing domain event: {e}")
            return False


class MainAppIdentityAdapter:
    """Adapter for integrating with main app's identity system."""

    def __init__(self, bridge: IdentityModuleBridge) -> None:
        """Initialize adapter with bridge.

        Args:
            bridge: Identity module bridge instance
        """
        self._bridge = bridge

    async def handle_external_authentication(
        self,
        provider: str,
        user_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Handle authentication from external providers.

        Args:
            provider: Authentication provider name
            user_data: User data from provider

        Returns:
            Authentication result
        """
        # This would integrate with main app's OAuth/SAML providers
        # and use identity-module's MFA system
        user_id = user_data.get("user_id")

        if not user_id:
            return {"success": False, "error": "Invalid user data"}

        # Check if MFA is required
        mfa_status = await self._bridge.get_user_mfa_status(UUID(user_id))

        if mfa_status["mfa_enabled"]:
            return {
                "success": True,
                "mfa_required": True,
                "available_methods": mfa_status["available_methods"],
            }

        # Create token without MFA
        token = await self._bridge.create_access_token(
            user_id=UUID(user_id),
            session_id=UUID(user_data.get("session_id")),
            mfa_verified=False,
        )

        return {
            "success": True,
            "token": token,
            "mfa_required": False,
        }

    async def check_resource_access(
        self,
        user_id: UUID,
        resource_type: str,
        resource_id: str,
        action: str,
    ) -> bool:
        """Check if user has access to specific resource.

        Args:
            user_id: User ID to check
            resource_type: Type of resource
            resource_id: Specific resource ID
            action: Action to perform

        Returns:
            True if access is granted
        """
        result = await self._bridge.check_user_permission(
            user_id=user_id,
            resource=resource_type,
            action=action,
            scope=resource_id,
        )

        return result["granted"]

    async def sync_external_roles(
        self,
        user_id: UUID,
        external_system: str,
        roles: list[str],
    ) -> bool:
        """Sync roles from external system.

        Args:
            user_id: User ID to sync roles for
            external_system: Name of external system
            roles: List of role names from external system

        Returns:
            True if sync was successful
        """
        # Prefix roles with external system name to avoid conflicts
        prefixed_roles = [f"{external_system}_{role}" for role in roles]

        return await self._bridge.sync_user_roles(user_id, prefixed_roles)


def create_identity_bridge(
    jwt_manager: JWTManager,
    totp_manager: TOTPManager,
    hardware_token_manager: HardwareTokenManager,
    backup_code_manager: BackupCodeManager,
    rbac_manager: RBACManager,
    permission_checker: PermissionChecker,
    audit_processor: AuditEventProcessor,
    notification_service: NotificationService,
) -> IdentityModuleBridge:
    """Factory function to create identity bridge.

    Args:
        jwt_manager: JWT token management
        totp_manager: TOTP authentication management
        hardware_token_manager: Hardware token management
        backup_code_manager: Backup code management
        rbac_manager: Role-based access control management
        permission_checker: Permission checking service
        audit_processor: Audit event processing
        notification_service: Notification service

    Returns:
        Configured identity bridge
    """
    return IdentityModuleBridge(
        jwt_manager=jwt_manager,
        totp_manager=totp_manager,
        hardware_token_manager=hardware_token_manager,
        backup_code_manager=backup_code_manager,
        rbac_manager=rbac_manager,
        permission_checker=permission_checker,
        audit_processor=audit_processor,
        notification_service=notification_service,
    )
