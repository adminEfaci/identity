"""REST API endpoints for Multi-Factor Authentication (MFA) management.

This module implements REST API endpoints for MFA operations including
TOTP setup, hardware token registration, and backup code management.
"""

import logging
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ...core.mfa import BackupCodeManager, HardwareTokenManager, TOTPManager
from ...domain.exceptions import ValidationError
from ..middleware.auth import require_auth
from ..models.api import ErrorResponse, SuccessResponse

logger = logging.getLogger(__name__)

# Create router for MFA endpoints
router = APIRouter(prefix="/api/mfa", tags=["mfa"])


# Request/Response Models
class TOTPSetupRequest(BaseModel):
    """Request to set up TOTP."""
    account_name: str = Field(..., description="Display name for the account")
    issuer: str = Field(default="Identity Service", description="Service issuer name")


class TOTPSetupResponse(BaseModel):
    """Response for TOTP setup."""
    success: bool
    secret: str = Field(..., description="TOTP secret key")
    qr_code: str = Field(..., description="Base64 encoded QR code image")
    backup_codes: list[str] = Field(..., description="Emergency backup codes")
    manual_entry_key: str = Field(..., description="Manual entry key for apps")


class TOTPVerifyRequest(BaseModel):
    """Request to verify TOTP token."""
    token: str = Field(..., min_length=6, max_length=8, description="TOTP token")


class HardwareTokenRegisterRequest(BaseModel):
    """Request to register hardware token."""
    token_name: str = Field(..., description="Display name for the token")
    credential_data: dict = Field(..., description="WebAuthn credential data")


class HardwareTokenResponse(BaseModel):
    """Response for hardware token operations."""
    success: bool
    token_id: str = Field(..., description="Hardware token ID")
    token_name: str = Field(..., description="Token display name")
    created_at: str = Field(..., description="Registration timestamp")


class MFAStatusResponse(BaseModel):
    """Response for MFA status."""
    mfa_enabled: bool
    totp_configured: bool
    hardware_tokens_count: int
    backup_codes_remaining: int
    last_used: Optional[str] = None


class BackupCodeVerifyRequest(BaseModel):
    """Request to verify backup code."""
    code: str = Field(..., min_length=8, max_length=12, description="Backup code")


# Dependency injection helpers
def get_totp_manager() -> TOTPManager:
    """Get TOTP manager instance."""
    # This should be injected via DI container
    return TOTPManager()


def get_hardware_token_manager() -> HardwareTokenManager:
    """Get hardware token manager instance."""
    # This should be injected via DI container
    return HardwareTokenManager()


def get_backup_code_manager() -> BackupCodeManager:
    """Get backup code manager instance."""
    # This should be injected via DI container
    return BackupCodeManager()


@router.get(
    "/status",
    response_model=MFAStatusResponse,
    summary="Get MFA status",
    description="Get the current MFA configuration status for the authenticated user",
    responses={
        200: {"description": "MFA status retrieved successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
    },
)
async def get_mfa_status(
    request: Request,
    current_user: Annotated[dict, Depends(require_auth)],
    totp_manager: Annotated[TOTPManager, Depends(get_totp_manager)],
    hardware_manager: Annotated[HardwareTokenManager, Depends(get_hardware_token_manager)],
    backup_manager: Annotated[BackupCodeManager, Depends(get_backup_code_manager)],
) -> MFAStatusResponse:
    """Get MFA status for the current user.

    Args:
        request: HTTP request
        current_user: Current authenticated user
        totp_manager: TOTP manager dependency
        hardware_manager: Hardware token manager dependency
        backup_manager: Backup code manager dependency

    Returns:
        MFA status information

    Raises:
        HTTPException: If status retrieval fails
    """
    try:
        user_id = current_user["user_id"]

        # Check TOTP configuration
        totp_configured = await totp_manager.is_totp_configured(user_id)

        # Check hardware tokens
        hardware_tokens = await hardware_manager.get_user_tokens(user_id)

        # Check backup codes
        backup_codes_count = await backup_manager.get_remaining_codes_count(user_id)

        # Get last MFA usage
        last_used = await totp_manager.get_last_used(user_id)

        mfa_enabled = totp_configured or len(hardware_tokens) > 0

        logger.debug(f"Retrieved MFA status for user {user_id}")

        return MFAStatusResponse(
            mfa_enabled=mfa_enabled,
            totp_configured=totp_configured,
            hardware_tokens_count=len(hardware_tokens),
            backup_codes_remaining=backup_codes_count,
            last_used=last_used.isoformat() if last_used else None,
        )

    except Exception as e:
        logger.error(f"Error retrieving MFA status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.post(
    "/totp/setup",
    response_model=TOTPSetupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Set up TOTP",
    description="Generate TOTP secret and QR code for authenticator app setup",
    responses={
        201: {"description": "TOTP setup initiated successfully"},
        400: {"model": ErrorResponse, "description": "Invalid request data"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        409: {"model": ErrorResponse, "description": "TOTP already configured"},
    },
)
async def setup_totp(
    request: TOTPSetupRequest,
    current_user: Annotated[dict, Depends(require_auth)],
    totp_manager: Annotated[TOTPManager, Depends(get_totp_manager)],
    backup_manager: Annotated[BackupCodeManager, Depends(get_backup_code_manager)],
) -> TOTPSetupResponse:
    """Set up TOTP for the current user.

    Args:
        request: TOTP setup request data
        current_user: Current authenticated user
        totp_manager: TOTP manager dependency
        backup_manager: Backup code manager dependency

    Returns:
        TOTP setup data including secret and QR code

    Raises:
        HTTPException: If TOTP setup fails
    """
    try:
        user_id = current_user["user_id"]

        # Check if TOTP is already configured
        if await totp_manager.is_totp_configured(user_id):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="TOTP is already configured for this user",
            )

        # Generate TOTP configuration
        totp_config = await totp_manager.generate_totp_config(
            account_name=request.account_name,
            issuer=request.issuer,
            user_id=user_id,
        )

        # Generate QR code
        qr_code_bytes = await totp_manager.generate_qr_code(totp_config)

        # Convert QR code to base64
        import base64
        qr_code_b64 = base64.b64encode(qr_code_bytes).decode('utf-8')

        # Generate backup codes
        backup_codes = await backup_manager.generate_backup_codes(user_id)

        logger.info(f"TOTP setup initiated for user {user_id}")

        return TOTPSetupResponse(
            success=True,
            secret=totp_config.secret,
            qr_code=qr_code_b64,
            backup_codes=[code.code for code in backup_codes],
            manual_entry_key=totp_config.secret,
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error setting up TOTP: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.post(
    "/totp/verify",
    response_model=SuccessResponse,
    summary="Verify TOTP token",
    description="Verify a TOTP token to complete setup or authenticate",
    responses={
        200: {"description": "TOTP token verified successfully"},
        400: {"model": ErrorResponse, "description": "Invalid or expired token"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        404: {"model": ErrorResponse, "description": "TOTP not configured"},
    },
)
async def verify_totp(
    request: TOTPVerifyRequest,
    current_user: Annotated[dict, Depends(require_auth)],
    totp_manager: Annotated[TOTPManager, Depends(get_totp_manager)],
    http_request: Request,
) -> SuccessResponse:
    """Verify a TOTP token.

    Args:
        request: TOTP verification request
        current_user: Current authenticated user
        totp_manager: TOTP manager dependency
        http_request: HTTP request for IP address

    Returns:
        Success response

    Raises:
        HTTPException: If TOTP verification fails
    """
    try:
        user_id = current_user["user_id"]

        # Check if TOTP is configured
        if not await totp_manager.is_totp_configured(user_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="TOTP is not configured for this user",
            )

        # Get user's TOTP secret
        totp_secret = await totp_manager.get_user_totp_secret(user_id)
        if not totp_secret:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="TOTP secret not found",
            )

        # Get client IP
        client_ip = http_request.client.host if http_request.client else "unknown"

        # Verify TOTP token
        is_valid = await totp_manager.verify_totp(
            secret=totp_secret,
            token=request.token,
            user_id=user_id,
            ip_address=client_ip,
        )

        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired TOTP token",
            )

        logger.info(f"TOTP verified successfully for user {user_id}")

        return SuccessResponse(
            success=True,
            message="TOTP token verified successfully",
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error verifying TOTP: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.delete(
    "/totp",
    response_model=SuccessResponse,
    summary="Disable TOTP",
    description="Disable TOTP authentication for the current user",
    responses={
        200: {"description": "TOTP disabled successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        404: {"model": ErrorResponse, "description": "TOTP not configured"},
    },
)
async def disable_totp(
    current_user: Annotated[dict, Depends(require_auth)],
    totp_manager: Annotated[TOTPManager, Depends(get_totp_manager)],
) -> SuccessResponse:
    """Disable TOTP for the current user.

    Args:
        current_user: Current authenticated user
        totp_manager: TOTP manager dependency

    Returns:
        Success response

    Raises:
        HTTPException: If TOTP disabling fails
    """
    try:
        user_id = current_user["user_id"]

        # Check if TOTP is configured
        if not await totp_manager.is_totp_configured(user_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="TOTP is not configured for this user",
            )

        # Disable TOTP
        await totp_manager.disable_totp(user_id)

        logger.info(f"TOTP disabled for user {user_id}")

        return SuccessResponse(
            success=True,
            message="TOTP authentication disabled successfully",
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error disabling TOTP: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.post(
    "/hardware-token/register",
    response_model=HardwareTokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register hardware token",
    description="Register a new hardware security token (FIDO2/WebAuthn)",
    responses={
        201: {"description": "Hardware token registered successfully"},
        400: {"model": ErrorResponse, "description": "Invalid token data"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
    },
)
async def register_hardware_token(
    request: HardwareTokenRegisterRequest,
    current_user: Annotated[dict, Depends(require_auth)],
    hardware_manager: Annotated[HardwareTokenManager, Depends(get_hardware_token_manager)],
) -> HardwareTokenResponse:
    """Register a hardware security token.

    Args:
        request: Hardware token registration request
        current_user: Current authenticated user
        hardware_manager: Hardware token manager dependency

    Returns:
        Hardware token registration response

    Raises:
        HTTPException: If token registration fails
    """
    try:
        user_id = current_user["user_id"]

        # Register hardware token
        token = await hardware_manager.register_token(
            user_id=user_id,
            token_name=request.token_name,
            credential_data=request.credential_data,
        )

        logger.info(f"Hardware token registered for user {user_id}: {token.id}")

        return HardwareTokenResponse(
            success=True,
            token_id=str(token.id),
            token_name=token.name,
            created_at=token.created_at.isoformat(),
        )

    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid token data: {e}",
        ) from e

    except Exception as e:
        logger.error(f"Error registering hardware token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.get(
    "/hardware-tokens",
    response_model=list[HardwareTokenResponse],
    summary="List hardware tokens",
    description="Get list of registered hardware tokens for the current user",
    responses={
        200: {"description": "Hardware tokens retrieved successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
    },
)
async def list_hardware_tokens(
    current_user: Annotated[dict, Depends(require_auth)],
    hardware_manager: Annotated[HardwareTokenManager, Depends(get_hardware_token_manager)],
) -> list[HardwareTokenResponse]:
    """List hardware tokens for the current user.

    Args:
        current_user: Current authenticated user
        hardware_manager: Hardware token manager dependency

    Returns:
        List of hardware tokens

    Raises:
        HTTPException: If token listing fails
    """
    try:
        user_id = current_user["user_id"]

        # Get user's hardware tokens
        tokens = await hardware_manager.get_user_tokens(user_id)

        logger.debug(f"Retrieved {len(tokens)} hardware tokens for user {user_id}")

        return [
            HardwareTokenResponse(
                success=True,
                token_id=str(token.id),
                token_name=token.name,
                created_at=token.created_at.isoformat(),
            )
            for token in tokens
        ]

    except Exception as e:
        logger.error(f"Error listing hardware tokens: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.delete(
    "/hardware-token/{token_id}",
    response_model=SuccessResponse,
    summary="Remove hardware token",
    description="Remove a registered hardware token",
    responses={
        200: {"description": "Hardware token removed successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        404: {"model": ErrorResponse, "description": "Token not found"},
    },
)
async def remove_hardware_token(
    token_id: str,
    current_user: Annotated[dict, Depends(require_auth)],
    hardware_manager: Annotated[HardwareTokenManager, Depends(get_hardware_token_manager)],
) -> SuccessResponse:
    """Remove a hardware token.

    Args:
        token_id: Hardware token ID to remove
        current_user: Current authenticated user
        hardware_manager: Hardware token manager dependency

    Returns:
        Success response

    Raises:
        HTTPException: If token removal fails
    """
    try:
        user_id = current_user["user_id"]

        # Remove hardware token
        success = await hardware_manager.remove_token(
            user_id=user_id,
            token_id=UUID(token_id),
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Hardware token not found",
            )

        logger.info(f"Hardware token removed: {token_id}")

        return SuccessResponse(
            success=True,
            message="Hardware token removed successfully",
        )

    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token ID format",
        ) from None

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error removing hardware token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.post(
    "/backup-code/verify",
    response_model=SuccessResponse,
    summary="Verify backup code",
    description="Verify a backup code for MFA authentication",
    responses={
        200: {"description": "Backup code verified successfully"},
        400: {"model": ErrorResponse, "description": "Invalid backup code"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
    },
)
async def verify_backup_code(
    request: BackupCodeVerifyRequest,
    current_user: Annotated[dict, Depends(require_auth)],
    backup_manager: Annotated[BackupCodeManager, Depends(get_backup_code_manager)],
) -> SuccessResponse:
    """Verify a backup code.

    Args:
        request: Backup code verification request
        current_user: Current authenticated user
        backup_manager: Backup code manager dependency

    Returns:
        Success response

    Raises:
        HTTPException: If backup code verification fails
    """
    try:
        user_id = current_user["user_id"]

        # Verify backup code
        is_valid = await backup_manager.verify_backup_code(
            user_id=user_id,
            code=request.code,
        )

        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or already used backup code",
            )

        logger.info(f"Backup code verified for user {user_id}")

        return SuccessResponse(
            success=True,
            message="Backup code verified successfully",
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Error verifying backup code: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.post(
    "/backup-codes/regenerate",
    response_model=dict,
    summary="Regenerate backup codes",
    description="Generate new backup codes and invalidate old ones",
    responses={
        200: {"description": "Backup codes regenerated successfully"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
    },
)
async def regenerate_backup_codes(
    current_user: Annotated[dict, Depends(require_auth)],
    backup_manager: Annotated[BackupCodeManager, Depends(get_backup_code_manager)],
) -> dict:
    """Regenerate backup codes for the current user.

    Args:
        current_user: Current authenticated user
        backup_manager: Backup code manager dependency

    Returns:
        New backup codes

    Raises:
        HTTPException: If backup code regeneration fails
    """
    try:
        user_id = current_user["user_id"]

        # Regenerate backup codes
        backup_codes = await backup_manager.regenerate_backup_codes(user_id)

        logger.info(f"Backup codes regenerated for user {user_id}")

        return {
            "success": True,
            "backup_codes": [code.code for code in backup_codes],
            "message": "New backup codes generated. Store them securely.",
        }

    except Exception as e:
        logger.error(f"Error regenerating backup codes: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e
