"""Core utilities module for the identity service.

This module provides foundational utilities including:
- Authentication and JWT helpers
- Cryptographic utilities
- Structured logging
- Multi-factor authentication
- Permission and RBAC helpers
- General utility functions
"""

from .auth import JWTManager, TokenValidator, AuthenticationError
from .crypto import EncryptionManager, HashingManager
from .logging import StructuredLogger, get_logger
from .mfa import TOTPManager, HardwareTokenManager
from .permissions import RBACManager, PermissionChecker
from .utils import SecurityUtils, ValidationUtils

__all__ = [
    "JWTManager",
    "TokenValidator", 
    "AuthenticationError",
    "EncryptionManager",
    "HashingManager",
    "StructuredLogger",
    "get_logger",
    "TOTPManager",
    "HardwareTokenManager",
    "RBACManager",
    "PermissionChecker",
    "SecurityUtils",
    "ValidationUtils",
]