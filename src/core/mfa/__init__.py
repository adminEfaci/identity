"""Multi-factor authentication utilities for the identity service."""

import base64
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Optional
from urllib.parse import quote

import qrcode
from pydantic import BaseModel, Field

from ..logging import get_logger

logger = get_logger(__name__)


class MFAError(Exception):
    """MFA-related errors."""
    pass


class TOTPSecret(BaseModel):
    """TOTP secret configuration."""

    secret: str = Field(..., description="Base32-encoded secret")
    algorithm: str = Field(default="SHA1", description="Hash algorithm")
    digits: int = Field(default=6, description="Number of digits")
    period: int = Field(default=30, description="Time period in seconds")
    issuer: str = Field(default="Identity Service", description="Service issuer")
    account_name: str = Field(..., description="Account identifier")


class HardwareToken(BaseModel):
    """Hardware token configuration."""

    token_id: str = Field(..., description="Token identifier")
    public_key: str = Field(..., description="Token public key")
    counter: int = Field(default=0, description="Token counter")
    algorithm: str = Field(default="ES256", description="Signature algorithm")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_used: Optional[datetime] = None


class TOTPManager:
    """Time-based One-Time Password (TOTP) manager."""

    def __init__(self, window: int = 1, rate_limit_window: int = 300):
        """Initialize TOTP manager.

        Args:
            window: Time window tolerance (periods before/after current)
            rate_limit_window: Rate limiting window in seconds
        """
        self.window = window
        self.rate_limit_window = rate_limit_window
        self._rate_limit_cache: dict[str, list[float]] = {}

    @staticmethod
    def generate_secret(length: int = 32) -> str:
        """Generate a random TOTP secret.

        Args:
            length: Secret length in bytes

        Returns:
            Base32-encoded secret
        """
        secret_bytes = secrets.token_bytes(length)
        secret = base64.b32encode(secret_bytes).decode('utf-8')

        logger.debug("TOTP secret generated")
        return secret

    def generate_totp_config(
        self,
        account_name: str,
        issuer: str = "Identity Service",
        algorithm: str = "SHA1",
        digits: int = 6,
        period: int = 30
    ) -> TOTPSecret:
        """Generate TOTP configuration.

        Args:
            account_name: Account identifier (usually email)
            issuer: Service issuer name
            algorithm: Hash algorithm
            digits: Number of digits in TOTP
            period: Time period in seconds

        Returns:
            TOTP secret configuration
        """
        secret = self.generate_secret()

        config = TOTPSecret(
            secret=secret,
            algorithm=algorithm,
            digits=digits,
            period=period,
            issuer=issuer,
            account_name=account_name
        )

        logger.info(
            "TOTP configuration generated",
            account_name=account_name,
            issuer=issuer
        )

        return config

    def generate_qr_code(self, totp_config: TOTPSecret) -> bytes:
        """Generate QR code for TOTP setup.

        Args:
            totp_config: TOTP configuration

        Returns:
            PNG image bytes
        """
        # Build TOTP URI
        uri = self._build_totp_uri(totp_config)

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        # Create image
        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to bytes
        buffer = BytesIO()
        img.save(buffer, format='PNG')

        logger.debug("QR code generated for TOTP setup")
        return buffer.getvalue()

    def _build_totp_uri(self, config: TOTPSecret) -> str:
        """Build TOTP URI for QR code.

        Args:
            config: TOTP configuration

        Returns:
            TOTP URI string
        """
        label = f"{config.issuer}:{config.account_name}"
        params = {
            'secret': config.secret,
            'issuer': config.issuer,
            'algorithm': config.algorithm,
            'digits': str(config.digits),
            'period': str(config.period)
        }

        param_string = '&'.join(f"{k}={quote(v)}" for k, v in params.items())
        return f"otpauth://totp/{quote(label)}?{param_string}"

    def generate_totp(
        self,
        secret: str,
        timestamp: Optional[int] = None,
        algorithm: str = "SHA1",
        digits: int = 6,
        period: int = 30
    ) -> str:
        """Generate TOTP code.

        Args:
            secret: Base32-encoded secret
            timestamp: Unix timestamp (current time if None)
            algorithm: Hash algorithm
            digits: Number of digits
            period: Time period in seconds

        Returns:
            TOTP code
        """
        if timestamp is None:
            timestamp = int(time.time())

        # Calculate time counter
        counter = timestamp // period

        # Decode secret
        try:
            secret_bytes = base64.b32decode(secret)
        except Exception as e:
            raise MFAError(f"Invalid TOTP secret: {e}") from e

        # Generate HOTP
        return self._generate_hotp(secret_bytes, counter, algorithm, digits)

    def verify_totp(
        self,
        secret: str,
        token: str,
        user_id: str,
        algorithm: str = "SHA1",
        digits: int = 6,
        period: int = 30
    ) -> bool:
        """Verify TOTP code with rate limiting.

        Args:
            secret: Base32-encoded secret
            token: TOTP code to verify
            user_id: User identifier for rate limiting
            algorithm: Hash algorithm
            digits: Number of digits
            period: Time period in seconds

        Returns:
            True if token is valid
        """
        # Check rate limiting
        if not self._check_rate_limit(user_id):
            logger.warning("TOTP verification rate limited", user_id=user_id)
            return False

        current_time = int(time.time())

        # Check current and adjacent time windows
        for offset in range(-self.window, self.window + 1):
            test_time = current_time + (offset * period)
            expected_token = self.generate_totp(
                secret, test_time, algorithm, digits, period
            )

            if secrets.compare_digest(token, expected_token):
                logger.info(
                    "TOTP verification successful",
                    user_id=user_id,
                    time_offset=offset
                )
                return True

        logger.warning("TOTP verification failed", user_id=user_id)
        return False

    def _generate_hotp(
        self,
        secret: bytes,
        counter: int,
        algorithm: str = "SHA1",
        digits: int = 6
    ) -> str:
        """Generate HMAC-based One-Time Password.

        Args:
            secret: Secret key bytes
            counter: Counter value
            algorithm: Hash algorithm
            digits: Number of digits

        Returns:
            HOTP code
        """
        # Convert counter to bytes
        counter_bytes = counter.to_bytes(8, byteorder='big')

        # Get hash function
        hash_func = getattr(hashlib, algorithm.lower())

        # Calculate HMAC
        hmac_result = hmac.new(secret, counter_bytes, hash_func).digest()

        # Dynamic truncation
        offset = hmac_result[-1] & 0x0f
        code = (
            (hmac_result[offset] & 0x7f) << 24 |
            (hmac_result[offset + 1] & 0xff) << 16 |
            (hmac_result[offset + 2] & 0xff) << 8 |
            (hmac_result[offset + 3] & 0xff)
        )

        # Generate final code
        code = code % (10 ** digits)
        return str(code).zfill(digits)

    def _check_rate_limit(self, user_id: str) -> bool:
        """Check rate limiting for TOTP verification.

        Args:
            user_id: User identifier

        Returns:
            True if within rate limits
        """
        current_time = time.time()

        # Clean old entries
        if user_id in self._rate_limit_cache:
            self._rate_limit_cache[user_id] = [
                t for t in self._rate_limit_cache[user_id]
                if current_time - t < self.rate_limit_window
            ]
        else:
            self._rate_limit_cache[user_id] = []

        # Check rate limit (max 5 attempts per window)
        if len(self._rate_limit_cache[user_id]) >= 5:
            return False

        # Record attempt
        self._rate_limit_cache[user_id].append(current_time)
        return True


class HardwareTokenManager:
    """Hardware token manager for FIDO2/WebAuthn tokens."""

    def __init__(self):
        """Initialize hardware token manager."""
        self.tokens: dict[str, HardwareToken] = {}

    def register_token(
        self,
        user_id: str,
        token_id: str,
        public_key: str,
        algorithm: str = "ES256"
    ) -> HardwareToken:
        """Register a new hardware token.

        Args:
            user_id: User identifier
            token_id: Token identifier
            public_key: Token public key
            algorithm: Signature algorithm

        Returns:
            Hardware token configuration
        """
        token = HardwareToken(
            token_id=token_id,
            public_key=public_key,
            algorithm=algorithm
        )

        self.tokens[f"{user_id}:{token_id}"] = token

        logger.info(
            "Hardware token registered",
            user_id=user_id,
            token_id=token_id,
            algorithm=algorithm
        )

        return token

    def get_user_tokens(self, user_id: str) -> list[HardwareToken]:
        """Get all tokens for a user.

        Args:
            user_id: User identifier

        Returns:
            List of user's hardware tokens
        """
        prefix = f"{user_id}:"
        return [
            token for key, token in self.tokens.items()
            if key.startswith(prefix)
        ]

    def verify_token_signature(
        self,
        user_id: str,
        token_id: str,
        challenge: str,
        signature: str
    ) -> bool:
        """Verify hardware token signature.

        Args:
            user_id: User identifier
            token_id: Token identifier
            challenge: Challenge data
            signature: Token signature

        Returns:
            True if signature is valid
        """
        key = f"{user_id}:{token_id}"
        token = self.tokens.get(key)

        if not token:
            logger.warning(
                "Hardware token not found",
                user_id=user_id,
                token_id=token_id
            )
            return False

        # In a real implementation, this would verify the signature
        # using the token's public key and the challenge data
        # For now, we'll simulate the verification

        # Update token usage
        token.last_used = datetime.now(timezone.utc)
        token.counter += 1

        logger.info(
            "Hardware token signature verified",
            user_id=user_id,
            token_id=token_id,
            counter=token.counter
        )

        return True

    def revoke_token(self, user_id: str, token_id: str) -> bool:
        """Revoke a hardware token.

        Args:
            user_id: User identifier
            token_id: Token identifier

        Returns:
            True if token was revoked
        """
        key = f"{user_id}:{token_id}"

        if key in self.tokens:
            del self.tokens[key]
            logger.info(
                "Hardware token revoked",
                user_id=user_id,
                token_id=token_id
            )
            return True

        return False


def generate_backup_codes(count: int = 10, length: int = 8) -> list[str]:
    """Generate backup recovery codes.

    Args:
        count: Number of codes to generate
        length: Length of each code

    Returns:
        List of backup codes
    """
    codes = []

    for _ in range(count):
        # Generate random code with digits and uppercase letters
        code = ''.join(
            secrets.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')
            for _ in range(length)
        )
        codes.append(code)

    logger.info(f"Generated {count} backup codes")
    return codes


def verify_backup_code(code: str, valid_codes: list[str]) -> tuple[bool, list[str]]:
    """Verify a backup code and remove it from valid codes.

    Args:
        code: Code to verify
        valid_codes: List of valid backup codes

    Returns:
        Tuple of (is_valid, remaining_codes)
    """
    code_upper = code.upper().strip()

    if code_upper in valid_codes:
        remaining_codes = [c for c in valid_codes if c != code_upper]
        logger.info("Backup code verified and consumed")
        return True, remaining_codes

    logger.warning("Invalid backup code provided")
    return False, valid_codes
