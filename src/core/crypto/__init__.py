"""Cryptographic utilities for the identity service."""

import base64
import hashlib
import os
import secrets
from typing import Optional, Union

import argon2
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..logging import get_logger

logger = get_logger(__name__)


class EncryptionError(Exception):
    """Encryption-related errors."""
    pass


class HashingError(Exception):
    """Hashing-related errors."""
    pass


class EncryptionManager:
    """Comprehensive encryption utilities using multiple algorithms."""

    def __init__(self, master_key: Optional[bytes] = None):
        """Initialize encryption manager.

        Args:
            master_key: Master key for encryption (32 bytes for AES-256)
        """
        if master_key:
            if len(master_key) != 32:
                raise EncryptionError("Master key must be 32 bytes for AES-256")
            self.master_key = master_key
        else:
            self.master_key = self._generate_key()

        # Initialize Fernet cipher
        fernet_key = base64.urlsafe_b64encode(self.master_key)
        self.fernet = Fernet(fernet_key)

    @staticmethod
    def _generate_key() -> bytes:
        """Generate a secure random key."""
        return secrets.token_bytes(32)

    @staticmethod
    def generate_salt(length: int = 16) -> bytes:
        """Generate a random salt.

        Args:
            length: Salt length in bytes

        Returns:
            Random salt
        """
        return secrets.token_bytes(length)

    def derive_key(self, password: str, salt: bytes, iterations: int = 100000) -> bytes:
        """Derive a key from password using PBKDF2.

        Args:
            password: Password to derive key from
            salt: Salt for key derivation
            iterations: Number of iterations

        Returns:
            Derived key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password.encode('utf-8'))

    def encrypt_fernet(self, data: Union[str, bytes]) -> bytes:
        """Encrypt data using Fernet (AES-128 with HMAC).

        Args:
            data: Data to encrypt

        Returns:
            Encrypted data
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        try:
            encrypted = self.fernet.encrypt(data)
            logger.debug("Data encrypted using Fernet")
            return encrypted
        except Exception as e:
            logger.error("Fernet encryption failed", error=str(e))
            raise EncryptionError(f"Encryption failed: {e}") from e

    def decrypt_fernet(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using Fernet.

        Args:
            encrypted_data: Encrypted data

        Returns:
            Decrypted data
        """
        try:
            decrypted = self.fernet.decrypt(encrypted_data)
            logger.debug("Data decrypted using Fernet")
            return decrypted
        except Exception as e:
            logger.error("Fernet decryption failed", error=str(e))
            raise EncryptionError(f"Decryption failed: {e}") from e

    def encrypt_aes_gcm(self, data: Union[str, bytes], key: Optional[bytes] = None) -> tuple[bytes, bytes, bytes]:
        """Encrypt data using AES-256-GCM.

        Args:
            data: Data to encrypt
            key: Encryption key (uses master key if None)

        Returns:
            Tuple of (encrypted_data, nonce, tag)
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        encryption_key = key or self.master_key
        nonce = os.urandom(12)  # 96-bit nonce for GCM

        try:
            cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()

            logger.debug("Data encrypted using AES-256-GCM")
            return encrypted_data, nonce, encryptor.tag
        except Exception as e:
            logger.error("AES-GCM encryption failed", error=str(e))
            raise EncryptionError(f"AES-GCM encryption failed: {e}") from e

    def decrypt_aes_gcm(
        self,
        encrypted_data: bytes,
        nonce: bytes,
        tag: bytes,
        key: Optional[bytes] = None
    ) -> bytes:
        """Decrypt data using AES-256-GCM.

        Args:
            encrypted_data: Encrypted data
            nonce: Nonce used for encryption
            tag: Authentication tag
            key: Decryption key (uses master key if None)

        Returns:
            Decrypted data
        """
        decryption_key = key or self.master_key

        try:
            cipher = Cipher(algorithms.AES(decryption_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            logger.debug("Data decrypted using AES-256-GCM")
            return decrypted_data
        except Exception as e:
            logger.error("AES-GCM decryption failed", error=str(e))
            raise EncryptionError(f"AES-GCM decryption failed: {e}") from e

    def encrypt_text(self, text: str) -> str:
        """Encrypt text and return base64-encoded result.

        Args:
            text: Text to encrypt

        Returns:
            Base64-encoded encrypted text
        """
        encrypted = self.encrypt_fernet(text)
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_text(self, encrypted_text: str) -> str:
        """Decrypt base64-encoded encrypted text.

        Args:
            encrypted_text: Base64-encoded encrypted text

        Returns:
            Decrypted text
        """
        encrypted_bytes = base64.b64decode(encrypted_text.encode('utf-8'))
        decrypted = self.decrypt_fernet(encrypted_bytes)
        return decrypted.decode('utf-8')


class HashingManager:
    """Comprehensive password hashing utilities using Argon2."""

    def __init__(
        self,
        time_cost: int = 3,
        memory_cost: int = 65536,  # 64 MB
        parallelism: int = 1,
        hash_len: int = 32,
        salt_len: int = 16
    ):
        """Initialize hashing manager with Argon2 parameters.

        Args:
            time_cost: Number of iterations
            memory_cost: Memory usage in KiB
            parallelism: Number of parallel threads
            hash_len: Length of the hash in bytes
            salt_len: Length of the salt in bytes
        """
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.hash_len = hash_len
        self.salt_len = salt_len

        # Initialize Argon2 hasher
        self.hasher = argon2.PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len
        )

    def hash_password(self, password: str) -> str:
        """Hash a password using Argon2.

        Args:
            password: Password to hash

        Returns:
            Hashed password
        """
        try:
            hashed = self.hasher.hash(password)
            logger.debug("Password hashed successfully")
            return hashed
        except Exception as e:
            logger.error("Password hashing failed", error=str(e))
            raise HashingError(f"Password hashing failed: {e}") from e

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify a password against its hash.

        Args:
            password: Plain text password
            hashed_password: Hashed password

        Returns:
            True if password matches, False otherwise
        """
        try:
            self.hasher.verify(hashed_password, password)
            logger.debug("Password verification successful")
            return True
        except argon2.exceptions.VerifyMismatchError:
            logger.debug("Password verification failed")
            return False
        except Exception as e:
            logger.error("Password verification error", error=str(e))
            raise HashingError(f"Password verification error: {e}") from e

    def needs_rehash(self, hashed_password: str) -> bool:
        """Check if a password hash needs to be rehashed.

        Args:
            hashed_password: Hashed password

        Returns:
            True if rehashing is needed
        """
        try:
            return self.hasher.check_needs_rehash(hashed_password)
        except Exception as e:
            logger.warning("Failed to check rehash requirement", error=str(e))
            return False

    def hash_data(self, data: Union[str, bytes], algorithm: str = "sha256") -> str:
        """Hash arbitrary data using specified algorithm.

        Args:
            data: Data to hash
            algorithm: Hash algorithm (sha256, sha512, etc.)

        Returns:
            Hexadecimal hash
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        try:
            hasher = hashlib.new(algorithm)
            hasher.update(data)
            result = hasher.hexdigest()

            logger.debug(f"Data hashed using {algorithm}")
            return result
        except Exception as e:
            logger.error(f"Data hashing failed with {algorithm}", error=str(e))
            raise HashingError(f"Data hashing failed: {e}") from e

    def hash_with_salt(self, data: Union[str, bytes], salt: Optional[bytes] = None) -> tuple[str, bytes]:
        """Hash data with salt using SHA-256.

        Args:
            data: Data to hash
            salt: Salt (generates random if None)

        Returns:
            Tuple of (hash, salt)
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        if salt is None:
            salt = secrets.token_bytes(32)

        try:
            hasher = hashlib.sha256()
            hasher.update(salt)
            hasher.update(data)
            hash_result = hasher.hexdigest()

            logger.debug("Data hashed with salt")
            return hash_result, salt
        except Exception as e:
            logger.error("Salted hashing failed", error=str(e))
            raise HashingError(f"Salted hashing failed: {e}") from e

    def verify_hash_with_salt(self, data: Union[str, bytes], hash_value: str, salt: bytes) -> bool:
        """Verify data against hash with salt.

        Args:
            data: Original data
            hash_value: Hash to verify against
            salt: Salt used for hashing

        Returns:
            True if data matches hash
        """
        computed_hash, _ = self.hash_with_salt(data, salt)
        return secrets.compare_digest(computed_hash, hash_value)


def generate_secure_token(length: int = 32) -> str:
    """Generate a secure random token.

    Args:
        length: Token length in bytes

    Returns:
        URL-safe base64-encoded token
    """
    token_bytes = secrets.token_bytes(length)
    return base64.urlsafe_b64encode(token_bytes).decode('utf-8')


def generate_api_key(prefix: str = "ak", length: int = 32) -> str:
    """Generate an API key with prefix.

    Args:
        prefix: Key prefix
        length: Random part length in bytes

    Returns:
        API key with prefix
    """
    random_part = generate_secure_token(length)
    return f"{prefix}_{random_part}"


def constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks.

    Args:
        a: First string
        b: Second string

    Returns:
        True if strings are equal
    """
    return secrets.compare_digest(a, b)
