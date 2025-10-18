"""whitespace_steganography.py

True PDF watermarking using whitespace steganography.

This method embeds secrets by appending invisible whitespace after the PDF EOF,
similar to add_after_eof but encoding the data as actual whitespace characters
(spaces and tabs) rather than base64.

The whitespace is completely invisible and encodes binary data where:
- Space character = binary '0'
- Tab character = binary '1'

The secret is encrypted using AES-256-GCM with PBKDF2 key derivation.

Requirements
------------
- cryptography for AES encryption
- No PDF parsing library needed (works with raw bytes)
"""

from __future__ import annotations

from typing import Final
import secrets
import struct

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    raise ImportError(
        "cryptography is required. Install with: pip install cryptography"
    )

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
)


class WhitespaceSteganography(WatermarkingMethod):
    """True whitespace steganography for PDF watermarking.

    Appends invisible whitespace (spaces and tabs) after the PDF EOF marker.
    Each bit is encoded as:
    - Space (0x20) = binary 0
    - Tab (0x09) = binary 1
    """

    name: Final[str] = "whitespace-stego"

    _MAGIC: Final[bytes] = b"\n%%WHITESPACE-STEGO:v1\n"
    _SALT_SIZE: Final[int] = 16
    _NONCE_SIZE: Final[int] = 12
    _KDF_ITERATIONS: Final[int] = 100000

    @staticmethod
    def get_usage() -> str:
        return (
            "True whitespace steganography - embeds data as invisible whitespace after EOF. "
            "Position parameter is ignored (always appends after EOF)."
        )

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Embed watermark by appending invisible whitespace after PDF EOF."""
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        data = load_pdf_bytes(pdf)

        # Encrypt the secret
        salt = secrets.token_bytes(self._SALT_SIZE)
        nonce = secrets.token_bytes(self._NONCE_SIZE)
        encrypted_data = self._encrypt_secret(secret, key, salt, nonce)

        # Build payload
        length = len(encrypted_data)
        payload = b"WS01" + struct.pack(">I", length) + salt + nonce + encrypted_data

        # Convert to binary string
        binary_str = self._bytes_to_binary(payload)

        # Convert to whitespace encoding
        whitespace_data = self._binary_to_whitespace(binary_str)

        # Append after EOF marker (same pattern as add_after_eof.py)
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + whitespace_data.encode("latin-1") + b"\n"

        return out

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        """Check if PDF is valid."""
        try:
            load_pdf_bytes(pdf)
            return True
        except Exception:
            return False

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        """Extract the embedded secret from whitespace."""
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        data = load_pdf_bytes(pdf)

        # Find our marker
        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No whitespace watermark found")

        start = idx + len(self._MAGIC)
        # Whitespace data ends at next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        whitespace_bytes = data[start:end]

        if not whitespace_bytes:
            raise SecretNotFoundError("Found marker but empty whitespace data")

        # Decode whitespace to string
        whitespace_data = whitespace_bytes.decode("latin-1", errors="ignore")

        # Convert whitespace to binary
        binary_str = self._whitespace_to_binary(whitespace_data)

        # Convert binary to bytes
        payload = self._binary_to_bytes(binary_str)

        # Parse payload
        if len(payload) < 4 + 4:  # magic + length
            raise SecretNotFoundError("Payload too short")

        magic = payload[:4]
        if magic != b"WS01":
            raise SecretNotFoundError("Invalid magic marker in payload")

        length = struct.unpack(">I", payload[4:8])[0]
        offset = 8

        if len(payload) < offset + self._SALT_SIZE + self._NONCE_SIZE + length:
            raise SecretNotFoundError("Incomplete payload")

        salt = payload[offset : offset + self._SALT_SIZE]
        offset += self._SALT_SIZE

        nonce = payload[offset : offset + self._NONCE_SIZE]
        offset += self._NONCE_SIZE

        encrypted_data = payload[offset : offset + length]

        # Decrypt
        return self._decrypt_secret(encrypted_data, key, salt, nonce)

    # ---------------------
    # Internal helpers
    # ---------------------

    def _bytes_to_binary(self, data: bytes) -> str:
        """Convert bytes to binary string."""
        return "".join(format(byte, "08b") for byte in data)

    def _binary_to_bytes(self, binary: str) -> bytes:
        """Convert binary string to bytes."""
        # Pad to multiple of 8
        padding = (8 - len(binary) % 8) % 8
        binary = binary + "0" * padding

        result = []
        for i in range(0, len(binary), 8):
            byte_val = int(binary[i : i + 8], 2)
            result.append(byte_val)
        return bytes(result)

    def _binary_to_whitespace(self, binary: str) -> str:
        """Convert binary string to whitespace (space=0, tab=1)."""
        result = []
        for bit in binary:
            if bit == "0":
                result.append(" ")
            else:
                result.append("\t")
        return "".join(result)

    def _whitespace_to_binary(self, whitespace: str) -> str:
        """Convert whitespace to binary string."""
        result = []
        for char in whitespace:
            if char == " ":
                result.append("0")
            elif char == "\t":
                result.append("1")
        return "".join(result)

    def _encrypt_secret(
        self, secret: str, key: str, salt: bytes, nonce: bytes
    ) -> bytes:
        """Encrypt secret using AES-256-GCM."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self._KDF_ITERATIONS,
        )
        derived_key = kdf.derive(key.encode("utf-8"))

        aesgcm = AESGCM(derived_key)
        secret_bytes = secret.encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, secret_bytes, None)

        return ciphertext

    def _decrypt_secret(
        self, encrypted_data: bytes, key: str, salt: bytes, nonce: bytes
    ) -> str:
        """Decrypt secret using AES-256-GCM."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self._KDF_ITERATIONS,
        )
        derived_key = kdf.derive(key.encode("utf-8"))

        aesgcm = AESGCM(derived_key)
        try:
            plaintext = aesgcm.decrypt(nonce, encrypted_data, None)
            return plaintext.decode("utf-8")
        except Exception:
            raise InvalidKeyError("Decryption failed - invalid key or corrupted data")


__all__ = ["WhitespaceSteganography"]
