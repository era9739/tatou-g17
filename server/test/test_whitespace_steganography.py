"""Unit tests for whitespace_steganography.py

Tests cover the WhitespaceSteganography watermarking method including:
- Basic roundtrip operations
- Error handling and validation
- Binary/whitespace conversion helpers
- Edge cases and security aspects
"""
from __future__ import annotations
from pathlib import Path
import pytest
import struct

from whitespace_steganography import WhitespaceSteganography
from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
)


@pytest.fixture
def method():
    """Create a WhitespaceSteganography instance."""
    return WhitespaceSteganography()


@pytest.fixture
def sample_pdf_path(tmp_path: Path) -> Path:
    """Create a minimal valid PDF for testing."""
    pdf = tmp_path / "sample.pdf"
    pdf.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"%%EOF\n"
    )
    return pdf


@pytest.fixture
def secret() -> str:
    """Standard test secret."""
    return "test-secret-message"


@pytest.fixture
def key() -> str:
    """Standard test key."""
    return "test-encryption-key"


# ============================================================================
# Basic Functionality Tests
# ============================================================================

class TestBasicFunctionality:
    """Test core watermarking operations."""

    def test_add_watermark_returns_bytes(self, method, sample_pdf_path, secret, key):
        """Verify add_watermark returns bytes."""
        result = method.add_watermark(sample_pdf_path, secret, key)
        assert isinstance(result, bytes)

    def test_watermarked_pdf_is_larger(self, method, sample_pdf_path, secret, key):
        """Watermarked PDF should be larger than original."""
        original = sample_pdf_path.read_bytes()
        watermarked = method.add_watermark(sample_pdf_path, secret, key)
        assert len(watermarked) > len(original)

    def test_watermarked_pdf_starts_with_pdf_header(self, method, sample_pdf_path, secret, key):
        """Output should still be a valid PDF."""
        watermarked = method.add_watermark(sample_pdf_path, secret, key)
        assert watermarked.startswith(b"%PDF-")

    def test_watermark_contains_magic_marker(self, method, sample_pdf_path, secret, key):
        """Watermarked PDF should contain the magic marker."""
        watermarked = method.add_watermark(sample_pdf_path, secret, key)
        assert method._MAGIC in watermarked

    def test_roundtrip_recovers_secret(self, method, sample_pdf_path, secret, key, tmp_path):
        """Add watermark and read it back successfully."""
        watermarked = method.add_watermark(sample_pdf_path, secret, key)
        watermarked_path = tmp_path / "watermarked.pdf"
        watermarked_path.write_bytes(watermarked)

        recovered = method.read_secret(watermarked_path, key)
        assert recovered == secret

    def test_is_watermark_applicable_for_valid_pdf(self, method, sample_pdf_path):
        """Valid PDF should be applicable for watermarking."""
        assert method.is_watermark_applicable(sample_pdf_path) is True

    def test_get_usage_returns_string(self, method):
        """get_usage should return a descriptive string."""
        usage = method.get_usage()
        assert isinstance(usage, str)
        assert len(usage) > 0


# ============================================================================
# Input Validation Tests
# ============================================================================

class TestInputValidation:
    """Test validation of input parameters."""

    def test_add_watermark_empty_secret_raises(self, method, sample_pdf_path, key):
        """Empty secret should raise ValueError."""
        with pytest.raises(ValueError, match="Secret must be a non-empty string"):
            method.add_watermark(sample_pdf_path, "", key)

    def test_add_watermark_empty_key_raises(self, method, sample_pdf_path, secret):
        """Empty key should raise ValueError."""
        with pytest.raises(ValueError, match="Key must be a non-empty string"):
            method.add_watermark(sample_pdf_path, secret, "")

    def test_add_watermark_non_string_key_raises(self, method, sample_pdf_path, secret):
        """Non-string key should raise ValueError."""
        with pytest.raises(ValueError, match="Key must be a non-empty string"):
            method.add_watermark(sample_pdf_path, secret, None)

    def test_read_secret_empty_key_raises(self, method, sample_pdf_path):
        """Empty key should raise ValueError when reading."""
        with pytest.raises(ValueError, match="Key must be a non-empty string"):
            method.read_secret(sample_pdf_path, "")

    def test_read_secret_non_string_key_raises(self, method, sample_pdf_path):
        """Non-string key should raise ValueError when reading."""
        with pytest.raises(ValueError, match="Key must be a non-empty string"):
            method.read_secret(sample_pdf_path, None)


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestErrorHandling:
    """Test error conditions and exceptions."""

    def test_read_secret_no_watermark_raises(self, method, sample_pdf_path, key):
        """Reading from unwatermarked PDF should raise SecretNotFoundError."""
        with pytest.raises(SecretNotFoundError, match="No whitespace watermark found"):
            method.read_secret(sample_pdf_path, key)

    def test_read_secret_wrong_key_raises(self, method, sample_pdf_path, secret, tmp_path):
        """Wrong decryption key should raise InvalidKeyError."""
        watermarked = method.add_watermark(sample_pdf_path, secret, "correct-key")
        watermarked_path = tmp_path / "watermarked.pdf"
        watermarked_path.write_bytes(watermarked)

        with pytest.raises(InvalidKeyError, match="Decryption failed"):
            method.read_secret(watermarked_path, "wrong-key")

    def test_read_secret_empty_whitespace_data_raises(self, method, sample_pdf_path, key):
        """Marker present but no whitespace data should raise error."""
        data = sample_pdf_path.read_bytes()
        corrupted = data + method._MAGIC + b"\n"
        corrupted_path = sample_pdf_path.parent / "corrupted.pdf"
        corrupted_path.write_bytes(corrupted)

        with pytest.raises(SecretNotFoundError, match="Found marker but empty whitespace data"):
            method.read_secret(corrupted_path, key)

    def test_read_secret_payload_too_short_raises(self, method, sample_pdf_path, key):
        """Payload shorter than minimum size should raise error."""
        data = sample_pdf_path.read_bytes()
        corrupted = data + method._MAGIC + b"   \t\t " + b"\n"  # Too short
        corrupted_path = sample_pdf_path.parent / "short.pdf"
        corrupted_path.write_bytes(corrupted)

        with pytest.raises(SecretNotFoundError, match="Payload too short"):
            method.read_secret(corrupted_path, key)

    def test_read_secret_invalid_magic_in_payload_raises(self, method, sample_pdf_path, key):
        """Invalid magic marker in payload should raise error."""
        data = sample_pdf_path.read_bytes()
        # Create a minimal but invalid payload
        bad_magic = b"BAD1"
        fake_payload = bad_magic + struct.pack(">I", 16) + b"\x00" * 40
        binary = method._bytes_to_binary(fake_payload)
        whitespace = method._binary_to_whitespace(binary)
        corrupted = data + method._MAGIC + whitespace.encode('latin-1') + b"\n"
        corrupted_path = sample_pdf_path.parent / "bad_magic.pdf"
        corrupted_path.write_bytes(corrupted)

        with pytest.raises(SecretNotFoundError, match="Invalid magic marker in payload"):
            method.read_secret(corrupted_path, key)

    def test_is_watermark_applicable_invalid_pdf_returns_false(self, method, tmp_path):
        """Invalid PDF should not be applicable."""
        invalid_pdf = tmp_path / "invalid.pdf"
        invalid_pdf.write_bytes(b"not a pdf")
        assert method.is_watermark_applicable(invalid_pdf) is False


# ============================================================================
# Helper Method Tests
# ============================================================================

class TestHelperMethods:
    """Test internal helper methods."""

    def test_bytes_to_binary_conversion(self, method):
        """Test conversion from bytes to binary string."""
        data = b"ABC"
        binary = method._bytes_to_binary(data)
        # A=65=01000001, B=66=01000010, C=67=01000011
        expected = "010000010100001001000011"
        assert binary == expected

    def test_binary_to_bytes_conversion(self, method):
        """Test conversion from binary string to bytes."""
        binary = "010000010100001001000011"
        data = method._binary_to_bytes(binary)
        assert data == b"ABC"

    def test_binary_to_bytes_with_padding(self, method):
        """Binary string not multiple of 8 should be padded."""
        binary = "01000001010"  # 11 bits
        data = method._binary_to_bytes(binary)
        # Should pad with 5 zeros: 0100000101000000
        assert len(data) == 2
        assert data[0] == 0b01000001  # 'A'
        assert data[1] == 0b01000000  # '@'

    def test_binary_to_whitespace_conversion(self, method):
        """Test conversion from binary to whitespace."""
        binary = "01001"
        whitespace = method._binary_to_whitespace(binary)
        # 0=space, 1=tab
        # Binary "01001" = space, tab, space, space, tab
        expected = " \t  \t"
        assert whitespace == expected

    def test_whitespace_to_binary_conversion(self, method):
        """Test conversion from whitespace to binary."""
        whitespace = " \t  \t"
        binary = method._whitespace_to_binary(whitespace)
        # space, tab, space, space, tab = 0, 1, 0, 0, 1
        expected = "01001"
        assert binary == expected

    def test_whitespace_roundtrip(self, method):
        """Binary -> Whitespace -> Binary should be lossless."""
        binary = "110010101100"
        whitespace = method._binary_to_whitespace(binary)
        recovered = method._whitespace_to_binary(whitespace)
        assert recovered == binary

    def test_bytes_roundtrip(self, method):
        """Bytes -> Binary -> Bytes should be lossless."""
        data = b"Hello World!"
        binary = method._bytes_to_binary(data)
        recovered = method._binary_to_bytes(binary)
        assert recovered == data


# ============================================================================
# Edge Cases and Special Scenarios
# ============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_watermark_with_unicode_secret(self, method, sample_pdf_path, key, tmp_path):
        """Unicode characters in secret should work."""
        secret = "Hello 世界 🌍"
        watermarked = method.add_watermark(sample_pdf_path, secret, key)
        watermarked_path = tmp_path / "unicode.pdf"
        watermarked_path.write_bytes(watermarked)

        recovered = method.read_secret(watermarked_path, key)
        assert recovered == secret

    def test_watermark_with_long_secret(self, method, sample_pdf_path, key, tmp_path):
        """Very long secret should work."""
        secret = "A" * 1000
        watermarked = method.add_watermark(sample_pdf_path, secret, key)
        watermarked_path = tmp_path / "long.pdf"
        watermarked_path.write_bytes(watermarked)

        recovered = method.read_secret(watermarked_path, key)
        assert recovered == secret

    def test_watermark_with_special_characters(self, method, sample_pdf_path, key, tmp_path):
        """Secret with special characters should work."""
        secret = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        watermarked = method.add_watermark(sample_pdf_path, secret, key)
        watermarked_path = tmp_path / "special.pdf"
        watermarked_path.write_bytes(watermarked)

        recovered = method.read_secret(watermarked_path, key)
        assert recovered == secret

    def test_pdf_without_trailing_newline(self, method, secret, key, tmp_path):
        """PDF without trailing newline should be handled."""
        pdf = tmp_path / "no_newline.pdf"
        pdf.write_bytes(b"%PDF-1.4\n%%EOF")  # No trailing newline

        watermarked = method.add_watermark(pdf, secret, key)
        assert method._MAGIC in watermarked

    def test_multiple_watermarks_reads_last(self, method, sample_pdf_path, key, tmp_path):
        """Multiple watermarks should read the last one."""
        watermarked1 = method.add_watermark(sample_pdf_path, "first-secret", key)
        path1 = tmp_path / "first.pdf"
        path1.write_bytes(watermarked1)

        watermarked2 = method.add_watermark(path1, "second-secret", key)
        path2 = tmp_path / "second.pdf"
        path2.write_bytes(watermarked2)

        recovered = method.read_secret(path2, key)
        assert recovered == "second-secret"

    def test_position_parameter_ignored(self, method, sample_pdf_path, secret, key):
        """Position parameter should be ignored."""
        result1 = method.add_watermark(sample_pdf_path, secret, key, position=None)
        result2 = method.add_watermark(sample_pdf_path, secret, key, position="some-position")
        # Results won't be identical due to random salt/nonce, but both should work
        assert len(result1) > 0
        assert len(result2) > 0

    def test_empty_secret_error_message(self, sample_pdf, key):
        """Test that error message is specific and helpful"""
        method = WhitespaceSteganography()

        with pytest.raises(ValueError) as exc_info:
            method.add_watermark(sample_pdf, "", key)

        error_message = str(exc_info.value).lower()
        assert "secret" in error_message
        assert "non-empty" in error_message or "empty" in error_message
        assert "xx" not in error_message.lower()

    def test_none_secret_error_message(self, sample_pdf, key):
        """Test error message when secret is None"""
        method = WhitespaceSteganography()

        with pytest.raises((ValueError, TypeError)) as exc_info:
            method.add_watermark(sample_pdf, None, key)

        assert exc_info.value is not None
        error_str = str(exc_info.value)
        assert len(error_str) > 0

    def test_all_error_messages_are_valid(self, sample_pdf, key):
        """Ensure all error messages in WhitespaceSteganography are proper strings"""
        method = WhitespaceSteganography()

        # Test empty secret error message
        try:
            method.add_watermark(sample_pdf, "", key)
        except ValueError as e:
            msg = str(e)
            assert len(msg) > 0
            assert "XX" not in msg  # No mutation markers
            assert msg[0].isupper() or msg[0].isdigit()  # Proper sentence

        # Test invalid key error message
        watermarked = method.add_watermark(sample_pdf, "test", key)
        try:
            method.read_secret(watermarked, "wrong-key")
        except (InvalidKeyError, Exception) as e:
            msg = str(e)
            assert len(msg) > 0
            assert "XX" not in msg


# ============================================================================
# Encryption/Decryption Tests
# ============================================================================

class TestEncryptionDecryption:
    """Test encryption and decryption functionality."""

    def test_encrypt_secret_returns_bytes(self, method):
        """_encrypt_secret should return bytes."""
        salt = b"0" * method._SALT_SIZE
        nonce = b"1" * method._NONCE_SIZE
        result = method._encrypt_secret("test", "key", salt, nonce)
        assert isinstance(result, bytes)

    def test_decrypt_secret_returns_string(self, method):
        """_decrypt_secret should return string."""
        salt = b"0" * method._SALT_SIZE
        nonce = b"1" * method._NONCE_SIZE
        encrypted = method._encrypt_secret("test", "key", salt, nonce)
        decrypted = method._decrypt_secret(encrypted, "key", salt, nonce)
        assert isinstance(decrypted, str)
        assert decrypted == "test"

    def test_encryption_with_different_salts_differs(self, method):
        """Same secret with different salts should produce different ciphertext."""
        salt1 = b"0" * method._SALT_SIZE
        salt2 = b"1" * method._SALT_SIZE
        nonce = b"2" * method._NONCE_SIZE

        encrypted1 = method._encrypt_secret("test", "key", salt1, nonce)
        encrypted2 = method._encrypt_secret("test", "key", salt2, nonce)
        assert encrypted1 != encrypted2

    def test_encryption_with_different_nonces_differs(self, method):
        """Same secret with different nonces should produce different ciphertext."""
        salt = b"0" * method._SALT_SIZE
        nonce1 = b"1" * method._NONCE_SIZE
        nonce2 = b"2" * method._NONCE_SIZE

        encrypted1 = method._encrypt_secret("test", "key", salt, nonce1)
        encrypted2 = method._encrypt_secret("test", "key", salt, nonce2)
        assert encrypted1 != encrypted2

    def test_decrypt_with_wrong_salt_fails(self, method):
        """Decryption with wrong salt should fail."""
        salt = b"0" * method._SALT_SIZE
        wrong_salt = b"1" * method._SALT_SIZE
        nonce = b"2" * method._NONCE_SIZE

        encrypted = method._encrypt_secret("test", "key", salt, nonce)
        with pytest.raises(InvalidKeyError):
            method._decrypt_secret(encrypted, "key", wrong_salt, nonce)

    def test_decrypt_with_wrong_nonce_fails(self, method):
        """Decryption with wrong nonce should fail."""
        salt = b"0" * method._SALT_SIZE
        nonce = b"1" * method._NONCE_SIZE
        wrong_nonce = b"2" * method._NONCE_SIZE

        encrypted = method._encrypt_secret("test", "key", salt, nonce)
        with pytest.raises(InvalidKeyError):
            method._decrypt_secret(encrypted, "key", salt, wrong_nonce)


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests simulating real-world usage."""

    def test_multiple_different_secrets_with_same_key(self, method, sample_pdf_path, key, tmp_path):
        """Multiple PDFs can be watermarked with different secrets using same key."""
        secrets = ["secret1", "secret2", "secret3"]

        for i, secret in enumerate(secrets):
            watermarked = method.add_watermark(sample_pdf_path, secret, key)
            path = tmp_path / f"watermarked_{i}.pdf"
            path.write_bytes(watermarked)

            recovered = method.read_secret(path, key)
            assert recovered == secret

    def test_same_secret_with_different_keys(self, method, sample_pdf_path, secret, tmp_path):
        """Same secret can be watermarked with different keys."""
        keys = ["key1", "key2", "key3"]

        for i, key in enumerate(keys):
            watermarked = method.add_watermark(sample_pdf_path, secret, key)
            path = tmp_path / f"watermarked_{i}.pdf"
            path.write_bytes(watermarked)

            recovered = method.read_secret(path, key)
            assert recovered == secret

            # Verify other keys don't work
            for other_key in keys:
                if other_key != key:
                    with pytest.raises(InvalidKeyError):
                        method.read_secret(path, other_key)

    def test_watermark_preserves_pdf_readability(self, method, sample_pdf_path, secret, key, tmp_path):
        """Watermarked PDF should still be a valid PDF structure."""
        watermarked = method.add_watermark(sample_pdf_path, secret, key)

        # Check basic PDF structure elements
        assert b"%PDF-" in watermarked
        assert b"%%EOF" in watermarked
        assert watermarked.count(b"%%EOF") >= 1


# ============================================================================
# Constants and Metadata Tests
# ============================================================================

class TestConstants:
    """Test class constants and metadata."""

    def test_method_name(self, method):
        """Method should have correct name."""
        assert method.name == "whitespace-stego"

    def test_magic_marker_format(self, method):
        """Magic marker should have expected format."""
        assert method._MAGIC == b"\n%%WHITESPACE-STEGO:v1\n"

    def test_salt_size(self, method):
        """Salt size should be 16 bytes."""
        assert method._SALT_SIZE == 16

    def test_nonce_size(self, method):
        """Nonce size should be 12 bytes."""
        assert method._NONCE_SIZE == 12

    def test_kdf_iterations(self, method):
        """KDF iterations should be 100000."""
        assert method._KDF_ITERATIONS == 100000