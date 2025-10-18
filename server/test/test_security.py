"""Security tests for CLI and file handling"""
import pytest
import sys
import warnings
from pathlib import Path
from security_utils import (
    validate_file_path,
    validate_pdf_file,
    sanitize_method_name,
    validate_secret_length,
    warn_insecure_key_usage,
    SecurityError,
    SecurityWarning  # ← ADD THIS
)


class TestPathValidation:
    """Test path validation security"""

    def test_valid_relative_path_in_cwd(self, tmp_path, monkeypatch):
        """Test valid relative path in current directory"""
        monkeypatch.chdir(tmp_path)
        test_file = tmp_path / "test.pdf"
        test_file.touch()

        result = validate_file_path("test.pdf", must_exist=True)
        assert result.exists()
        assert result.is_absolute()

    def test_valid_absolute_path_in_home(self, tmp_path):
        """Test absolute path in temp directory works (pytest temp)"""
        # pytest tmp_path is automatically safe
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        test_file = subdir / "test.pdf"
        test_file.touch()

        # Should work - pytest temp is allowed
        result = validate_file_path(str(test_file), must_exist=True)
        assert result.exists()

    def test_path_traversal_blocked(self):
        """Test that path traversal attempts are caught"""
        # Will be blocked by either "outside allowed" or "system directory"
        with pytest.raises(SecurityError):
            validate_file_path("../../../etc/passwd")

    def test_absolute_system_path_blocked(self):
        """Test that system paths are blocked"""
        # Will be blocked by "outside allowed" check
        with pytest.raises(SecurityError):
            validate_file_path("/etc/shadow")

    def test_empty_path_rejected(self):
        """Test empty path is rejected"""
        with pytest.raises(SecurityError, match="empty"):
            validate_file_path("")

    def test_whitespace_only_path_rejected(self):
        """Test whitespace-only path rejected"""
        with pytest.raises(SecurityError, match="empty"):
            validate_file_path("   ")

    def test_must_exist_validates_existence(self, tmp_path):
        """Test must_exist parameter works"""
        nonexistent = tmp_path / "does_not_exist.pdf"

        # Pytest tmp allowed, but file doesn't exist
        with pytest.raises(FileNotFoundError):
            validate_file_path(str(nonexistent), must_exist=True)

    def test_can_create_new_file(self, tmp_path, monkeypatch):
        """Test can validate path for new file creation"""
        monkeypatch.chdir(tmp_path)
        new_file = "output.pdf"

        # Should not raise
        result = validate_file_path(new_file, must_exist=False)
        assert not result.exists()  # File doesn't exist yet


class TestPDFValidation:
    """Test PDF file validation"""

    def test_valid_pdf_accepted(self, tmp_path):
        """Test valid PDF is accepted"""
        pdf = tmp_path / "valid.pdf"
        pdf.write_bytes(b"%PDF-1.4\n%%EOF\n")

        assert validate_pdf_file(pdf) is True

    def test_non_pdf_rejected(self, tmp_path):
        """Test non-PDF files are rejected"""
        fake_pdf = tmp_path / "fake.pdf"
        fake_pdf.write_text("This is not a PDF")

        with pytest.raises(SecurityError, match="not a valid PDF"):
            validate_pdf_file(fake_pdf)

    def test_empty_file_rejected(self, tmp_path):
        """Test empty file is rejected"""
        empty = tmp_path / "empty.pdf"
        empty.write_bytes(b"")

        with pytest.raises(SecurityError, match="not a valid PDF"):
            validate_pdf_file(empty)

    def test_directory_rejected(self, tmp_path):
        """Test directory is rejected"""
        directory = tmp_path / "not_a_file"
        directory.mkdir()

        with pytest.raises(SecurityError, match="not a file"):
            validate_pdf_file(directory)

    def test_oversized_file_rejected(self, tmp_path):
        """Test files over size limit are rejected"""
        huge_pdf = tmp_path / "huge.pdf"
        # Create 2MB file (over 1MB limit for test)
        huge_pdf.write_bytes(b"%PDF-1.4\n" + b"X" * (2 * 1024 * 1024))

        with pytest.raises(SecurityError, match="too large"):
            validate_pdf_file(huge_pdf, max_size_mb=1)

    def test_nonexistent_file_raises(self, tmp_path):
        """Test nonexistent file raises FileNotFoundError"""
        nonexistent = tmp_path / "missing.pdf"

        with pytest.raises(FileNotFoundError):
            validate_pdf_file(nonexistent)


class TestMethodSanitization:
    """Test method name sanitization"""

    def test_valid_method_names(self):
        """Test valid method names pass"""
        valid_methods = [
            "whitespace-stego",
            "add-after-eof",
            "base64_comment",
            "method123",
            "Method_Name",
            "test-method_1"
        ]
        for method in valid_methods:
            result = sanitize_method_name(method)
            assert result == method

    def test_command_injection_attempts_blocked(self):
        """Test command injection attempts are blocked"""
        injection_attempts = [
            "method; rm -rf /",
            "method`whoami`",
            "method$(cat /etc/passwd)",
            "method&& ls",
            "method | cat",
            "method > /etc/passwd",
            "method < input.txt",
            "method\nls",
            "method\rcat"
        ]
        for attempt in injection_attempts:
            with pytest.raises(SecurityError):
                sanitize_method_name(attempt)

    def test_path_traversal_in_method_blocked(self):
        """Test path traversal in method name blocked"""
        with pytest.raises(SecurityError):
            sanitize_method_name("../../etc/passwd")

    def test_long_method_name_rejected(self):
        """Test very long method names rejected"""
        long_name = "a" * 51
        with pytest.raises(SecurityError, match="too long"):
            sanitize_method_name(long_name)

    def test_empty_method_rejected(self):
        """Test empty method name rejected"""
        with pytest.raises(SecurityError, match="empty"):
            sanitize_method_name("")

    def test_whitespace_only_method_rejected(self):
        """Test whitespace-only method rejected"""
        with pytest.raises(SecurityError, match="empty"):
            sanitize_method_name("   ")


class TestSecretValidation:
    """Test secret/key validation"""

    def test_valid_secret_accepted(self):
        """Test valid secrets are accepted"""
        valid_secrets = [
            "a",  # Minimum length
            "normal-secret-123",
            "a" * 1000,  # Long but within limit
            "Special!@#$%Characters"
        ]
        for secret in valid_secrets:
            assert validate_secret_length(secret) is True

    def test_empty_secret_rejected(self):
        """Test empty secret is rejected"""
        with pytest.raises(SecurityError, match="empty"):
            validate_secret_length("")

    def test_too_long_secret_rejected(self):
        """Test very long secrets rejected (DoS prevention)"""
        huge_secret = "x" * 10001

        with pytest.raises(SecurityError, match="too long"):
            validate_secret_length(huge_secret)

    def test_custom_length_limits(self):
        """Test custom min/max length limits"""
        # Too short
        with pytest.raises(SecurityError, match="too short"):
            validate_secret_length("abc", min_length=5)

        # Too long
        with pytest.raises(SecurityError, match="too long"):
            validate_secret_length("abcdefghij", max_length=5)

        # Just right
        assert validate_secret_length("abcde", min_length=5, max_length=5) is True


class TestSecurityWarnings:
    """Test security warning system"""

    def test_insecure_key_warning_issued(self):
        """Test warning when using insecure key method"""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            warn_insecure_key_usage()

            assert len(w) == 1
            assert issubclass(w[0].category, SecurityWarning)
            assert "process list" in str(w[0].message).lower()
            assert "ps aux" in str(w[0].message).lower()


class TestIntegration:
    """Integration tests for security utilities"""

    def test_secure_workflow(self, tmp_path, monkeypatch):
        """Test complete secure workflow"""
        monkeypatch.chdir(tmp_path)

        # Create valid PDF
        pdf_path = tmp_path / "input.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\nContent\n%%EOF\n")

        # Validate input path
        validated_input = validate_file_path("input.pdf", must_exist=True)
        assert validated_input.exists()

        # Validate it's a PDF
        assert validate_pdf_file(validated_input) is True

        # Validate output path
        validated_output = validate_file_path("output.pdf", must_exist=False)
        assert not validated_output.exists()

        # Sanitize method
        method = sanitize_method_name("whitespace-stego")
        assert method == "whitespace-stego"

        # Validate secret
        secret = "test-secret-123"
        assert validate_secret_length(secret) is True

    def test_insecure_workflow_blocked(self):
        """Test that insecure operations are blocked"""
        # Try to access system file
        with pytest.raises(SecurityError):
            validate_file_path("/etc/passwd", must_exist=False)

        # Try injection in method
        with pytest.raises(SecurityError):
            sanitize_method_name("method; rm -rf /")

        # Try huge secret (DoS)
        with pytest.raises(SecurityError):
            validate_secret_length("x" * 100000)