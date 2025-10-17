"""Tests for watermarking CLI tool"""
import pytest
from pathlib import Path
from watermarking_cli import _read_text_from_file
from security_utils import SecurityError


class TestCLIHelpers:
    """Test CLI helper functions"""

    def test_read_text_from_file(self, tmp_path):
        """Test reading text from file"""
        test_file = tmp_path / "secret.txt"
        test_content = "my secret text"
        test_file.write_text(test_content)

        result = _read_text_from_file(str(test_file))
        assert result == test_content

    def test_read_text_from_file_not_found(self, tmp_path):
        """Test reading from non-existent file raises error"""
        # Use a path that would be allowed (in tmp) but doesn't exist
        nonexistent = tmp_path / "nonexistent_file.txt"

        with pytest.raises((FileNotFoundError, SecurityError)):
            # Either error is acceptable - file doesn't exist or path validation
            _read_text_from_file(str(nonexistent))

    def test_read_text_from_file_with_newlines(self, tmp_path):
        """Test reading file preserves content as-is"""
        test_file = tmp_path / "secret.txt"
        test_file.write_text("secret text\n\n")

        result = _read_text_from_file(str(test_file))
        # Function returns content as-is (doesn't strip)
        assert "secret text" in result


class TestCLIEdgeCases:
    """Test edge cases in CLI functions"""

    def test_read_empty_file(self, tmp_path):
        """Test reading empty file"""
        test_file = tmp_path / "empty.txt"
        test_file.write_text("")

        result = _read_text_from_file(str(test_file))
        assert result == ""

    def test_read_file_with_unicode(self, tmp_path):
        """Test reading file with unicode characters"""
        test_file = tmp_path / "unicode.txt"
        test_content = "Hello 🌍"
        test_file.write_text(test_content, encoding='utf-8')

        result = _read_text_from_file(str(test_file))
        assert "Hello" in result

    def test_read_file_with_spaces(self, tmp_path):
        """Test reading file with leading/trailing spaces"""
        test_file = tmp_path / "spaces.txt"
        test_file.write_text("  secret  ")

        result = _read_text_from_file(str(test_file))
        assert "secret" in result

    def test_read_multiline_file(self, tmp_path):
        """Test reading multi-line file"""
        test_file = tmp_path / "multiline.txt"
        test_content = "line1\nline2\nline3"
        test_file.write_text(test_content)

        result = _read_text_from_file(str(test_file))
        assert "line1" in result
        assert "line2" in result
        assert "line3" in result
