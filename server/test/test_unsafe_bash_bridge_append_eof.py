import pytest
from unsafe_bash_bridge_append_eof import UnsafeBashBridgeAppendEOF
from watermarking_method import SecretNotFoundError  # ← CORRECT IMPORT


@pytest.fixture
def method():
    """Create UnsafeBashBridgeAppendEOF instance"""
    return UnsafeBashBridgeAppendEOF()


class TestAddWatermark:
    """Test watermark embedding"""

    def test_add_watermark_basic(self, method, tmp_path):
        """Test basic watermark addition"""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\nContent\n%%EOF\n")

        secret = "test-secret-123"
        key = "test-key"

        result = method.add_watermark(pdf_path, secret, key)

        assert isinstance(result, bytes)
        assert result.startswith(b"%PDF-1.4")
        assert b"%%EOF" in result
        assert secret.encode() in result

    def test_add_watermark_preserves_content(self, method, tmp_path):
        """Test that original PDF content is preserved"""
        original_content = b"%PDF-1.4\nOriginal Content\n%%EOF\n"
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(original_content)

        result = method.add_watermark(pdf_path, "secret", "key")
        assert b"Original Content" in result

    def test_add_watermark_appends_after_eof(self, method, tmp_path):
        """Test that secret is appended after %%EOF"""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\n%%EOF\n")

        secret = "appended-secret"
        result = method.add_watermark(pdf_path, secret, "key")

        # Find EOF and check what's after
        eof_idx = result.rfind(b"%%EOF")
        after_eof = result[eof_idx + len(b"%%EOF"):]
        assert secret.encode() in after_eof

    def test_add_watermark_with_special_chars(self, method, tmp_path):
        """Test watermark with special characters"""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\n%%EOF\n")

        secret = "secret!@#$%"
        result = method.add_watermark(pdf_path, secret, "key")
        assert isinstance(result, bytes)

    def test_add_watermark_accepts_bytes_input(self, method):
        """Test that bytes input works"""
        pdf_bytes = b"%PDF-1.4\n%%EOF\n"
        result = method.add_watermark(pdf_bytes, "secret", "key")
        assert isinstance(result, bytes)


class TestReadSecret:
    """Test watermark extraction"""

    def test_read_secret_basic(self, method, tmp_path):
        """Test reading embedded secret"""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\n%%EOF\n")

        secret = "my-secret-data"
        key = "test-key"

        watermarked = method.add_watermark(pdf_path, secret, key)
        watermarked_path = tmp_path / "watermarked.pdf"
        watermarked_path.write_bytes(watermarked)

        extracted = method.read_secret(watermarked_path, key)
        assert secret == extracted or secret in extracted

    def test_read_secret_no_watermark_raises(self, method, tmp_path):
        """Test reading from non-watermarked PDF raises error"""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\n%%EOF\n")

        with pytest.raises(SecretNotFoundError):
            method.read_secret(pdf_path, "key")

    def test_read_secret_roundtrip(self, method, tmp_path):
        """Test complete roundtrip: add then read"""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\n%%EOF\n")

        original_secret = "roundtrip-test"
        key = "test-key"

        watermarked = method.add_watermark(pdf_path, original_secret, key)
        watermarked_path = tmp_path / "watermarked.pdf"
        watermarked_path.write_bytes(watermarked)

        extracted = method.read_secret(watermarked_path, key)
        assert original_secret in extracted or extracted == original_secret

    def test_read_secret_no_eof_raises(self, method, tmp_path):
        """Test reading from PDF without %%EOF raises error"""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\nNo EOF")

        with pytest.raises(SecretNotFoundError, match="%%EOF"):
            method.read_secret(pdf_path, "key")

    def test_read_secret_empty_after_eof_raises(self, method, tmp_path):
        """Test reading when nothing after %%EOF raises error"""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\n%%EOF")  # Nothing after

        with pytest.raises(SecretNotFoundError):
            method.read_secret(pdf_path, "key")


class TestEdgeCases:
    """Test edge cases"""

    def test_long_secret(self, method, tmp_path):
        """Test with very long secret"""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\n%%EOF\n")

        long_secret = "x" * 1000
        result = method.add_watermark(pdf_path, long_secret, "key")
        assert isinstance(result, bytes)

    def test_multiple_eof_markers(self, method, tmp_path):
        """Test PDF with multiple %%EOF markers"""
        pdf_content = b"%PDF-1.4\n%%EOF\nMore\n%%EOF\n"
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(pdf_content)

        result = method.add_watermark(pdf_path, "secret", "key")
        assert isinstance(result, bytes)

    def test_watermark_twice(self, method, tmp_path):
        """Test adding watermark twice"""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\n%%EOF\n")

        result1 = method.add_watermark(pdf_path, "secret1", "key")

        tmp_pdf = tmp_path / "temp.pdf"
        tmp_pdf.write_bytes(result1)
        result2 = method.add_watermark(tmp_pdf, "secret2", "key")

        # Both secrets should be present
        assert b"secret1" in result2
        assert b"secret2" in result2


class TestMethodContract:
    """Test that method follows the watermarking contract"""

    def test_has_required_methods(self, method):
        """Test class has required methods"""
        assert hasattr(method, 'add_watermark')
        assert hasattr(method, 'read_secret')
        assert callable(method.add_watermark)
        assert callable(method.read_secret)

    def test_name_attribute(self, method):
        """Test method has name attribute"""
        assert hasattr(method, 'name')
        assert method.name == "bash-bridge-eof"