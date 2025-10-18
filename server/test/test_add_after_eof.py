import pytest
from pathlib import Path
from add_after_eof import AddAfterEOF
from watermarking_method import SecretNotFoundError, InvalidKeyError, load_pdf_bytes


@pytest.fixture
def method():
    """Create AddAfterEOF instance"""
    return AddAfterEOF()


@pytest.fixture
def simple_pdf(tmp_path):
    """Create a simple test PDF"""
    pdf = tmp_path / "test.pdf"
    pdf.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")
    return pdf


class TestAddWatermark:
    """Test watermark addition"""

    def test_add_watermark_basic(self, method, simple_pdf):
        """Test basic watermark addition"""
        result = method.add_watermark(simple_pdf, "test-secret", "test-key")

        assert isinstance(result, bytes)
        assert b"%PDF-" in result
        assert b"%%EOF" in result

    def test_add_watermark_empty_secret_raises(self, method, simple_pdf):
        """Test empty secret raises error"""
        with pytest.raises(ValueError, match="[Ss]ecret"):
            method.add_watermark(simple_pdf, "", "key")

    def test_add_watermark_empty_key_raises(self, method, simple_pdf):
        """Test empty key raises error"""
        with pytest.raises(ValueError, match="[Kk]ey"):
            method.add_watermark(simple_pdf, "secret", "")

    def test_add_watermark_preserves_structure(self, method, simple_pdf):
        """Test PDF structure is preserved"""
        result = method.add_watermark(simple_pdf, "secret", "key")

        assert result.startswith(b"%PDF-")
        assert b"%%EOF" in result

    def test_add_watermark_deterministic(self, method, simple_pdf):
        """Test same inputs produce same output"""
        result1 = method.add_watermark(simple_pdf, "secret", "key")
        result2 = method.add_watermark(simple_pdf, "secret", "key")

        assert result1 == result2


class TestReadSecret:
    """Test watermark reading"""

    def test_read_secret_roundtrip(self, method, simple_pdf):
        """Test reading embedded secret"""
        secret = "test-secret-123"
        key = "test-key"

        watermarked = method.add_watermark(simple_pdf, secret, key)
        extracted = method.read_secret(watermarked, key)

        assert extracted == secret

    def test_read_secret_no_watermark_raises(self, method, simple_pdf):
        """Test reading from non-watermarked PDF raises error"""
        with pytest.raises(SecretNotFoundError):
            method.read_secret(simple_pdf, "key")

    def test_read_secret_wrong_key_raises(self, method, simple_pdf):
        """Test wrong key raises error"""
        watermarked = method.add_watermark(simple_pdf, "secret", "correct-key")

        with pytest.raises(InvalidKeyError):
            method.read_secret(watermarked, "wrong-key")

    def test_read_secret_various_secrets(self, method, simple_pdf):
        """Test roundtrip with various secrets"""
        test_secrets = [
            "simple",
            "with spaces",
            "with-dashes",
            "123456",
            "MixedCase123",
        ]

        for secret in test_secrets:
            watermarked = method.add_watermark(simple_pdf, secret, "key")
            extracted = method.read_secret(watermarked, "key")
            assert extracted == secret


class TestEdgeCases:
    """Test edge cases"""

    def test_multiple_watermarks(self, method, simple_pdf):
        """Test watermarking already watermarked PDF"""
        wm1 = method.add_watermark(simple_pdf, "secret1", "key1")
        wm2 = method.add_watermark(wm1, "secret2", "key2")

        # Second watermark should work
        extracted = method.read_secret(wm2, "key2")
        assert extracted == "secret2"

    def test_long_secret(self, method, simple_pdf):
        """Test with long secret"""
        long_secret = "x" * 1000
        watermarked = method.add_watermark(simple_pdf, long_secret, "key")
        extracted = method.read_secret(watermarked, "key")
        assert extracted == long_secret


class TestMethodContract:
    """Test method interface compliance"""

    def test_name_attribute(self, method):
        """Test method has name attribute"""
        assert hasattr(method, 'name')
        assert isinstance(method.name, str)
        assert len(method.name) > 0
        # The actual name is "toy-eof"
        assert method.name in ["toy-eof", "add-after-eof"]

    def test_has_get_usage(self, method):
        """Test has usage method"""
        assert hasattr(method, 'get_usage')
        usage = method.get_usage()
        assert isinstance(usage, str)
        assert len(usage) > 0