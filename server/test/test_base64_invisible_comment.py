from pathlib import Path

import pytest
from base64_invisible_comment import Base64InvisibleComment
from watermarking_method import SecretNotFoundError


def test_base64_invisible_comment_roundtrip(tmp_path: Path):
    """Verify that a Base64InvisibleComment watermark can be added and recovered correctly."""
    # Create a minimal valid PDF
    pdf_path = tmp_path / "sample.pdf"
    pdf_path.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")

    method = Base64InvisibleComment()
    secret = "softsec-test-secret"
    key = "unused-key"

    # Add watermark
    out_pdf_path = tmp_path / "watermarked.pdf"
    watermarked_bytes = method.add_watermark(pdf_path, secret=secret, key=key)
    out_pdf_path.write_bytes(watermarked_bytes)

    # Ensure watermark bytes are appended
    data = out_pdf_path.read_bytes()
    assert b"%%WM-B64:v1" in data, "Expected watermark marker not found in output PDF"
    assert data.startswith(b"%PDF-"), "Output should still be a valid PDF"

    # Read back the secret
    extracted = method.read_secret(out_pdf_path, key=key)
    assert extracted == secret, "Extracted secret must match the original"

def test_read_secret_raises_when_no_marker(tmp_path: Path):
    """Ensure that reading a watermark from a clean PDF raises SecretNotFoundError."""
    pdf_path = tmp_path / "clean.pdf"
    pdf_path.write_bytes(b"%PDF-1.4\n%%EOF\n")

    method = Base64InvisibleComment()

    try:
        method.read_secret(pdf_path, key="any")
        assert False, "Expected SecretNotFoundError for unwatermarked PDF"
    except SecretNotFoundError:
        pass  # Expected


def test_empty_secret_raises_with_message(sample_pdf):
    """Test that ValueError has proper error message"""
    from base64_invisible_comment import Base64InvisibleComment

    method = Base64InvisibleComment()

    with pytest.raises(ValueError) as exc_info:
        method.add_watermark(sample_pdf, "", "test-key")

    # Error message must not be None
    assert exc_info.value is not None
    error_message = str(exc_info.value)
    assert error_message is not None
    assert len(error_message) > 0
    assert "secret" in error_message.lower()
    assert "empty" in error_message.lower()


def test_none_secret_error_handling(sample_pdf):
    """Test proper error when secret is None"""
    from base64_invisible_comment import Base64InvisibleComment

    method = Base64InvisibleComment()

    with pytest.raises((ValueError, TypeError)) as exc_info:
        method.add_watermark(sample_pdf, None, "test-key")

    assert exc_info.value is not None
    error_str = str(exc_info.value)
    assert error_str  # Not empty or None




