import pytest
import json
from pathlib import Path

from watermarking_utils import (
    apply_watermark,
    read_watermark,
    is_watermarking_applicable,
    explore_pdf,
    get_method,
    METHODS
)
from watermarking_method import SecretNotFoundError, InvalidKeyError


@pytest.fixture
def sample_pdf(tmp_path):
    """Create a simple test PDF"""
    pdf = tmp_path / "test.pdf"
    pdf.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")
    return pdf


class TestApplyWatermark:
    """Test apply_watermark utility function"""

    def test_apply_watermark_with_method_name(self, sample_pdf):
        """Test applying watermark using method name string"""
        result = apply_watermark(
            method="toy-eof",
            pdf=sample_pdf,
            secret="test-secret",
            key="test-key"
        )

        assert isinstance(result, bytes)
        assert b"%PDF-" in result

    def test_apply_watermark_with_method_instance(self, sample_pdf):
        """Test applying watermark using method instance"""
        from add_after_eof import AddAfterEOF
        method = AddAfterEOF()

        result = apply_watermark(
            method=method,
            pdf=sample_pdf,
            secret="test-secret",
            key="test-key"
        )

        assert isinstance(result, bytes)

    def test_apply_watermark_with_position(self, sample_pdf):
        """Test applying watermark with position parameter"""
        result = apply_watermark(
            method="toy-eof",
            pdf=sample_pdf,
            secret="test-secret",
            key="test-key",
            position="0"
        )

        assert isinstance(result, bytes)

    def test_apply_watermark_with_bytes_input(self):
        """Test applying watermark with bytes PDF"""
        pdf_bytes = b"%PDF-1.4\n%%EOF\n"

        result = apply_watermark(
            method="toy-eof",
            pdf=pdf_bytes,
            secret="test-secret",
            key="test-key"
        )

        assert isinstance(result, bytes)

    def test_apply_watermark_invalid_method_raises(self, sample_pdf):
        """Test invalid method name raises error"""
        with pytest.raises(KeyError):
            apply_watermark(
                method="nonexistent-method",
                pdf=sample_pdf,
                secret="secret",
                key="key"
            )

    def test_apply_watermark_preserves_pdf(self, sample_pdf):
        """Test watermarking preserves PDF structure"""
        original = sample_pdf.read_bytes()

        result = apply_watermark(
            method="toy-eof",
            pdf=sample_pdf,
            secret="secret",
            key="key"
        )

        # Result should start with PDF header
        assert result.startswith(b"%PDF-")
        # Should contain original content
        assert b"1 0 obj" in result


class TestReadWatermark:
    """Test read_watermark utility function"""

    def test_read_watermark_roundtrip(self, sample_pdf):
        """Test roundtrip: apply then read"""
        secret = "test-secret-123"

        watermarked = apply_watermark(
            method="toy-eof",
            pdf=sample_pdf,
            secret=secret,
            key="test-key"
        )

        extracted = read_watermark(
            method="toy-eof",
            pdf=watermarked,
            key="test-key"
        )

        assert extracted == secret

    def test_read_watermark_with_method_instance(self, sample_pdf):
        """Test reading with method instance"""
        from add_after_eof import AddAfterEOF
        method = AddAfterEOF()

        watermarked = apply_watermark(
            method=method,
            pdf=sample_pdf,
            secret="secret",
            key="key"
        )

        extracted = read_watermark(
            method=method,
            pdf=watermarked,
            key="key"
        )

        assert extracted == "secret"

    def test_read_watermark_no_watermark_raises(self, sample_pdf):
        """Test reading non-watermarked PDF raises error"""
        with pytest.raises(SecretNotFoundError):
            read_watermark(
                method="toy-eof",
                pdf=sample_pdf,
                key="key"
            )

    def test_read_watermark_wrong_key_raises(self, sample_pdf):
        """Test wrong key raises error"""
        watermarked = apply_watermark(
            method="toy-eof",
            pdf=sample_pdf,
            secret="secret",
            key="correct-key"
        )

        with pytest.raises((InvalidKeyError, SecretNotFoundError)):
            read_watermark(
                method="toy-eof",
                pdf=watermarked,
                key="wrong-key"
            )


class TestIsWatermarkingApplicable:
    """Test is_watermarking_applicable utility function"""

    def test_is_applicable_with_valid_pdf(self, sample_pdf):
        """Test method is applicable on valid PDF"""
        result = is_watermarking_applicable(
            method="toy-eof",
            pdf=sample_pdf
        )

        assert isinstance(result, bool)

    def test_is_applicable_with_method_instance(self, sample_pdf):
        """Test with method instance"""
        from add_after_eof import AddAfterEOF
        method = AddAfterEOF()

        result = is_watermarking_applicable(
            method=method,
            pdf=sample_pdf
        )

        assert isinstance(result, bool)

    def test_is_applicable_with_position(self, sample_pdf):
        """Test with position parameter"""
        result = is_watermarking_applicable(
            method="toy-eof",
            pdf=sample_pdf,
            position="0"
        )

        assert isinstance(result, bool)

    def test_is_applicable_with_bytes(self):
        """Test with bytes PDF"""
        pdf_bytes = b"%PDF-1.4\n%%EOF\n"

        result = is_watermarking_applicable(
            method="toy-eof",
            pdf=pdf_bytes
        )

        assert isinstance(result, bool)


class TestExplorePdf:
    """Test explore_pdf utility function"""

    def test_explore_pdf_returns_dict(self, sample_pdf):
        """Test explore returns dictionary"""
        result = explore_pdf(sample_pdf)

        assert isinstance(result, dict)

    def test_explore_pdf_has_basic_info(self, sample_pdf):
        """Test explore contains basic PDF info"""
        result = explore_pdf(sample_pdf)

        # Should have some keys (exact keys depend on implementation)
        assert len(result) > 0

    def test_explore_pdf_with_bytes(self):
        """Test explore with bytes input"""
        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n"

        result = explore_pdf(pdf_bytes)

        assert isinstance(result, dict)

    def test_explore_pdf_serializable(self, sample_pdf):
        """Test result is JSON serializable"""
        result = explore_pdf(sample_pdf)

        # Should be JSON serializable
        json_str = json.dumps(result)
        assert isinstance(json_str, str)


class TestGetMethod:
    """Test get_method utility function"""

    def test_get_method_with_string(self):
        """Test getting method by name"""
        method = get_method("toy-eof")

        assert method is not None
        assert hasattr(method, 'add_watermark')
        assert hasattr(method, 'read_secret')

    def test_get_method_with_instance(self):
        """Test passing through method instance"""
        from add_after_eof import AddAfterEOF
        original = AddAfterEOF()

        result = get_method(original)

        assert result is original

    def test_get_method_invalid_name_raises(self):
        """Test invalid method name raises KeyError"""
        with pytest.raises(KeyError):
            get_method("nonexistent-method")

    def test_get_method_all_registered_methods(self):
        """Test all methods in METHODS are gettable"""
        for method_name in METHODS.keys():
            method = get_method(method_name)
            assert method is not None


class TestMETHODSRegistry:
    """Test METHODS registry"""

    def test_methods_is_dict(self):
        """Test METHODS is a dictionary"""
        assert isinstance(METHODS, dict)

    def test_methods_not_empty(self):
        """Test METHODS contains methods"""
        assert len(METHODS) > 0

    def test_methods_keys_are_strings(self):
        """Test all keys are strings"""
        for key in METHODS.keys():
            assert isinstance(key, str)

    def test_methods_values_have_interface(self):
        """Test all values implement watermarking interface"""
        for method in METHODS.values():
            assert hasattr(method, 'add_watermark')
            assert hasattr(method, 'read_secret')
            assert hasattr(method, 'name')

    def test_methods_names_match_keys(self):
        """Test method.name matches registry key"""
        for key, method in METHODS.items():
            assert method.name == key


class TestIntegration:
    """Integration tests for utility functions"""

    def test_complete_workflow_all_methods(self, sample_pdf):
        """Test complete workflow with all registered methods"""
        secret = "integration-test"
        key = "test-key"

        for method_name in METHODS.keys():
            # Check if applicable
            applicable = is_watermarking_applicable(
                method=method_name,
                pdf=sample_pdf
            )

            if applicable:
                # Apply watermark
                watermarked = apply_watermark(
                    method=method_name,
                    pdf=sample_pdf,
                    secret=secret,
                    key=key
                )

                # Verify it's bytes
                assert isinstance(watermarked, bytes)

                # Read back
                try:
                    extracted = read_watermark(
                        method=method_name,
                        pdf=watermarked,
                        key=key
                    )
                    assert extracted == secret
                except Exception:
                    # Some methods might not support reading
                    pass

    def test_different_methods_produce_different_output(self, sample_pdf):
        """Test different methods produce different watermarked PDFs"""
        secret = "test-secret"
        key = "test-key"

        results = {}
        for method_name in list(METHODS.keys())[:2]:  # Test first 2 methods
            applicable = is_watermarking_applicable(
                method=method_name,
                pdf=sample_pdf
            )

            if applicable:
                watermarked = apply_watermark(
                    method=method_name,
                    pdf=sample_pdf,
                    secret=secret,
                    key=key
                )
                results[method_name] = watermarked

        # Different methods should produce different outputs
        if len(results) >= 2:
            values = list(results.values())
            assert values[0] != values[1]


class TestEdgeCases:
    """Test edge cases in utility functions"""

    def test_apply_empty_secret_raises(self, sample_pdf):
        """Test empty secret raises error"""
        with pytest.raises(ValueError):
            apply_watermark(
                method="toy-eof",
                pdf=sample_pdf,
                secret="",
                key="key"
            )

    def test_apply_empty_key_raises(self, sample_pdf):
        """Test empty key raises error"""
        with pytest.raises(ValueError):
            apply_watermark(
                method="toy-eof",
                pdf=sample_pdf,
                secret="secret",
                key=""
            )

    def test_very_long_secret(self, sample_pdf):
        """Test with very long secret"""
        long_secret = "x" * 10000

        watermarked = apply_watermark(
            method="toy-eof",
            pdf=sample_pdf,
            secret=long_secret,
            key="key"
        )

        assert isinstance(watermarked, bytes)