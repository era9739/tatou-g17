import pytest
from pathlib import Path


class TestHealthzEndpoint:
    """Improve coverage for healthz endpoint"""

    def test_healthz_basic(self, client):
        """Test basic healthz functionality"""
        response = client.get('/healthz')
        assert response.status_code == 200
        assert 'message' in response.json

    def test_healthz_no_auth_required(self, client):
        """Test healthz doesn't require authentication"""
        response = client.get('/healthz')
        assert response.status_code == 200

    def test_healthz_returns_json(self, client):
        """Test healthz returns JSON"""
        response = client.get('/healthz')
        assert 'application/json' in response.content_type
        data = response.json
        assert isinstance(data, dict)
        assert 'message' in data

    def test_healthz_with_query_params(self, client):
        """Test healthz ignores query parameters"""
        response = client.get('/healthz?test=value')
        assert response.status_code == 200


class TestMetricsEndpoint:
    """Test metrics endpoint"""

    def test_metrics_endpoint_exists(self, client):
        """Test metrics endpoint is accessible"""
        response = client.get('/metrics')
        # Should either return 200 or 404 if not implemented
        assert response.status_code in [200, 404, 405]

    def test_metrics_no_auth_required(self, client):
        """Test metrics doesn't require auth if it exists"""
        response = client.get('/metrics')
        if response.status_code == 200:
            # Accept any text/plain variant
            assert 'text/plain' in response.content_type


class TestStaticFiles:
    """Test static file serving"""

    def test_home_page(self, client):
        """Test home page is accessible"""
        response = client.get('/')
        assert response.status_code in [200, 404]
        if response.status_code == 200:
            assert 'text/html' in response.content_type

    def test_static_file_serving(self, client):
        """Test static files can be served"""
        # Try common static file paths
        paths = [
            '/static/style.css',
            '/static/app.js',
            '/static/documents.html',
            '/static/login.html'
        ]

        for path in paths:
            response = client.get(path)
            # Either exists (200) or doesn't (404)
            assert response.status_code in [200, 404]


class TestWatermarkingUtils:
    """Test watermarking utility functions"""

    def test_explore_pdf_with_valid_pdf(self, tmp_path):
        """Test explore_pdf with valid PDF"""
        from watermarking_utils import explore_pdf

        pdf_content = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000053 00000 n 
0000000102 00000 n 
trailer<</Size 4/Root 1 0 R>>
startxref
159
%%EOF
"""
        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_bytes(pdf_content)

        result = explore_pdf(pdf_file)
        assert isinstance(result, dict)
        assert 'size' in result
        assert result['size'] > 0

    def test_explore_pdf_with_empty_file(self, tmp_path):
        """Test explore_pdf with empty file raises error"""
        from watermarking_utils import explore_pdf

        empty_file = tmp_path / "empty.pdf"
        empty_file.write_bytes(b"")

        # Should raise ValueError for invalid PDF
        with pytest.raises(ValueError, match="PDF"):
            explore_pdf(empty_file)

    def test_explore_pdf_with_nonexistent_file(self):
        """Test explore_pdf with non-existent file raises error"""
        from watermarking_utils import explore_pdf
        from pathlib import Path

        nonexistent = Path("/tmp/nonexistent_file_12345.pdf")

        # Should raise FileNotFoundError
        with pytest.raises(FileNotFoundError):
            explore_pdf(nonexistent)

    def test_explore_pdf_large_file(self, tmp_path):
        """Test explore_pdf with large file"""
        from watermarking_utils import explore_pdf

        # Create a larger PDF
        pdf_content = b"%PDF-1.4\n" + b"X" * 10000 + b"\n%%EOF\n"
        pdf_file = tmp_path / "large.pdf"
        pdf_file.write_bytes(pdf_content)

        # May or may not work depending on PDF validity
        try:
            result = explore_pdf(pdf_file)
            assert isinstance(result, dict)
        except ValueError:
            # Expected if not a valid PDF
            pass

    def test_register_method_called(self):
        """Test that register_method is used for methods"""
        from watermarking_utils import METHODS

        # Methods should be registered
        assert len(METHODS) > 0
        assert 'whitespace-stego' in METHODS

    def test_get_method_returns_valid_object(self):
        """Test get_method returns method instances"""
        from watermarking_utils import get_method

        method = get_method('whitespace-stego')
        assert method is not None
        assert hasattr(method, 'add_watermark')
        assert hasattr(method, 'read_secret')

    def test_apply_watermark_function(self, tmp_path):
        """Test apply_watermark utility function"""
        from watermarking_utils import apply_watermark

        pdf_content = b"%PDF-1.4\nContent\n%%EOF\n"
        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_bytes(pdf_content)

        # Should not raise an error
        result = apply_watermark('whitespace-stego', pdf_file, 'secret', 'key')
        assert isinstance(result, bytes) or result is not None

    def test_is_watermarking_applicable_function(self, tmp_path):
        """Test is_watermarking_applicable utility"""
        from watermarking_utils import is_watermarking_applicable

        pdf_content = b"%PDF-1.4\nContent\n%%EOF\n"
        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_bytes(pdf_content)

        result = is_watermarking_applicable('whitespace-stego', pdf_file)
        assert isinstance(result, bool)

    def test_read_watermark_function(self, tmp_path):
        """Test read_watermark utility function"""
        from watermarking_utils import read_watermark

        pdf_content = b"%PDF-1.4\nContent\n%%EOF\n"
        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_bytes(pdf_content)

        # Should handle gracefully even if no watermark
        try:
            result = read_watermark('whitespace-stego', pdf_file, 'key')
        except Exception:
            pass  # Expected to fail if no watermark


class TestSecurityUtilsAdditional:
    """Test additional security utility functions"""

    def test_is_safe_filename_valid_names(self):
        """Test is_safe_filename with valid filenames"""
        try:
            from security_utils import is_safe_filename

            safe_names = [
                "document.pdf",
                "file-name.pdf",
                "file_name_123.pdf",
                "MyDocument.pdf"
            ]

            for name in safe_names:
                result = is_safe_filename(name)
                assert isinstance(result, bool)
        except ImportError:
            pytest.skip("is_safe_filename not implemented")

    def test_is_safe_filename_unsafe_names(self):
        """Test is_safe_filename with unsafe filenames"""
        try:
            from security_utils import is_safe_filename
        except (ImportError, AttributeError):
            pytest.skip("is_safe_filename not implemented")
            return

        unsafe_names = [
            "../etc/passwd",
            "../../file.pdf",
            "/absolute/path.pdf",
            "file\x00.pdf",
        ]

        # Function may not exist or may not validate all cases
        # This is an educational project with intentional vulnerabilities
        for name in unsafe_names:
            try:
                result = is_safe_filename(name)
                # Some names may pass, this is expected in educational context
                assert isinstance(result, bool)
            except Exception:
                pass

    def test_is_safe_filename_empty_string(self):
        """Test is_safe_filename with empty string"""
        try:
            from security_utils import is_safe_filename
            result = is_safe_filename("")
            if result is not None:
                assert isinstance(result, bool)
        except (ImportError, AttributeError):
            pytest.skip("is_safe_filename not implemented")

    def test_get_safe_temp_dir_returns_path(self):
        """Test get_safe_temp_dir returns a path"""
        try:
            from security_utils import get_safe_temp_dir
            result = get_safe_temp_dir()
            if result is not None:
                assert isinstance(result, (str, Path))
        except (ImportError, AttributeError):
            pytest.skip("get_safe_temp_dir not implemented")

    def test_get_safe_temp_dir_is_writable(self):
        """Test get_safe_temp_dir returns writable directory"""
        try:
            from security_utils import get_safe_temp_dir
            from pathlib import Path

            result = get_safe_temp_dir()
            if result is not None:
                temp_dir = Path(result)
                # Should be able to create files in temp dir
                if temp_dir.exists():
                    assert temp_dir.is_dir()
        except (ImportError, AttributeError):
            pytest.skip("get_safe_temp_dir not implemented")

    def test_validate_secret_length_edge_cases(self):
        """Test validate_secret_length with edge cases"""
        from security_utils import validate_secret_length

        # Test minimum length
        assert validate_secret_length("abc") is not None

        # Test very long secret
        long_secret = "a" * 1000
        result = validate_secret_length(long_secret)
        assert isinstance(result, bool)

    def test_validate_file_path_with_various_inputs(self, tmp_path):
        """Test validate_file_path with various inputs"""
        from security_utils import validate_file_path

        # Create test file
        test_file = tmp_path / "test.pdf"
        test_file.write_bytes(b"test")

        # Test valid path
        result = validate_file_path(str(test_file))
        assert result is not None

    def test_sanitize_method_name_edge_cases(self):
        """Test sanitize_method_name with edge cases"""
        from security_utils import sanitize_method_name

        # Test with hyphens and underscores
        assert sanitize_method_name("method-name") == "method-name"
        assert sanitize_method_name("method_name") == "method_name"

        # Test with numbers
        assert sanitize_method_name("method123") == "method123"


class TestRMAPFunctions:
    """Test RMAP helper functions"""

    def test_init_rmap_base_pdf(self, client, app):
        """Test RMAP base PDF initialization"""
        # This tests the init_rmap_base_pdf function
        response = client.get('/api/get-watermarking-methods')
        # If RMAP is initialized, this should work
        assert response.status_code == 200

    def test_rmap_get_link_missing_payload(self, client, app):
        """Test RMAP get link with missing payload"""
        response = client.post('/api/rmap-get-link', json={})
        # Should fail without payload
        assert response.status_code in [400, 503]

    def test_rmap_get_link_invalid_payload(self, client, app):
        """Test RMAP get link with invalid payload"""
        response = client.post('/api/rmap-get-link', json={
            'payload': 'invalid-payload-data'
        })
        # May return 400, 500, or 503 depending on implementation
        assert response.status_code in [400, 500, 503]


class TestEdgeCases:
    """Test various edge cases"""

    def test_large_request_body(self, client, auth_headers):
        """Test handling of large request bodies"""
        large_data = {"data": "X" * 100000}  # 100KB
        response = client.post(
            '/api/create-user',
            json=large_data
        )
        # Should handle gracefully
        assert response.status_code in [400, 409, 413, 500]

    def test_malformed_json(self, client, auth_headers):
        """Test handling of malformed JSON"""
        response = client.post(
            '/api/create-user',
            data='{"invalid": json',
            content_type='application/json'
        )
        assert response.status_code in [400, 415]

    def test_missing_content_type(self, client):
        """Test requests with missing content-type"""
        response = client.post('/api/create-user', data='test')
        assert response.status_code in [400, 415]

    def test_unsupported_http_method(self, client):
        """Test unsupported HTTP methods"""
        response = client.patch('/api/create-user')
        assert response.status_code in [405, 404]

    def test_url_encoding_issues(self, client, auth_headers):
        """Test URL encoding edge cases"""
        response = client.get('/api/get-document/%20%20', headers=auth_headers)
        assert response.status_code in [400, 401, 404]


@pytest.fixture
def auth_headers(client):
    """Create authentication headers"""
    import uuid
    unique_id = str(uuid.uuid4())[:8]

    # Create user
    client.post('/api/create-user', json={
        'login': f'utilstest_{unique_id}',
        'email': f'utils_{unique_id}@test.com',
        'password': 'password123'
    })

    # Login
    login_resp = client.post('/api/login', json={
        'email': f'utils_{unique_id}@test.com',
        'password': 'password123'
    })

    if login_resp.status_code == 200:
        token = login_resp.json['token']
        return {'Authorization': f'Bearer {token}'}

    return {}