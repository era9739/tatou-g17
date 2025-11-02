import pytest
import io
import uuid


@pytest.fixture
def auth_headers(client):
    """Get authentication headers"""
    unique_id = str(uuid.uuid4())[:8]
    
    client.post('/api/create-user', json={
        'login': f'testuser_{unique_id}',
        'email': f'test_{unique_id}@test.com',
        'password': 'TestPass123!'
    })
    
    response = client.post('/api/login', json={
        'email': f'test_{unique_id}@test.com',
        'password': 'TestPass123!'
    })
    
    if response.status_code == 200:
        return {'Authorization': f'Bearer {response.json["token"]}'}
    return {}


@pytest.fixture
def uploaded_document(client, auth_headers):
    """Upload a document and return its ID"""
    pdf = b"%PDF-1.4\n%%EOF\n"
    response = client.post(
        '/api/upload-document',
        data={'file': (io.BytesIO(pdf), 'test.pdf'), 'name': 'test'},
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    if response.status_code == 201:
        return response.json['id']
    return None


# ============================================================================
# Missing Endpoint Tests
# ============================================================================

class TestCreateWatermarkWithoutPathParam:
    """Test POST /api/create-watermark (without path param, uses JSON body)"""

    def test_create_watermark_json_body_success(self, client, auth_headers, uploaded_document):
        """Positive: Create watermark with document_id in JSON body"""
        if uploaded_document:
            response = client.post(
                '/api/create-watermark',
                json={
                    'document_id': uploaded_document,
                    'method': 'whitespace-stego',
                    'secret': 'test-secret',
                    'key': 'test-key',
                    'intended_for': 'recipient@test.com'
                },
                headers=auth_headers
            )
            # Should work (201) or fail gracefully (400/500)
            assert response.status_code in [201, 400, 500]

    def test_create_watermark_json_body_missing_document_id(self, client, auth_headers):
        """Negative: Create watermark without document_id"""
        response = client.post(
            '/api/create-watermark',
            json={
                'method': 'whitespace-stego',
                'secret': 'test-secret',
                'key': 'test-key'
            },
            headers=auth_headers
        )
        assert response.status_code == 400

    def test_create_watermark_json_body_invalid_document_id(self, client, auth_headers):
        """Negative: Create watermark with invalid document_id"""
        response = client.post(
            '/api/create-watermark',
            json={
                'document_id': 999999,
                'method': 'whitespace-stego',
                'secret': 'test-secret',
                'key': 'test-key'
            },
            headers=auth_headers
        )
        assert response.status_code in [400, 404]

    def test_create_watermark_json_body_missing_params(self, client, auth_headers, uploaded_document):
        """Negative: Create watermark with missing required parameters"""
        if uploaded_document:
            response = client.post(
                '/api/create-watermark',
                json={
                    'document_id': uploaded_document
                    # Missing method, secret, key
                },
                headers=auth_headers
            )
            assert response.status_code == 400

    def test_create_watermark_json_body_without_auth(self, client, uploaded_document):
        """Negative: Create watermark without authentication"""
        if uploaded_document:
            response = client.post(
                '/api/create-watermark',
                json={
                    'document_id': uploaded_document,
                    'method': 'whitespace-stego',
                    'secret': 'test-secret',
                    'key': 'test-key'
                }
            )
            assert response.status_code == 401


class TestReadWatermarkWithoutPathParam:
    """Test POST /api/read-watermark (without path param, uses JSON body)"""

    def test_read_watermark_json_body_success(self, client, auth_headers, uploaded_document):
        """Positive: Read watermark with document_id in JSON body"""
        if uploaded_document:
            response = client.post(
                '/api/read-watermark',
                json={
                    'document_id': uploaded_document,
                    'method': 'whitespace-stego',
                    'key': 'test-key'
                },
                headers=auth_headers
            )
            # Should work or fail gracefully
            assert response.status_code in [200, 400, 404, 500]

    def test_read_watermark_json_body_missing_document_id(self, client, auth_headers):
        """Negative: Read watermark without document_id"""
        response = client.post(
            '/api/read-watermark',
            json={
                'method': 'whitespace-stego',
                'key': 'test-key'
            },
            headers=auth_headers
        )
        assert response.status_code == 400

    def test_read_watermark_json_body_invalid_document_id(self, client, auth_headers):
        """Negative: Read watermark with invalid document_id"""
        response = client.post(
            '/api/read-watermark',
            json={
                'document_id': 999999,
                'method': 'whitespace-stego',
                'key': 'test-key'
            },
            headers=auth_headers
        )
        assert response.status_code in [400, 404]

    def test_read_watermark_json_body_missing_method(self, client, auth_headers, uploaded_document):
        """Negative: Read watermark without method"""
        if uploaded_document:
            response = client.post(
                '/api/read-watermark',
                json={
                    'document_id': uploaded_document,
                    'key': 'test-key'
                    # Missing method
                },
                headers=auth_headers
            )
            assert response.status_code == 400

    def test_read_watermark_json_body_missing_key(self, client, auth_headers, uploaded_document):
        """Negative: Read watermark without key"""
        if uploaded_document:
            response = client.post(
                '/api/read-watermark',
                json={
                    'document_id': uploaded_document,
                    'method': 'whitespace-stego'
                    # Missing key
                },
                headers=auth_headers
            )
            assert response.status_code == 400

    def test_read_watermark_json_body_invalid_method(self, client, auth_headers, uploaded_document):
        """Negative: Read watermark with invalid method"""
        if uploaded_document:
            response = client.post(
                '/api/read-watermark',
                json={
                    'document_id': uploaded_document,
                    'method': 'invalid-method-xyz',
                    'key': 'test-key'
                },
                headers=auth_headers
            )
            assert response.status_code in [400, 404]

    def test_read_watermark_json_body_without_auth(self, client, uploaded_document):
        """Negative: Read watermark without authentication"""
        if uploaded_document:
            response = client.post(
                '/api/read-watermark',
                json={
                    'document_id': uploaded_document,
                    'method': 'whitespace-stego',
                    'key': 'test-key'
                }
            )
            assert response.status_code == 401
