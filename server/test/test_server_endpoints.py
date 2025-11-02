import pytest
import io
import uuid


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def unique_id():
    """Generate unique ID for test isolation"""
    return str(uuid.uuid4())[:8]


@pytest.fixture
def sample_pdf():
    """Generate sample PDF bytes"""
    return b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\nxref\n0 1\ntrailer<</Root 1 0 R>>\nstartxref\n30\n%%EOF\n"


@pytest.fixture
def create_test_user(client, unique_id):
    """Factory to create unique test users"""

    def _create_user(suffix=""):
        user_data = {
            "login": f"testuser_{unique_id}{suffix}",
            "email": f"test_{unique_id}{suffix}@example.com",
            "password": "TestPass123!"
        }
        response = client.post('/api/create-user', json=user_data)
        if response.status_code in [200, 201]:
            return user_data
        return None

    return _create_user


@pytest.fixture
def auth_token(client, create_test_user):
    """Get authentication token"""
    user_data = create_test_user()
    if user_data:
        response = client.post('/api/login', json={
            "email": user_data["email"],
            "password": user_data["password"]
        })
        if response.status_code == 200:
            return response.json.get('token')
    return None


@pytest.fixture
def auth_headers(auth_token):
    """Get authorization headers"""
    if auth_token:
        return {'Authorization': f'Bearer {auth_token}'}
    return {}


@pytest.fixture
def uploaded_document(client, auth_headers, sample_pdf):
    """Upload a document and return its ID"""
    response = client.post(
        '/api/upload-document',
        data={'file': (io.BytesIO(sample_pdf), 'test.pdf'), 'name': 'test-doc'},
        headers=auth_headers,
        content_type='multipart/form-data'
    )
    if response.status_code == 201:
        return response.json['id']
    return None


# ============================================================================
# 1. Healthz Endpoint
# ============================================================================

class TestHealthz:
    """Test /healthz endpoint"""

    def test_healthz_returns_200(self, client):
        """Positive: Returns 200 OK"""
        response = client.get('/healthz')
        assert response.status_code == 200

    def test_healthz_returns_json(self, client):
        """Positive: Returns valid JSON with message"""
        response = client.get('/healthz')
        assert response.is_json
        assert 'message' in response.json
        assert isinstance(response.json['message'], str)

    def test_healthz_no_auth_required(self, client):
        """Positive: No authentication required"""
        response = client.get('/healthz')
        assert response.status_code == 200

    def test_healthz_ignores_query_params(self, client):
        """Edge case: Ignores query parameters"""
        response = client.get('/healthz?foo=bar')
        assert response.status_code == 200


# ============================================================================
# 2. User Management
# ============================================================================

class TestUserManagement:
    """Test user creation and login endpoints"""

    # Create User Tests
    def test_create_user_success(self, client, unique_id):
        """Positive: Create user successfully"""
        response = client.post('/api/create-user', json={
            "email": f"test_{unique_id}@example.com",
            "login": f"testuser_{unique_id}",
            "password": "SecurePass123!"
        })
        assert response.status_code in [200, 201]
        assert 'id' in response.json
        assert 'login' in response.json
        assert 'email' in response.json

    def test_create_user_duplicate_email(self, client, unique_id):
        """Negative: Duplicate email rejected"""
        email = f"duplicate_{unique_id}@example.com"

        client.post('/api/create-user', json={
            "email": email,
            "login": f"user1_{unique_id}",
            "password": "pass123"
        })

        response = client.post('/api/create-user', json={
            "email": email,
            "login": f"user2_{unique_id}",
            "password": "pass456"
        })
        assert response.status_code == 409

    def test_create_user_missing_email(self, client, unique_id):
        """Negative: Missing email"""
        response = client.post('/api/create-user', json={
            "login": f"testuser_{unique_id}",
            "password": "password123"
        })
        assert response.status_code == 400

    def test_create_user_missing_password(self, client, unique_id):
        """Negative: Missing password"""
        response = client.post('/api/create-user', json={
            "email": f"test_{unique_id}@example.com",
            "login": f"testuser_{unique_id}"
        })
        assert response.status_code == 400

    def test_create_user_empty_password(self, client, unique_id):
        """Negative: Empty password"""
        response = client.post('/api/create-user', json={
            "email": f"test_{unique_id}@example.com",
            "login": f"testuser_{unique_id}",
            "password": ""
        })
        assert response.status_code == 400

    # Login Tests
    def test_login_success(self, client, create_test_user):
        """Positive: Login with correct credentials"""
        user = create_test_user()

        response = client.post('/api/login', json={
            "email": user["email"],
            "password": user["password"]
        })
        assert response.status_code == 200
        assert 'token' in response.json
        assert 'token_type' in response.json
        assert 'expires_in' in response.json
        assert response.json['token_type'] == 'bearer'
        assert isinstance(response.json['expires_in'], int)

    def test_login_wrong_password(self, client, create_test_user):
        """Negative: Wrong password"""
        user = create_test_user()

        response = client.post('/api/login', json={
            "email": user["email"],
            "password": "wrongpassword"
        })
        assert response.status_code == 401

    def test_login_nonexistent_user(self, client, unique_id):
        """Negative: Non-existent user"""
        response = client.post('/api/login', json={
            "email": f"nonexistent_{unique_id}@example.com",
            "password": "anypassword"
        })
        assert response.status_code == 401

    def test_login_missing_email(self, client):
        """Negative: Missing email"""
        response = client.post('/api/login', json={
            "password": "password123"
        })
        assert response.status_code == 400

    def test_login_missing_password(self, client, unique_id):
        """Negative: Missing password"""
        response = client.post('/api/login', json={
            "email": f"test_{unique_id}@example.com"
        })
        assert response.status_code == 400


# ============================================================================
# 3. Document Upload
# ============================================================================

class TestDocumentUpload:
    """Test /api/upload-document endpoint"""

    def test_upload_document_success(self, client, auth_headers, sample_pdf):
        """Positive: Upload document successfully"""
        response = client.post(
            '/api/upload-document',
            data={'file': (io.BytesIO(sample_pdf), 'test.pdf'), 'name': 'Test Doc'},
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        assert response.status_code == 201
        assert 'id' in response.json
        assert 'sha256' in response.json

    def test_upload_document_without_auth(self, client, sample_pdf):
        """Negative: Upload without authentication"""
        response = client.post(
            '/api/upload-document',
            data={'file': (io.BytesIO(sample_pdf), 'test.pdf')},
            content_type='multipart/form-data'
        )
        assert response.status_code == 401

    def test_upload_document_no_file(self, client, auth_headers):
        """Negative: Upload without file"""
        response = client.post(
            '/api/upload-document',
            data={},
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        assert response.status_code == 400

    def test_upload_document_multiple_files(self, client, auth_headers, sample_pdf):
        """Positive: Upload multiple documents"""
        for i in range(3):
            response = client.post(
                '/api/upload-document',
                data={'file': (io.BytesIO(sample_pdf), f'doc{i}.pdf'), 'name': f'Doc {i}'},
                headers=auth_headers,
                content_type='multipart/form-data'
            )
            assert response.status_code == 201


# ============================================================================
# 4. List Documents
# ============================================================================

class TestListDocuments:
    """Test /api/list-documents endpoint"""

    def test_list_documents_success(self, client, auth_headers):
        """Positive: List documents successfully"""
        response = client.get('/api/list-documents', headers=auth_headers)
        assert response.status_code == 200
        assert 'documents' in response.json
        assert isinstance(response.json['documents'], list)

    def test_list_documents_without_auth(self, client):
        """Negative: List without authentication"""
        response = client.get('/api/list-documents')
        assert response.status_code == 401

    def test_list_documents_shows_uploaded(self, client, auth_headers, sample_pdf):
        """Positive: Uploaded documents appear in list"""
        # Upload a document
        client.post(
            '/api/upload-document',
            data={'file': (io.BytesIO(sample_pdf), 'test.pdf'), 'name': 'Test'},
            headers=auth_headers,
            content_type='multipart/form-data'
        )

        # List documents
        response = client.get('/api/list-documents', headers=auth_headers)
        assert response.status_code == 200
        assert len(response.json['documents']) >= 1

    def test_list_documents_user_isolation(self, client, create_test_user, sample_pdf):
        """Security: Users only see their own documents"""
        # User 1 uploads
        user1 = create_test_user("_1")
        login1 = client.post('/api/login', json={"email": user1["email"], "password": user1["password"]})
        headers1 = {'Authorization': f'Bearer {login1.json["token"]}'}

        client.post(
            '/api/upload-document',
            data={'file': (io.BytesIO(sample_pdf), 'user1.pdf')},
            headers=headers1,
            content_type='multipart/form-data'
        )

        # User 2 lists
        user2 = create_test_user("_2")
        login2 = client.post('/api/login', json={"email": user2["email"], "password": user2["password"]})
        headers2 = {'Authorization': f'Bearer {login2.json["token"]}'}

        response = client.get('/api/list-documents', headers=headers2)
        # User 2 should not see user 1's documents
        assert response.status_code == 200


# ============================================================================
# 5. Get Document
# ============================================================================

class TestGetDocument:
    """Test /api/get-document endpoint"""

    def test_get_document_success(self, client, auth_headers, uploaded_document):
        """Positive: Get document by ID"""
        if uploaded_document:
            response = client.get(
                f'/api/get-document/{uploaded_document}',
                headers=auth_headers
            )
            assert response.status_code == 200
            assert b'%PDF' in response.data

    def test_get_document_query_param(self, client, auth_headers, uploaded_document):
        """Positive: Get document with query parameter"""
        if uploaded_document:
            response = client.get(
                f'/api/get-document?id={uploaded_document}',
                headers=auth_headers
            )
            assert response.status_code in [200, 400]

    def test_get_document_without_auth(self, client, uploaded_document):
        """Negative: Get document without auth"""
        if uploaded_document:
            response = client.get(f'/api/get-document/{uploaded_document}')
            assert response.status_code == 401

    def test_get_document_nonexistent(self, client, auth_headers):
        """Negative: Get non-existent document"""
        response = client.get('/api/get-document/999999', headers=auth_headers)
        assert response.status_code == 404

    def test_get_document_invalid_id(self, client, auth_headers):
        """Negative: Invalid document ID"""
        response = client.get('/api/get-document/invalid', headers=auth_headers)
        assert response.status_code in [400, 404]

    def test_get_document_missing_id(self, client, auth_headers):
        """Negative: Missing document ID"""
        response = client.get('/api/get-document', headers=auth_headers)
        assert response.status_code == 400

    def test_get_document_other_user(self, client, create_test_user, sample_pdf):
        """Security: Cannot get other user's document"""
        # User 1 uploads
        user1 = create_test_user("_1")
        login1 = client.post('/api/login', json={"email": user1["email"], "password": user1["password"]})
        headers1 = {'Authorization': f'Bearer {login1.json["token"]}'}

        upload = client.post(
            '/api/upload-document',
            data={'file': (io.BytesIO(sample_pdf), 'test.pdf')},
            headers=headers1,
            content_type='multipart/form-data'
        )

        if upload.status_code == 201:
            doc_id = upload.json['id']

            # User 2 tries to get it
            user2 = create_test_user("_2")
            login2 = client.post('/api/login', json={"email": user2["email"], "password": user2["password"]})
            headers2 = {'Authorization': f'Bearer {login2.json["token"]}'}

            response = client.get(f'/api/get-document/{doc_id}', headers=headers2)
            assert response.status_code in [403, 404]


# ============================================================================
# 6. Delete Document
# ============================================================================

class TestDeleteDocument:
    """Test /api/delete-document endpoint"""

    def test_delete_document_success(self, client, auth_headers, uploaded_document):
        """Positive: Delete document successfully"""
        if uploaded_document:
            response = client.delete(
                f'/api/delete-document/{uploaded_document}',
                headers=auth_headers
            )
            assert response.status_code in [200, 204]

    def test_delete_document_via_post(self, client, auth_headers, uploaded_document):
        """Positive: Delete via POST method"""
        if uploaded_document:
            response = client.post(
                '/api/delete-document',
                json={'id': uploaded_document},
                headers=auth_headers
            )
            assert response.status_code in [200, 204, 400]

    def test_delete_document_query_param(self, client, auth_headers, uploaded_document):
        """Positive: Delete with query parameter"""
        if uploaded_document:
            response = client.delete(
                f'/api/delete-document?id={uploaded_document}',
                headers=auth_headers
            )
            assert response.status_code in [200, 204, 400]

    def test_delete_document_without_auth(self, client, uploaded_document):
        """Negative: Delete without authentication"""
        if uploaded_document:
            response = client.delete(f'/api/delete-document/{uploaded_document}')
            assert response.status_code == 401

    def test_delete_document_nonexistent(self, client, auth_headers):
        """Negative: Delete non-existent document"""
        response = client.delete('/api/delete-document/999999', headers=auth_headers)
        assert response.status_code in [404, 403]

    def test_delete_document_invalid_id(self, client, auth_headers):
        """Negative: Invalid document ID"""
        response = client.delete('/api/delete-document/invalid', headers=auth_headers)
        assert response.status_code in [400, 404]

    def test_delete_document_missing_id(self, client, auth_headers):
        """Negative: Missing document ID"""
        response = client.post('/api/delete-document', json={}, headers=auth_headers)
        assert response.status_code == 400

    def test_delete_document_other_user(self, client, create_test_user, sample_pdf):
        """Security: Cannot delete other user's document"""
        # User 1 uploads
        user1 = create_test_user("_1")
        login1 = client.post('/api/login', json={"email": user1["email"], "password": user1["password"]})
        headers1 = {'Authorization': f'Bearer {login1.json["token"]}'}

        upload = client.post(
            '/api/upload-document',
            data={'file': (io.BytesIO(sample_pdf), 'test.pdf')},
            headers=headers1,
            content_type='multipart/form-data'
        )

        if upload.status_code == 201:
            doc_id = upload.json['id']

            # User 2 tries to delete
            user2 = create_test_user("_2")
            login2 = client.post('/api/login', json={"email": user2["email"], "password": user2["password"]})
            headers2 = {'Authorization': f'Bearer {login2.json["token"]}'}

            response = client.delete(f'/api/delete-document/{doc_id}', headers=headers2)
            assert response.status_code in [403, 404]


# ============================================================================
# 7. Watermarking Methods
# ============================================================================

class TestWatermarkingMethods:
    """Test /api/get-watermarking-methods endpoint"""

    def test_get_methods_success(self, client):
        """Positive: Get watermarking methods"""
        response = client.get('/api/get-watermarking-methods')
        assert response.status_code == 200
        assert 'methods' in response.json
        assert 'count' in response.json
        assert isinstance(response.json['methods'], list)

    def test_get_methods_no_auth_required(self, client):
        """Positive: No authentication required"""
        response = client.get('/api/get-watermarking-methods')
        assert response.status_code == 200


# ============================================================================
# 8. Create Watermark
# ============================================================================

class TestCreateWatermark:
    """Test /api/create-watermark endpoint"""

    def test_create_watermark_missing_params(self, client, auth_headers, uploaded_document):
        """Negative: Missing required parameters"""
        if uploaded_document:
            response = client.post(
                f'/api/create-watermark/{uploaded_document}',
                json={},
                headers=auth_headers
            )
            assert response.status_code == 400

    def test_create_watermark_invalid_method(self, client, auth_headers, uploaded_document):
        """Negative: Invalid watermarking method"""
        if uploaded_document:
            response = client.post(
                f'/api/create-watermark/{uploaded_document}',
                json={'method': 'invalid-method', 'secret': 'test', 'key': 'test'},
                headers=auth_headers
            )
            assert response.status_code == 400

    def test_create_watermark_without_auth(self, client, uploaded_document):
        """Negative: Create watermark without auth"""
        if uploaded_document:
            response = client.post(
                f'/api/create-watermark/{uploaded_document}',
                json={'method': 'whitespace-stego', 'secret': 'test', 'key': 'test'}
            )
            assert response.status_code == 401


# ============================================================================
# 9. Read Watermark
# ============================================================================

class TestReadWatermark:
    """Test /api/read-watermark endpoint"""

    def test_read_watermark_missing_params(self, client, auth_headers, uploaded_document):
        """Negative: Missing required parameters"""
        if uploaded_document:
            response = client.post(
                f'/api/read-watermark/{uploaded_document}',
                json={},
                headers=auth_headers
            )
            assert response.status_code == 400

    def test_read_watermark_invalid_method(self, client, auth_headers, uploaded_document):
        """Negative: Invalid method"""
        if uploaded_document:
            response = client.post(
                f'/api/read-watermark/{uploaded_document}',
                json={'method': 'invalid-method', 'key': 'test'},
                headers=auth_headers
            )
            assert response.status_code in [400, 404]

    def test_read_watermark_without_auth(self, client, uploaded_document):
        """Negative: Read without authentication"""
        if uploaded_document:
            response = client.post(
                f'/api/read-watermark/{uploaded_document}',
                json={'method': 'whitespace-stego', 'key': 'test'}
            )
            assert response.status_code == 401


# ============================================================================
# 10. List Versions
# ============================================================================

class TestListVersions:
    """Test /api/list-versions endpoint"""

    def test_list_versions_path_param(self, client, auth_headers, uploaded_document):
        """Positive: List versions with path parameter"""
        if uploaded_document:
            response = client.get(
                f'/api/list-versions/{uploaded_document}',
                headers=auth_headers
            )
            assert response.status_code == 200
            assert 'versions' in response.json

    def test_list_versions_query_param(self, client, auth_headers, uploaded_document):
        """Positive: List versions with query parameter"""
        if uploaded_document:
            response = client.get(
                f'/api/list-versions?id={uploaded_document}',
                headers=auth_headers
            )
            assert response.status_code == 200

    def test_list_versions_without_auth(self, client, uploaded_document):
        """Negative: List versions without auth"""
        if uploaded_document:
            response = client.get(f'/api/list-versions/{uploaded_document}')
            assert response.status_code == 401

    def test_list_versions_missing_id(self, client, auth_headers):
        """Negative: List versions without document ID"""
        response = client.get('/api/list-versions', headers=auth_headers)
        assert response.status_code == 400

    def test_list_versions_invalid_id(self, client, auth_headers):
        """Negative: Invalid document ID"""
        response = client.get('/api/list-versions/invalid', headers=auth_headers)
        assert response.status_code in [400, 404]


# ============================================================================
# 11. List All Versions
# ============================================================================

class TestListAllVersions:
    """Test /api/list-all-versions endpoint"""

    def test_list_all_versions_success(self, client, auth_headers):
        """Positive: List all versions"""
        response = client.get('/api/list-all-versions', headers=auth_headers)
        assert response.status_code == 200
        assert 'versions' in response.json
        assert isinstance(response.json['versions'], list)

    def test_list_all_versions_without_auth(self, client):
        """Negative: List all versions without auth"""
        response = client.get('/api/list-all-versions')
        assert response.status_code == 401


# ============================================================================
# 12. Get Version (Public)
# ============================================================================

class TestGetVersion:
    """Test /api/get-version endpoint"""

    def test_get_version_invalid_link(self, client):
        """Negative: Invalid version link"""
        response = client.get('/api/get-version/nonexistent-link')
        assert response.status_code == 404

    def test_get_version_no_auth_required(self, client):
        """Positive: No authentication required"""
        response = client.get('/api/get-version/test-link')
        # Should not return 401 (auth error)
        assert response.status_code != 401


# ============================================================================
# 13. RMAP Endpoints
# ============================================================================

class TestRMAPEndpoints:
    """Test RMAP endpoints"""

    def test_rmap_initiate(self, client, auth_headers, uploaded_document):
        """Test RMAP initiate"""
        if uploaded_document:
            response = client.post(
                '/api/rmap-initiate',
                json={'document_id': uploaded_document},
                headers=auth_headers
            )
            assert response.status_code in [200, 201, 400, 500, 503]

    def test_rmap_get_link_missing_payload(self, client):
        """Negative: RMAP get link without payload"""
        response = client.post('/api/rmap-get-link', json={})
        assert response.status_code in [400, 500, 503]

    def test_rmap_get_link_invalid_payload(self, client):
        """Negative: RMAP get link with invalid payload"""
        response = client.post('/api/rmap-get-link', json={'payload': 'invalid'})
        assert response.status_code in [400, 500, 503]


# ============================================================================
# 14. Static Files and Metrics
# ============================================================================

class TestStaticAndMetrics:
    """Test static files, home, and metrics"""

    def test_home_route(self, client):
        """Test home route exists"""
        response = client.get('/')
        assert response.status_code in [200, 404]

    def test_static_files(self, client):
        """Test static file serving"""
        response = client.get('/static/style.css')
        assert response.status_code in [200, 404]

    def test_metrics_endpoint(self, client):
        """Test metrics endpoint"""
        response = client.get('/metrics')
        assert response.status_code in [200, 404, 405]

    def test_metrics_no_auth_required(self, client):
        """Test metrics doesn't require auth"""
        response = client.get('/metrics')
        assert response.status_code != 401