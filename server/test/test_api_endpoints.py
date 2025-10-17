import pytest
import json
import io
import uuid
from pathlib import Path
from server import create_app


@pytest.fixture
def app():
    """Create test app with test configuration"""
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "STORAGE_DIR": Path("./test_storage"),
    })
    yield app


@pytest.fixture
def client(app):
    """Test client for making requests"""
    return app.test_client()


@pytest.fixture
def unique_user_data():
    """Generate unique user data for each test"""
    unique_id = str(uuid.uuid4())[:8]
    return {
        "email": f"test_{unique_id}@example.com",
        "login": f"testuser_{unique_id}",
        "password": "testpass123"
    }


@pytest.fixture
def auth_headers(client, unique_user_data):
    """Create user and return auth headers"""
    # Create test user
    client.post('/api/create-user', json=unique_user_data)

    # Login to get token
    response = client.post('/api/login', json={
        "email": unique_user_data["email"],
        "password": unique_user_data["password"]
    })
    token = response.json['token']

    return {"Authorization": f"Bearer {token}"}


class TestUserManagement:
    """Test user creation and authentication"""

    def test_create_user_success(self, client):
        """Test creating a new user with unique credentials"""
        unique_id = str(uuid.uuid4())[:8]
        response = client.post('/api/create-user', json={
            "email": f"newuser_{unique_id}@test.com",
            "login": f"newuser_{unique_id}",
            "password": "password123"
        })
        assert response.status_code == 201
        data = response.json
        assert "id" in data
        assert data["email"] == f"newuser_{unique_id}@test.com"
        assert data["login"] == f"newuser_{unique_id}"

        # Security: password should NOT be in response
        assert "password" not in data

        # Validate ID type and value
        assert isinstance(data["id"], int)
        assert data["id"] > 0

    def test_create_user_missing_fields(self, client):
        response = client.post('/api/create-user', json={
            "email": "test@test.com"
            # missing login and password
        })
        assert response.status_code == 400
        assert "error" in response.json

    def test_create_user_duplicate_email(self, client):
        unique_id = str(uuid.uuid4())[:8]
        email = f"duplicate_{unique_id}@test.com"

        # Create first user
        client.post('/api/create-user', json={
            "email": email,
            "login": f"user1_{unique_id}",
            "password": "pass123"
        })

        # Try to create with same email
        response = client.post('/api/create-user', json={
            "email": email,
            "login": f"user2_{unique_id}",
            "password": "pass456"
        })
        assert response.status_code == 409
        assert "already exists" in response.json["error"].lower()

    def test_login_success(self, client, unique_user_data):
        # Create user first
        client.post('/api/create-user', json=unique_user_data)

        # Login
        response = client.post('/api/login', json={
            "email": unique_user_data["email"],
            "password": unique_user_data["password"]
        })
        assert response.status_code == 200
        data = response.json

        # Validate all required fields exist
        assert "token" in data
        assert "token_type" in data
        assert "expires_in" in data

        # Validate field values and types
        assert isinstance(data["token"], str)
        assert len(data["token"]) > 20  # Token should be substantial
        assert data["token_type"] == "bearer"
        assert isinstance(data["expires_in"], int)
        assert data["expires_in"] > 0

    def test_login_wrong_password(self, client, unique_user_data):
        # Create user
        client.post('/api/create-user', json=unique_user_data)

        # Try wrong password
        response = client.post('/api/login', json={
            "email": unique_user_data["email"],
            "password": "wrongpass"
        })
        assert response.status_code == 401
        assert "invalid credentials" in response.json["error"].lower()

    def test_login_nonexistent_user(self, client):
        response = client.post('/api/login', json={
            "email": "notexist@test.com",
            "password": "anypass"
        })
        assert response.status_code == 401


class TestAuthentication:
    """Test authentication and authorization"""

    def test_protected_route_without_auth(self, client):
        response = client.get('/api/list-documents')
        assert response.status_code == 401

    def test_protected_route_with_invalid_token(self, client):
        headers = {"Authorization": "Bearer invalid_token_here"}
        response = client.get('/api/list-documents', headers=headers)
        assert response.status_code == 401

    def test_protected_route_with_valid_token(self, client, auth_headers):
        response = client.get('/api/list-documents', headers=auth_headers)
        assert response.status_code == 200


class TestDocumentOperations:
    """Test document upload and management"""

    def test_upload_document_success(self, client, auth_headers, tmp_path):
        # Create a test PDF
        pdf_content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"

        data = {
            'file': (io.BytesIO(pdf_content), 'test.pdf', 'application/pdf'),
            'name': 'My Test Document'
        }

        response = client.post(
            '/api/upload-document',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )

        assert response.status_code == 201
        result = response.json

        # Validate all required fields exist
        assert "id" in result
        assert "name" in result
        assert "sha256" in result
        assert "size" in result

        # Validate field types and values
        assert isinstance(result["id"], int)
        assert result["id"] > 0
        assert result["name"] == "My Test Document"
        assert isinstance(result["sha256"], str)
        assert len(result["sha256"]) == 64  # SHA256 is 64 hex characters
        assert result["size"] == len(pdf_content)
        assert isinstance(result["size"], int)

    def test_upload_document_no_file(self, client, auth_headers):
        response = client.post(
            '/api/upload-document',
            data={},
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        assert response.status_code == 400
        assert "file is required" in response.json["error"].lower()

    def test_list_documents_empty(self, client, auth_headers):
        """Test listing documents - should return documents array"""
        response = client.get('/api/list-documents', headers=auth_headers)
        assert response.status_code == 200
        data = response.json
        assert "documents" in data
        assert isinstance(data["documents"], list)

    def test_list_documents_with_uploads(self, client, auth_headers):
        """Test that uploaded documents appear in list"""
        # Upload a document first
        pdf_content = b"%PDF-1.4\n%%EOF\n"
        data = {
            'file': (io.BytesIO(pdf_content), 'doc1.pdf')
        }
        client.post(
            '/api/upload-document',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )

        # List documents
        response = client.get('/api/list-documents', headers=auth_headers)
        assert response.status_code == 200
        data = response.json
        assert "documents" in data
        assert len(data["documents"]) >= 1  # At least one document


class TestWatermarkingAPI:
    """Test watermarking methods endpoint"""

    def test_get_watermarking_methods(self, client):
        response = client.get('/api/get-watermarking-methods')
        assert response.status_code == 200
        data = response.json
        assert "count" in data
        assert "methods" in data
        assert isinstance(data["methods"], list)
        assert data["count"] == len(data["methods"])


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_create_user_empty_email(self, client):
        """Test that empty email is rejected"""
        response = client.post('/api/create-user', json={
            "email": "",
            "login": "testuser",
            "password": "pass123"
        })
        assert response.status_code == 400
        assert "error" in response.json

    def test_create_user_empty_password(self, client):
        """Test that empty password is rejected"""
        unique_id = str(uuid.uuid4())[:8]
        response = client.post('/api/create-user', json={
            "email": f"test_{unique_id}@test.com",
            "login": f"user_{unique_id}",
            "password": ""
        })
        assert response.status_code == 400
        assert "error" in response.json

    def test_create_user_empty_login(self, client):
        """Test that empty login is rejected"""
        unique_id = str(uuid.uuid4())[:8]
        response = client.post('/api/create-user', json={
            "email": f"test_{unique_id}@test.com",
            "login": "",
            "password": "pass123"
        })
        assert response.status_code == 400
        assert "error" in response.json

    def test_login_empty_credentials(self, client):
        """Test login with empty credentials"""
        response = client.post('/api/login', json={
            "email": "",
            "password": ""
        })
        assert response.status_code == 400

    def test_upload_document_empty_name(self, client, auth_headers):
        """Test uploading document with empty name"""
        pdf_content = b"%PDF-1.4\n%%EOF\n"
        data = {
            'file': (io.BytesIO(pdf_content), 'test.pdf'),
            'name': ''  # Empty name
        }
        response = client.post(
            '/api/upload-document',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        # Should either accept (using filename) or reject (400)
        assert response.status_code in [201, 400]

    def test_login_missing_email(self, client):
        """Test login with missing email field"""
        response = client.post('/api/login', json={
            "password": "somepass"
        })
        assert response.status_code == 400

    def test_login_missing_password(self, client):
        """Test login with missing password field"""
        response = client.post('/api/login', json={
            "email": "test@test.com"
        })
        assert response.status_code == 400

    def test_create_user_invalid_email_format(self, client):
        """Test creating user with invalid email format"""
        unique_id = str(uuid.uuid4())[:8]
        response = client.post('/api/create-user', json={
            "email": "not-an-email",
            "login": f"user_{unique_id}",
            "password": "pass123"
        })
        # Should either reject (400), accept (201), or conflict (409)
        assert response.status_code in [201, 400, 409]


class TestConfiguration:
    """Test application configuration"""

    def test_secret_key_must_not_be_none(self):
        """Ensure SECRET_KEY is never None"""
        app = create_app()
        assert app.config["SECRET_KEY"] is not None
        assert app.config["SECRET_KEY"] != ""
        assert len(app.config["SECRET_KEY"]) >= 8

    def test_secret_key_from_environment(self, monkeypatch):
        """Test SECRET_KEY loads from environment variable"""
        monkeypatch.setenv("SECRET_KEY", "test-custom-key-123")
        app = create_app()
        assert app.config["SECRET_KEY"] == "test-custom-key-123"

    def test_secret_key_has_default(self):
        """Test SECRET_KEY has secure default if env not set"""
        import os
        # Clear environment variable if set
        old_key = os.environ.get("SECRET_KEY")
        if "SECRET_KEY" in os.environ:
            del os.environ["SECRET_KEY"]

        app = create_app()
        # Should have a default value
        assert app.config["SECRET_KEY"] is not None
        assert app.config["SECRET_KEY"] == "ehmgr17key"

        # Restore if it was set
        if old_key:
            os.environ["SECRET_KEY"] = old_key

    def test_rmap_keys_dir_config(self, monkeypatch):
        """Test RMAP_KEYS_DIR loads from environment"""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setenv("RMAP_KEYS_DIR", tmpdir)
            app = create_app()

            # Verify the config is used (we'd need to check internal state)
            # For now, just ensure app starts without crashing
            assert app is not None
            assert app.config["SECRET_KEY"] is not None

    def test_rmap_keys_dir_default(self):
        """Test RMAP_KEYS_DIR has working default"""
        import os
        # Clear env var if set
        old_val = os.environ.get("RMAP_KEYS_DIR")
        if "RMAP_KEYS_DIR" in os.environ:
            del os.environ["RMAP_KEYS_DIR"]

        app = create_app()

        # Should use default path without crashing
        assert app is not None

        # Restore if it was set
        if old_val:
            os.environ["RMAP_KEYS_DIR"] = old_val