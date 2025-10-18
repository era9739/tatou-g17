import pytest
import io
import uuid
import tempfile
import shutil
from pathlib import Path
from server import create_app
from sqlalchemy import create_engine, text


@pytest.fixture
def app(monkeypatch):
    """Create test app with test configuration using SQLite"""
    # Create a temporary directory for test storage
    test_storage = Path(tempfile.mkdtemp())

    # Monkey-patch SQL queries to be SQLite compatible
    original_text = text

    def patched_text(sql_string):
        """Replace MariaDB-specific SQL with SQLite equivalents"""
        sql_str = str(sql_string)
        # Replace LAST_INSERT_ID() with SQLite's last_insert_rowid()
        sql_str = sql_str.replace("SELECT LAST_INSERT_ID()", "SELECT last_insert_rowid()")
        sql_str = sql_str.replace("LAST_INSERT_ID()", "last_insert_rowid()")
        # Fix ON DUPLICATE KEY UPDATE (MariaDB specific) to SQLite INSERT OR REPLACE
        if "ON DUPLICATE KEY UPDATE" in sql_str:
            # For the system user creation, just use INSERT OR IGNORE
            sql_str = sql_str.replace("ON DUPLICATE KEY UPDATE id=id", "")
            if "INSERT INTO Users" in sql_str:
                sql_str = sql_str.replace("INSERT INTO", "INSERT OR IGNORE INTO")
        return original_text(sql_str)

    monkeypatch.setattr("sqlalchemy.text", patched_text)
    monkeypatch.setattr("server.text", patched_text)

    app = create_app()

    # Override with test configuration
    app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key-for-testing",
        "STORAGE_DIR": test_storage,
        "TOKEN_TTL_SECONDS": 86400,
        # SQLite configuration (overrides MariaDB)
        "DB_USER": "",
        "DB_PASSWORD": "",
        "DB_HOST": "",
        "DB_PORT": 0,
        "DB_NAME": ":memory:",
        # Disable RMAP initialization for tests
        "RMAP_BASE_PDF": "/nonexistent/path.pdf",
    })

    # Create a test engine with SQLite
    test_engine = create_engine("sqlite:///:memory:", future=True)
    app.config["_ENGINE"] = test_engine

    # Initialize database schema for SQLite
    with test_engine.begin() as conn:
        # Create Users table (SQLite compatible)
        conn.execute(patched_text("""
            CREATE TABLE Users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email VARCHAR(320) NOT NULL UNIQUE,
                hpassword VARCHAR(255) NOT NULL,
                login VARCHAR(64) NOT NULL
            )
        """))

        # Create Documents table (SQLite compatible)
        conn.execute(patched_text("""
            CREATE TABLE Documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(255) NOT NULL,
                path VARCHAR(1024) NOT NULL UNIQUE,
                ownerid INTEGER NOT NULL,
                creation DATETIME DEFAULT CURRENT_TIMESTAMP,
                sha256 BLOB NOT NULL,
                size INTEGER NOT NULL,
                FOREIGN KEY (ownerid) REFERENCES Users(id) ON DELETE CASCADE
            )
        """))

        # Create Versions table (SQLite compatible)
        conn.execute(patched_text("""
            CREATE TABLE Versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                documentid INTEGER NOT NULL,
                link VARCHAR(255) NOT NULL UNIQUE,
                intended_for VARCHAR(320),
                secret VARCHAR(320) NOT NULL,
                method VARCHAR(32) NOT NULL,
                position TEXT,
                path VARCHAR(320) NOT NULL,
                FOREIGN KEY (documentid) REFERENCES Documents(id) ON DELETE CASCADE
            )
        """))

        # Add SQLite-specific functions to mimic MariaDB functions
        # UNHEX - convert hex string to binary
        conn.connection.create_function("UNHEX", 1, lambda x: bytes.fromhex(x) if x else None)
        # HEX - convert binary to hex string
        conn.connection.create_function("HEX", 1, lambda x: x.hex().upper() if x else None)

    yield app

    # Cleanup
    shutil.rmtree(test_storage, ignore_errors=True)


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
    response = client.post('/api/create-user', json=unique_user_data)
    assert response.status_code == 201, f"User creation failed: {response.get_json()}"

    # Login to get token
    response = client.post('/api/login', json={
        "email": unique_user_data["email"],
        "password": unique_user_data["password"]
    })
    assert response.status_code == 200, f"Login failed: {response.get_json()}"

    data = response.get_json()
    assert 'token' in data, f"No token in response: {data}"

    token = data['token']
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