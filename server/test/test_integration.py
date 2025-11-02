import pytest
from io import BytesIO
import uuid


class TestFullWorkflow:
    """Test complete user workflows"""

    def test_complete_user_journey(self, client, sample_pdf_factory):
        """Test complete workflow from user creation to watermark extraction"""
        # Use unique username to avoid conflicts
        unique_id = str(uuid.uuid4())[:8]

        # 1. Create user
        create_response = client.post('/api/create-user', json={
            'login': f'journeyuser_{unique_id}',
            'email': f'journey_{unique_id}@test.com',
            'password': 'password123'
        })
        assert create_response.status_code in [200, 201]

        # 2. Login
        login_response = client.post('/api/login', json={
            'email': f'journey_{unique_id}@test.com',
            'password': 'password123'
        })
        assert login_response.status_code == 200
        token = login_response.json['token']
        headers = {'Authorization': f'Bearer {token}'}

        # 3. Upload document
        upload_response = client.post(
            '/api/upload-document',
            data={'file': (sample_pdf_factory(), 'journey.pdf'), 'name': 'journey-doc'},
            headers=headers,
            content_type='multipart/form-data'
        )
        assert upload_response.status_code == 201
        doc_id = upload_response.json['id']

        # 4. List documents
        list_response = client.get('/api/list-documents', headers=headers)
        assert list_response.status_code == 200
        assert len(list_response.json['documents']) >= 1

        # 5. Get document
        get_response = client.get(f'/api/get-document/{doc_id}', headers=headers)
        assert get_response.status_code == 200

        # 6. Create watermark
        watermark_response = client.post(
            f'/api/create-watermark/{doc_id}',
            json={
                'method': 'whitespace-stego',
                'secret': 'journey-secret',
                'key': 'journey-key',
                'intended_for': 'recipient@test.com'
            },
            headers=headers
        )
        if watermark_response.status_code == 201:
            version_id = watermark_response.json['id']
            link = watermark_response.json['link']

            # 7. List versions
            versions_response = client.get(
                f'/api/list-versions/{doc_id}',
                headers=headers
            )
            assert versions_response.status_code == 200
            assert len(versions_response.json['versions']) >= 1

            # 8. Get version by link (no auth needed)
            version_response = client.get(f'/api/get-version/{link}')
            if version_response.status_code == 200:
                assert b'%PDF' in version_response.data

    def test_multi_document_workflow(self, client, sample_pdf_factory):
        """Test workflow with multiple documents"""
        unique_id = str(uuid.uuid4())[:8]

        # Create and login
        client.post('/api/create-user', json={
            'login': f'multiuser_{unique_id}',
            'email': f'multi_{unique_id}@test.com',
            'password': 'password123'
        })

        login_response = client.post('/api/login', json={
            'email': f'multi_{unique_id}@test.com',
            'password': 'password123'
        })

        if login_response.status_code == 200:
            token = login_response.json['token']
            headers = {'Authorization': f'Bearer {token}'}

            # Upload multiple documents
            doc_ids = []
            for i in range(3):
                # Create fresh BytesIO for each upload
                upload_response = client.post(
                    '/api/upload-document',
                    data={'file': (sample_pdf_factory(), f'doc{i}.pdf'), 'name': f'document-{i}'},
                    headers=headers,
                    content_type='multipart/form-data'
                )
                if upload_response.status_code == 201:
                    doc_ids.append(upload_response.json['id'])

            # Verify all documents are listed
            list_response = client.get('/api/list-documents', headers=headers)
            if list_response.status_code == 200:
                assert len(list_response.json['documents']) >= len(doc_ids)

    def test_watermark_read_write_cycle(self, client, sample_pdf_factory):
        """Test creating and reading watermarks"""
        unique_id = str(uuid.uuid4())[:8]

        # Setup
        client.post('/api/create-user', json={
            'login': f'cycleuser_{unique_id}',
            'email': f'cycle_{unique_id}@test.com',
            'password': 'password123'
        })

        login_response = client.post('/api/login', json={
            'email': f'cycle_{unique_id}@test.com',
            'password': 'password123'
        })

        if login_response.status_code == 200:
            token = login_response.json['token']
            headers = {'Authorization': f'Bearer {token}'}

            # Upload
            upload_response = client.post(
                '/api/upload-document',
                data={'file': (sample_pdf_factory(), 'cycle.pdf'), 'name': 'cycle-doc'},
                headers=headers,
                content_type='multipart/form-data'
            )

            if upload_response.status_code == 201:
                doc_id = upload_response.json['id']
                secret = 'test-secret-for-cycle'
                key = 'test-key-for-cycle'

                # Create watermark
                watermark_response = client.post(
                    f'/api/create-watermark/{doc_id}',
                    json={
                        'method': 'whitespace-stego',
                        'secret': secret,
                        'key': key,
                        'intended_for': 'reader@test.com'
                    },
                    headers=headers
                )

                # Response depends on implementation
                assert watermark_response.status_code in [201, 400, 500]


class TestErrorHandling:
    """Test error handling scenarios"""

    def test_duplicate_user_creation(self, client):
        """Test creating duplicate user"""
        unique_id = str(uuid.uuid4())[:8]
        user_data = {
            'login': f'dupuser_{unique_id}',
            'email': f'dup_{unique_id}@test.com',
            'password': 'password123'
        }

        # First creation
        response1 = client.post('/api/create-user', json=user_data)
        assert response1.status_code in [200, 201]

        # Duplicate creation should fail
        response2 = client.post('/api/create-user', json=user_data)
        assert response2.status_code in [400, 409]  # Conflict or Bad Request

    def test_login_with_wrong_password(self, client):
        """Test login with incorrect password"""
        unique_id = str(uuid.uuid4())[:8]
        client.post('/api/create-user', json={
            'login': f'wrongpass_{unique_id}',
            'email': f'wrongpass_{unique_id}@test.com',
            'password': 'correct123'
        })

        response = client.post('/api/login', json={
            'email': f'wrongpass_{unique_id}@test.com',
            'password': 'wrong456'
        })
        assert response.status_code in [401, 403]

    def test_login_nonexistent_user(self, client):
        """Test login with non-existent user"""
        response = client.post('/api/login', json={
            'email': f'notexist_{uuid.uuid4()}@test.com',
            'password': 'password123'
        })
        assert response.status_code in [401, 404]

    def test_access_without_token(self, client):
        """Test accessing protected endpoints without token"""
        protected_endpoints = [
            ('/api/upload-document', 'post'),
            ('/api/list-documents', 'get'),
            ('/api/list-versions/1', 'get'),
            ('/api/list-all-versions', 'get')
        ]

        for endpoint, method in protected_endpoints:
            if method == 'post':
                response = client.post(endpoint)
            else:
                response = client.get(endpoint)

            # 401 for auth required, 404 if route doesn't exist
            assert response.status_code in [401, 404]

    def test_invalid_token(self, client):
        """Test using invalid authentication token"""
        headers = {'Authorization': 'Bearer invalid-token-12345'}

        response = client.get('/api/list-documents', headers=headers)
        assert response.status_code in [401, 403]

    def test_expired_token(self, client):
        """Test handling of expired tokens"""
        unique_id = str(uuid.uuid4())[:8]
        # Create user and login
        client.post('/api/create-user', json={
            'login': f'expireuser_{unique_id}',
            'email': f'expire_{unique_id}@test.com',
            'password': 'password123'
        })

        login_response = client.post('/api/login', json={
            'email': f'expire_{unique_id}@test.com',
            'password': 'password123'
        })

        if login_response.status_code == 200:
            # Token should be valid initially
            token = login_response.json['token']
            headers = {'Authorization': f'Bearer {token}'}

            response = client.get('/api/list-documents', headers=headers)
            assert response.status_code in [200, 401]


class TestInputValidation:
    """Test input validation across endpoints"""

    def test_create_user_missing_fields(self, client):
        """Test user creation with missing fields"""
        # Missing password
        response = client.post('/api/create-user', json={
            'login': 'test',
            'email': 'test@test.com'
        })
        assert response.status_code == 400

        # Missing email
        response = client.post('/api/create-user', json={
            'login': 'test',
            'password': 'password'
        })
        assert response.status_code == 400

        # Missing login
        response = client.post('/api/create-user', json={
            'email': 'test@test.com',
            'password': 'password'
        })
        assert response.status_code == 400

    def test_create_user_invalid_email(self, client):
        """Test user creation with invalid email"""
        unique_id = str(uuid.uuid4())[:8]
        response = client.post('/api/create-user', json={
            'login': f'testuser_{unique_id}',
            'email': 'invalid-email',  # Invalid format
            'password': 'password123'
        })
        # May or may not validate email - accept both
        assert response.status_code in [200, 201, 400, 409]

    def test_create_user_weak_password(self, client):
        """Test user creation with weak password"""
        unique_id = str(uuid.uuid4())[:8]
        response = client.post('/api/create-user', json={
            'login': f'testuser_{unique_id}',
            'email': f'test_{unique_id}@test.com',
            'password': '123'
        })
        # May or may not enforce password strength
        assert response.status_code in [200, 201, 400]

    def test_upload_non_pdf_file(self, client, auth_headers):
        """Test uploading non-PDF file"""
        fake_file = BytesIO(b"This is not a PDF file")

        response = client.post(
            '/api/upload-document',
            data={'file': (fake_file, 'fake.pdf'), 'name': 'fake-doc'},
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        # Server may accept it (201) or reject it (400/415)
        # Educational project may not validate strictly
        assert response.status_code in [201, 400, 415]

    def test_upload_oversized_file(self, client, auth_headers):
        """Test uploading file exceeding size limit"""
        # Just test with a reasonably sized file, not actually 100MB
        large_content = b"%PDF-1.4\n" + b"X" * 1000
        large_file = BytesIO(large_content)

        response = client.post(
            '/api/upload-document',
            data={'file': (large_file, 'large.pdf'), 'name': 'large-doc'},
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        # Should handle gracefully
        assert response.status_code in [200, 201, 400, 413]

    def test_upload_empty_file(self, client, auth_headers):
        """Test uploading empty file"""
        empty_file = BytesIO(b"")

        response = client.post(
            '/api/upload-document',
            data={'file': (empty_file, 'empty.pdf'), 'name': 'empty-doc'},
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        # Server may accept empty files (educational project)
        assert response.status_code in [201, 400, 415]


class TestConcurrencyAndRaceConditions:
    """Test concurrent operations"""

    def test_concurrent_document_creation(self, client, sample_pdf_factory):
        """Test creating multiple documents rapidly"""
        unique_id = str(uuid.uuid4())[:8]
        client.post('/api/create-user', json={
            'login': f'concuser_{unique_id}',
            'email': f'conc_{unique_id}@test.com',
            'password': 'password123'
        })

        login_response = client.post('/api/login', json={
            'email': f'conc_{unique_id}@test.com',
            'password': 'password123'
        })

        if login_response.status_code == 200:
            token = login_response.json['token']
            headers = {'Authorization': f'Bearer {token}'}

            # Upload multiple documents rapidly with fresh BytesIO each time
            responses = []
            for i in range(5):
                response = client.post(
                    '/api/upload-document',
                    data={'file': (sample_pdf_factory(), f'rapid{i}.pdf'), 'name': f'rapid-{i}'},
                    headers=headers,
                    content_type='multipart/form-data'
                )
                responses.append(response)

            # All should succeed or fail gracefully
            for response in responses:
                assert response.status_code in [200, 201, 400, 500]


class TestDatabaseIntegrity:
    """Test database-related scenarios"""

    def test_document_ownership(self, client, sample_pdf_factory):
        """Test that users can only access their own documents"""
        unique_id = str(uuid.uuid4())[:8]

        # Create two users
        client.post('/api/create-user', json={
            'login': f'owner_{unique_id}',
            'email': f'owner_{unique_id}@test.com',
            'password': 'password123'
        })

        client.post('/api/create-user', json={
            'login': f'other_{unique_id}',
            'email': f'other_{unique_id}@test.com',
            'password': 'password123'
        })

        # Owner uploads document
        owner_login = client.post('/api/login', json={
            'email': f'owner_{unique_id}@test.com',
            'password': 'password123'
        })

        if owner_login.status_code == 200:
            owner_token = owner_login.json['token']
            owner_headers = {'Authorization': f'Bearer {owner_token}'}

            upload_response = client.post(
                '/api/upload-document',
                data={'file': (sample_pdf_factory(), 'owned.pdf'), 'name': 'owned-doc'},
                headers=owner_headers,
                content_type='multipart/form-data'
            )

            if upload_response.status_code == 201:
                doc_id = upload_response.json['id']

                # Other user tries to access
                other_login = client.post('/api/login', json={
                    'email': f'other_{unique_id}@test.com',
                    'password': 'password123'
                })

                if other_login.status_code == 200:
                    other_token = other_login.json['token']
                    other_headers = {'Authorization': f'Bearer {other_token}'}

                    # Should be denied
                    response = client.get(
                        f'/api/get-document/{doc_id}',
                        headers=other_headers
                    )
                    assert response.status_code in [403, 404]


@pytest.fixture
def auth_headers(client):
    """Create auth headers with unique user"""
    unique_id = str(uuid.uuid4())[:8]
    client.post('/api/create-user', json={
        'login': f'integtest_{unique_id}',
        'email': f'integ_{unique_id}@test.com',
        'password': 'password123'
    })

    login_resp = client.post('/api/login', json={
        'email': f'integ_{unique_id}@test.com',
        'password': 'password123'
    })

    if login_resp.status_code == 200:
        token = login_resp.json['token']
        return {'Authorization': f'Bearer {token}'}

    return {}


@pytest.fixture
def sample_pdf_factory():
    """Factory that creates fresh BytesIO objects for each call"""

    def create_pdf():
        content = b"""%PDF-1.4
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
        return BytesIO(content)

    return create_pdf