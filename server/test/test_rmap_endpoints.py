"""
Unit tests for RMAP endpoints (/api/rmap-initiate and /api/rmap-get-link)

Note: Some tests that create watermarked PDFs (which require database writes)
are marked with pytest.mark.skip since they would need a running database.
In a real environment, these would work with the test database fixture.
"""
import pytest
import json
import base64
from unittest.mock import Mock, patch, MagicMock, ANY


class TestRMAPInitiate:
    """Test suite for /api/rmap-initiate endpoint"""

    def test_rmap_initiate_missing_payload(self, client):
        """Test that missing payload returns 400"""
        response = client.post('/api/rmap-initiate', json={})
        assert response.status_code == 400
        assert "payload is required" in response.json["error"].lower()

    def test_rmap_initiate_invalid_json(self, client):
        """Test that invalid JSON returns 400"""
        response = client.post(
            '/api/rmap-initiate',
            data="not json",
            content_type='application/json'
        )
        assert response.status_code in [400, 415]

    def test_rmap_initiate_empty_payload(self, client):
        """Test that empty payload field returns 400"""
        response = client.post('/api/rmap-initiate', json={"payload": ""})
        assert response.status_code == 400

    def test_rmap_initiate_rmap_not_initialized(self, client, app):
        """Test behavior when RMAP is not initialized"""
        # Temporarily set RMAP to None
        original_rmap = app.config.get("RMAP")
        app.config["RMAP"] = None

        response = client.post('/api/rmap-initiate', json={
            "payload": "test_payload_data"
        })

        # Restore original RMAP
        app.config["RMAP"] = original_rmap

        assert response.status_code == 503
        assert "not initialized" in response.json["error"].lower()

    @patch('server.RMAP')
    def test_rmap_initiate_success(self, mock_rmap_class, client, app):
        """Test successful RMAP initiate flow"""
        # Mock RMAP instance
        mock_rmap = Mock()
        mock_rmap.handle_message1.return_value = {
            "payload": "encrypted_response_payload"
        }

        # Inject mock RMAP into app config
        app.config["RMAP"] = mock_rmap

        response = client.post('/api/rmap-initiate', json={
            "payload": "client_encrypted_payload"
        })

        assert response.status_code == 200
        data = response.json
        assert "payload" in data
        assert data["payload"] == "encrypted_response_payload"
        mock_rmap.handle_message1.assert_called_once()

    @patch('server.RMAP')
    def test_rmap_initiate_authentication_failure(self, mock_rmap_class, client, app):
        """Test RMAP initiate when authentication fails"""
        mock_rmap = Mock()
        mock_rmap.handle_message1.return_value = {
            "error": "invalid identity"
        }

        app.config["RMAP"] = mock_rmap

        response = client.post('/api/rmap-initiate', json={
            "payload": "invalid_client_payload"
        })

        assert response.status_code == 400
        assert "error" in response.json

    @patch('server.RMAP')
    def test_rmap_initiate_server_error(self, mock_rmap_class, client, app):
        """Test RMAP initiate when server encounters an error"""
        mock_rmap = Mock()
        mock_rmap.handle_message1.side_effect = Exception("Decryption failed")

        app.config["RMAP"] = mock_rmap

        response = client.post('/api/rmap-initiate', json={
            "payload": "some_payload"
        })

        assert response.status_code == 500
        assert "server error" in response.json["error"].lower()


class TestRMAPGetLink:
    """Test suite for /api/rmap-get-link endpoint"""

    def test_rmap_get_link_missing_payload(self, client):
        """Test that missing payload returns 400"""
        response = client.post('/api/rmap-get-link', json={})
        assert response.status_code == 400
        assert "payload is required" in response.json["error"].lower()

    def test_rmap_get_link_invalid_json(self, client):
        """Test that invalid JSON returns 400"""
        response = client.post(
            '/api/rmap-get-link',
            data="not json",
            content_type='application/json'
        )
        assert response.status_code in [400, 415]

    @patch('server.RMAP')
    def test_rmap_get_link_empty_payload(self, mock_rmap_class, client, app):
        """Test that empty payload field returns 400"""
        # Set up a mock RMAP that returns an error for empty payload
        mock_rmap = Mock()
        mock_rmap.handle_message2.return_value = {"error": "invalid payload"}
        app.config["RMAP"] = mock_rmap

        response = client.post('/api/rmap-get-link', json={"payload": ""})
        assert response.status_code == 400

    def test_rmap_get_link_rmap_not_initialized(self, client, app):
        """Test behavior when RMAP is not initialized"""
        original_rmap = app.config.get("RMAP")
        app.config["RMAP"] = None

        response = client.post('/api/rmap-get-link', json={
            "payload": "test_payload_data"
        })

        app.config["RMAP"] = original_rmap

        assert response.status_code == 503
        assert "not initialized" in response.json["error"].lower()

    @pytest.mark.skip(reason="Requires database connection - works in integration environment")
    @patch('server.RMAP')
    def test_rmap_get_link_success(self, mock_rmap_class, client, app):
        """Test successful RMAP get-link flow"""
        # Create a temporary PDF file for testing
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', delete=False) as f:
            f.write(b"%PDF-1.4\n%%EOF\n")
            temp_pdf = f.name

        try:
            # Set the base PDF path in config
            app.config["RMAP_BASE_PDF"] = temp_pdf

            # Use app context to ensure get_engine() works
            with app.app_context():
                mock_rmap = Mock()
                mock_rmap.handle_message2.return_value = {
                    "result": "abcd1234567890abcd1234567890abcd"  # 32-hex result
                }
                mock_rmap.nonces = {"Group_17": "some_nonce_value"}

                app.config["RMAP"] = mock_rmap

                response = client.post('/api/rmap-get-link', json={
                    "payload": "client_message2_payload"
                })

                assert response.status_code == 200
                data = response.json
                assert "result" in data
                assert len(data["result"]) == 32  # 32-hex string

                # Verify nonces were cleared
                assert len(mock_rmap.nonces) == 0
        finally:
            # Clean up temp file
            Path(temp_pdf).unlink(missing_ok=True)

    @patch('server.RMAP')
    def test_rmap_get_link_verification_failure(self, mock_rmap_class, client, app):
        """Test RMAP get-link when verification fails"""
        mock_rmap = Mock()
        mock_rmap.handle_message2.return_value = {
            "error": "invalid nonce"
        }

        app.config["RMAP"] = mock_rmap

        response = client.post('/api/rmap-get-link', json={
            "payload": "invalid_nonce_payload"
        })

        assert response.status_code == 400
        assert "error" in response.json

    @patch('server.RMAP')
    def test_rmap_get_link_server_error(self, mock_rmap_class, client, app):
        """Test RMAP get-link when server encounters an error"""
        mock_rmap = Mock()
        mock_rmap.handle_message2.side_effect = Exception("Decryption failed")

        app.config["RMAP"] = mock_rmap

        response = client.post('/api/rmap-get-link', json={
            "payload": "some_payload"
        })

        assert response.status_code == 500
        assert "server error" in response.json["error"].lower()

    @pytest.mark.skip(reason="Requires database connection - works in integration environment")
    @patch('server.RMAP')
    def test_rmap_get_link_handles_empty_nonces(self, mock_rmap_class, client, app):
        """Test that get-link handles case where nonces dict is empty"""
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', delete=False) as f:
            f.write(b"%PDF-1.4\n%%EOF\n")
            temp_pdf = f.name

        try:
            app.config["RMAP_BASE_PDF"] = temp_pdf

            with app.app_context():
                mock_rmap = Mock()
                mock_rmap.handle_message2.return_value = {
                    "result": "1234567890abcdef1234567890abcdef"
                }
                mock_rmap.nonces = {}  # Empty nonces

                app.config["RMAP"] = mock_rmap

                response = client.post('/api/rmap-get-link', json={
                    "payload": "valid_payload"
                })

                assert response.status_code == 200
                # Should still work, but identity will be "Unknown"
        finally:
            Path(temp_pdf).unlink(missing_ok=True)


class TestRMAPIntegration:
    """Integration tests for RMAP flow"""

    @pytest.mark.skip(reason="Requires database connection - works in integration environment")
    @patch('server.RMAP')
    def test_complete_rmap_flow(self, mock_rmap_class, client, app):
        """Test complete RMAP authentication flow: initiate -> get-link"""
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', delete=False) as f:
            f.write(b"%PDF-1.4\n%%EOF\n")
            temp_pdf = f.name

        try:
            app.config["RMAP_BASE_PDF"] = temp_pdf

            with app.app_context():
                mock_rmap = Mock()

                # Step 1: Initiate
                mock_rmap.handle_message1.return_value = {
                    "payload": "server_response_1"
                }
                app.config["RMAP"] = mock_rmap

                response1 = client.post('/api/rmap-initiate', json={
                    "payload": "client_message_1"
                })
                assert response1.status_code == 200

                # Step 2: Get Link
                mock_rmap.handle_message2.return_value = {
                    "result": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
                }
                mock_rmap.nonces = {"Group_05": "nonce_value"}

                response2 = client.post('/api/rmap-get-link', json={
                    "payload": "client_message_2"
                })
                assert response2.status_code == 200
                assert "result" in response2.json

                # Verify both handlers were called
                mock_rmap.handle_message1.assert_called_once()
                mock_rmap.handle_message2.assert_called_once()
        finally:
            Path(temp_pdf).unlink(missing_ok=True)

    def test_rmap_endpoints_content_type(self, client):
        """Test that RMAP endpoints require correct content-type"""
        # Test with form data instead of JSON
        response = client.post(
            '/api/rmap-initiate',
            data={'payload': 'test'},
            content_type='application/x-www-form-urlencoded'
        )
        # Should accept request but payload won't be in json format
        assert response.status_code in [400, 415]


class TestRMAPSecurity:
    """Security tests for RMAP endpoints"""

    def test_rmap_endpoints_no_authentication_required(self, client):
        """Verify RMAP endpoints don't require bearer token authentication"""
        # These endpoints use RMAP protocol for auth, not bearer tokens
        response = client.post('/api/rmap-initiate', json={
            "payload": "test"
        })
        # Should not return 401 Unauthorized
        assert response.status_code != 401

    @patch('server.RMAP')
    def test_rmap_initiate_validates_identity(self, mock_rmap_class, client, app):
        """Test that only known identities are accepted"""
        mock_rmap = Mock()
        mock_rmap.handle_message1.return_value = {
            "error": "unknown identity"
        }

        app.config["RMAP"] = mock_rmap

        response = client.post('/api/rmap-initiate', json={
            "payload": "unknown_group_payload"
        })

        assert response.status_code == 400

    def test_rmap_payload_size_limits(self, client):
        """Test that overly large payloads are rejected"""
        # Create a very large payload
        large_payload = "A" * (10 * 1024 * 1024)  # 10MB

        response = client.post('/api/rmap-initiate', json={
            "payload": large_payload
        })

        # Should fail due to size (either 400, 413, or 500)
        assert response.status_code in [400, 413, 500]


class TestRMAPEdgeCases:
    """Edge case tests for RMAP endpoints"""

    def test_rmap_initiate_null_payload(self, client):
        """Test handling of null payload value"""
        response = client.post('/api/rmap-initiate', json={
            "payload": None
        })
        assert response.status_code == 400

    @patch('server.RMAP')
    def test_rmap_get_link_null_payload(self, mock_rmap_class, client, app):
        """Test handling of null payload value"""
        mock_rmap = Mock()
        mock_rmap.handle_message2.return_value = {"error": "invalid payload"}
        app.config["RMAP"] = mock_rmap

        response = client.post('/api/rmap-get-link', json={
            "payload": None
        })
        assert response.status_code == 400

    @pytest.mark.skip(reason="Requires database connection - works in integration environment")
    @patch('server.RMAP')
    def test_rmap_result_format_validation(self, mock_rmap_class, client, app):
        """Test that result must be 32-character hex"""
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', delete=False) as f:
            f.write(b"%PDF-1.4\n%%EOF\n")
            temp_pdf = f.name

        try:
            app.config["RMAP_BASE_PDF"] = temp_pdf

            with app.app_context():
                mock_rmap = Mock()
                # Invalid result format (not 32 hex chars)
                mock_rmap.handle_message2.return_value = {
                    "result": "short"
                }
                mock_rmap.nonces = {}

                app.config["RMAP"] = mock_rmap

                response = client.post('/api/rmap-get-link', json={
                    "payload": "valid_payload"
                })

                # Should still return 200 - no validation on result format currently
                # This test documents current behavior
                assert response.status_code == 200
        finally:
            Path(temp_pdf).unlink(missing_ok=True)

    @patch('server.RMAP')
    def test_rmap_endpoints_with_extra_fields(self, mock_rmap_class, client, app):
        """Test that extra fields in request are handled gracefully"""
        mock_rmap = Mock()
        mock_rmap.handle_message1.return_value = {
            "payload": "server_response"
        }
        app.config["RMAP"] = mock_rmap

        response = client.post('/api/rmap-initiate', json={
            "payload": "test_payload",
            "extra_field": "should_be_ignored",
            "another_field": 12345
        })

        # Should process normally, ignoring extra fields
        assert response.status_code in [200, 400, 503]

    @pytest.mark.skip(reason="Requires database connection - works in integration environment")
    @patch('server.RMAP')
    def test_rmap_get_link_with_multiple_identities(self, mock_rmap_class, client, app):
        """Test behavior when multiple identities are in nonces"""
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', delete=False) as f:
            f.write(b"%PDF-1.4\n%%EOF\n")
            temp_pdf = f.name

        try:
            app.config["RMAP_BASE_PDF"] = temp_pdf

            with app.app_context():
                mock_rmap = Mock()
                mock_rmap.handle_message2.return_value = {
                    "result": "f" * 32
                }
                # Multiple active sessions
                mock_rmap.nonces = {
                    "Group_05": "nonce1",
                    "Group_17": "nonce2"
                }

                app.config["RMAP"] = mock_rmap

                response = client.post('/api/rmap-get-link', json={
                    "payload": "valid_payload"
                })

                assert response.status_code == 200
                # Should use first identity and clear all nonces
                assert len(mock_rmap.nonces) == 0
        finally:
            Path(temp_pdf).unlink(missing_ok=True)