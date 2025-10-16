import pytest
import sys
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server import create_app

@pytest.fixture(scope="session")
def app():
    """Create test app with test configuration"""
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key",
    })
    yield app

@pytest.fixture
def client(app):
    """Test client for making requests"""
    return app.test_client()

@pytest.fixture
def sample_pdf(tmp_path):
    """Create a minimal valid PDF for testing"""
    pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer
<< /Size 4 /Root 1 0 R >>
startxref
187
%%EOF
"""
    pdf_file = tmp_path / "test.pdf"
    pdf_file.write_bytes(pdf_content)
    return pdf_file