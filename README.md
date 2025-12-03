# Tatou - PDF Watermarking Platform

A web platform for PDF watermarking with security testing capabilities. This project is intended for pedagogical use and contains intentional security vulnerabilities for educational purposes. **Do not deploy on an open network.**

## Table of Contents

- [Project Overview](#project-overview)
- [Prerequisites](#prerequisites)
- [Setup Instructions](#setup-instructions)
- [Running Tests](#running-tests)
- [Deployment](#deployment)
- [RMAP Client Integration](#rmap-client-integration)
- [Additional Testing](#additional-testing)
- [Project Structure](#project-structure)
- [API Documentation](#api-documentation)
- [Contributors](#contributors)

---

## Project Overview

Tatou is a Flask-based web application that allows users to watermark PDF documents using various steganographic techniques. The platform includes:

- User authentication and document management
- Multiple watermarking methods (whitespace steganography, EOF injection, base64 encoding)
- RMAP (Roger Michael Authentication Protocol) for secure document sharing
- Comprehensive testing suite including unit tests, API tests, mutation tests, and fuzz tests

**Architecture:**
- **Backend:** Python Flask server
- **Database:** MariaDB
- **Frontend:** HTML/JavaScript
- **Deployment:** Docker and Docker Compose

---

## Prerequisites

- **Operating System:** Linux (Ubuntu/Debian recommended) or macOS
- **Required Software:**
  - Python 3.12+
  - Docker and Docker Compose
  - Git
  - HTTPie (optional, for API testing)

---

## Setup Instructions

### 1. Clone the Repository

```bash
git https://github.com/era9739/tatou-g17.git
cd tatou
```

### 2. Set Up Python Virtual Environment

```bash
cd server

# Create a Python virtual environment
python3 -m venv .venv

# Activate the virtual environment
# On Linux/macOS:
source .venv/bin/activate
# On Windows:
# .venv\Scripts\activate

# Install development dependencies
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

---

## Running Tests

### Unit Tests

Run the complete test suite with pytest:

```bash
cd server

# Activate virtual environment if not already active
source .venv/bin/activate

# Run all unit tests
python -m pytest

# Run with verbose output
python -m pytest -v

# Run specific test file
python -m pytest test/test_server_endpoints.py
```

### API Tests

API tests are included in the unit test suite and test all Flask endpoints:

```bash
# Run API-specific tests
python -m pytest test/test_server_endpoints.py -v

# Test with detailed output
python -m pytest test/test_server_endpoints.py -vv
```

### Coverage Analysis

Generate test coverage reports:

```bash
# Run tests with coverage
python -m pytest --cov=src --cov-report=html --cov-report=term

# View HTML coverage report
# Open htmlcov/index.html in your browser

# Generate detailed coverage report
python -m pytest --cov=src --cov-report=html:test-results/coverage --cov-report=term-missing
```

**Coverage Reports Location:**
- HTML Report: `test-results/coverage/index.html`
- Terminal: Displayed after test execution

---

## Additional Testing

### Mutation Testing

Mutation testing evaluates test suite effectiveness by introducing small code changes:

```bash
cd server
source .venv/bin/activate

# Install mutmut if not already installed
pip install mutmut

# Run mutation testing
mutmut run

# View mutation testing results
mutmut results

# Show specific mutant details
mutmut show <mutant_id>

# Generate HTML report
mutmut html
```

**Configuration:** See `server/setup.cfg` for mutation testing settings

**Documentation:** Detailed mutation testing analysis is available in `MUTATION_TESTING_REPORT.md`

### Fuzz Testing

Fuzz testing helps discover robustness and security issues:

```bash
cd server

# Ensure the application is running (see Deployment section)
# Set base URL for local testing
export TATOU_BASE=http://localhost:5000

# Run simple fuzzer
python fuzz/simple_fuzzer.py

# Run fuzzer via GitHub Actions (see .github/workflows/fuzz.yml)
```

**Fuzzer Configuration:** See `server/fuzz/configuration.md`

**What it tests:**
- JSON endpoint validation with malformed inputs
- File upload handling with various file sizes and types
- Input sanitization and error handling
- API robustness against unexpected inputs

---

## Deployment

### Local Development with Docker

```bash
# From the root directory of the project

# 1. Create environment file
cp sample.env .env

# 2. Edit .env and configure your passwords and secrets
# Required variables:
#   - MARIADB_ROOT_PASSWORD
#   - MARIADB_USER
#   - MARIADB_PASSWORD
#   - SECRET_KEY
#   - FLAG_2 (for RMAP testing)
nano .env  # or use your preferred editor

# 3. Build and start containers
docker compose up --build -d

# 4. Monitor logs in real-time
docker compose logs -f

# 5. Check application health
# Install HTTPie if needed: pip install httpie
http -v :5000/healthz

# 6. Open web interface
# Navigate to http://127.0.0.1:5000 in your browser
```

### Deployment Commands

```bash
# Stop all containers
docker compose down

# Rebuild and restart
docker compose up --build -d

# View logs
docker compose logs server
docker compose logs db

# Check container status
docker ps

# Access server shell
docker exec -it tatou-g17-server-1 bash

# Access database shell
docker exec -it tatou-g17-db-1 mysql -u root -p
```

### Environment Variables

Key environment variables in `.env`:

```bash
# Database Configuration
MARIADB_ROOT_PASSWORD=<your_root_password>
MARIADB_USER=<database_user>
MARIADB_PASSWORD=<database_password>
MARIADB_DATABASE=tatou_db

# Application Secrets
SECRET_KEY=<your_secret_key>
FLAG_2=<your_flag_value>

# RMAP Configuration (optional)
RMAP_KEYS_DIR=/app/server/keys
RMAP_BASE_PDF=/app/group_17_rmap.pdf
RMAP_LINK_TTL=600
```

---

## RMAP Client Integration

RMAP (Roger Michael Authentication Protocol) enables secure, authenticated PDF retrieval.

### Prerequisites

Install the RMAP client library:

```bash
# Install from GitHub
python -m pip install rmap@git+https://github.com/nharrand/RMAP-Server.git@v2.0.0

# Or for development
pip install -e git+https://github.com/nharrand/RMAP-Server.git@v2.0.0#egg=rmap
```

### Key Setup

You need three key files to connect:

1. **Client Private Key** (`client_private.asc`) - Your group's private key
2. **Server Public Key** (`server_public.asc`) - Tatou server's public key
3. **Client Public Key** - Must be registered in `server/keys/clients/`

### Connecting to RMAP Endpoint

```bash
# Basic connection using rmap-client CLI
rmap-client --client-priv client_private.asc \
            --identity Group_17 \
            --server-pub server_public.asc \
            --server 127.0.0.1

# Connect to remote server
rmap-client --client-priv client_private.asc \
            --identity Group_17 \
            --server-pub server_public.asc \
            --server your.server.address

# With custom port
rmap-client --client-priv client_private.asc \
            --identity Group_17 \
            --server-pub server_public.asc \
            --server 127.0.0.1:5000
```

### Python RMAP Integration

```python
from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP

# Initialize Identity Manager
im = IdentityManager(
    client_keys_dir="server/keys/clients",
    server_public_key_path="server/keys/server_public.asc",
    server_private_key_path="server/keys/server_private.asc"
)

# Initialize RMAP
rmap = RMAP(im)

# Handle incoming RMAP messages (server-side)
response = rmap.handle_message1(payload_dict)
link_response = rmap.handle_message2(payload_dict)
```

### RMAP API Endpoints

The server provides two RMAP endpoints:

1. **POST /api/rmap-initiate** - Initial handshake (Message 1)
   ```json
   {
     "payload": "<base64_encrypted_payload>"
   }
   ```

2. **POST /api/rmap-get-link** - Retrieve watermarked PDF link (Message 2)
   ```json
   {
     "payload": "<base64_encrypted_payload>"
   }
   ```

### RMAP Configuration in Server

The RMAP system requires:

```
server/keys/
├── server_public.asc       # Server's public key
├── server_private.asc      # Server's private key (keep secure!)
└── clients/                # Directory of client public keys
    ├── Group_05.asc
    ├── Group_17.asc
    └── Group_20.asc
```

**Important:** Never commit `server_private.asc` to version control!

### Testing RMAP

```bash
# 1. Ensure server is running
docker compose up -d

# 2. Check RMAP initialization in logs
docker compose logs server | grep RMAP

# 3. Test with rmap-client
rmap-client --client-priv server_private.asc \
            --identity Group_17 \
            --server-pub server_public.asc \
            --server 127.0.0.1

# 4. Verify watermarked PDF retrieval
# The client will receive a link like: /get-version/<token>
```

---

## Project Structure

```
tatou/
├── server/
│   ├── src/                        # Source code
│   │   ├── server.py               # Main Flask application
│   │   ├── watermarking_utils.py   # Watermarking utilities
│   │   ├── whitespace_steganography.py
│   │   ├── add_after_eof.py
│   │   ├── base64_invisible_comment.py
│   │   ├── watermarking_cli.py     # CLI interface
│   │   └── security_utils.py       # Security validation
│   │
│   ├── test/                       # Test suite
│   │   ├── conftest.py             # Test configuration
│   │   ├── test_api_endpoints.py   # API tests (28 tests)
│   │   ├── test_whitespace_steganography.py  # (24 tests)
│   │   ├── test_add_after_eof.py   # (18 tests)
│   │   ├── test_base64_invisible_comment.py  # (12 tests)
│   │   ├── test_watermarking_cli.py  # (21 tests)
│   │   └── test_security.py        # Security tests (30 tests)
│   │
│   ├── fuzz/                       # Fuzzing tests
│   │   ├── simple_fuzzer.py        # Main fuzzer
│   │   └── configuration.md        # Fuzzer documentation
│   │
│   ├── keys/                       # RMAP encryption keys
│   │   ├── server_public.asc
│   │   ├── server_private.asc
│   │   └── clients/                # Client public keys
│   │
│   ├── pyproject.toml              # Python dependencies
│   ├── setup.cfg                   # Tool configuration
│   ├── Dockerfile                  # Server container
│   └── entrypoint.sh               # Container startup script
│
├── .github/
│   └── workflows/
│       ├── build-and-test.yml      # CI/CD pipeline
│       └── fuzz.yml                # Fuzz testing workflow
│
├── docker-compose.yml              # Container orchestration
├── sample.env                      # Environment template
├── README.md                       # This file
├── API.md                          # API documentation
└── MUTATION_TESTING_REPORT.md      # Mutation testing analysis
```

---

## API Documentation

Detailed API specifications are available in `server/API.md`.

### Public Endpoints (No Authentication)

- `GET /healthz` - Health check
- `POST /create-user` - Create new user account
- `POST /login` - User authentication
- `GET /get-watermarking-methods` - List available watermarking methods

### Authenticated Endpoints

- `POST /upload-document` - Upload PDF document
- `POST /add-watermark` - Add watermark to document
- `GET /list-documents` - List user's documents
- `GET /get-document/<doc_id>` - Retrieve document
- `POST /read-watermark` - Extract watermark from document
- `GET /get-version/<token>` - Retrieve watermarked document via token

### RMAP Endpoints

- `POST /api/rmap-initiate` - RMAP authentication initiation
- `POST /api/rmap-get-link` - Retrieve watermarked PDF link

---

## CI/CD Pipeline

The project includes automated testing via GitHub Actions:

### Build and Test Workflow

Triggered on push to `main` and pull requests:

```yaml
# .github/workflows/build-and-test.yml
- Runs unit tests with pytest
- Generates coverage reports
- Builds and pushes Docker images
- Publishes test results
```

### Running Locally

```bash
# Run the same tests as CI
cd server
source .venv/bin/activate

python -m pytest \
  --verbose \
  --junit-xml=test-results/junit.xml \
  --html=test-results/report.html \
  --self-contained-html \
  --cov=src \
  --cov-report=html:test-results/coverage \
  --cov-report=term
```

---

## Security Considerations

⚠️ **Warning:** This application intentionally contains security vulnerabilities for educational purposes.

**Known Security Features:**
- Path traversal prevention
- Input validation and sanitization
- File size limits (100MB max)
- Secret length validation
- Command injection prevention

**Do not deploy this application on production or public networks.**

For security testing documentation, see `MUTATION_TESTING_REPORT.md`.

---

## Troubleshooting

### Common Issues

**Database Connection Fails:**
```bash
# Check database container status
docker compose logs db

# Verify database is healthy
docker inspect --format='{{json .State.Health.Status}}' tatou-g17-db-1

# Restart database
docker compose restart db
```

**RMAP Initialization Fails:**
```bash
# Check key files exist
ls -la server/keys/

# Verify permissions
chmod 600 server/keys/server_private.asc

# Check logs
docker compose logs server | grep RMAP
```

**Tests Failing:**
```bash
# Ensure virtual environment is activated
source .venv/bin/activate

# Reinstall dependencies
pip install -e ".[dev]"

# Clear pytest cache
pytest --cache-clear
```

---

## Contributors

**Group 17 Team Members:**
- Erangi De Silva
- Harin Wimalasiri
- Malsha Jayawardana

**Instructor:** Nicolas Harrand

**Course:** Software Security Project, Stockholm University

---

## License

This project is for educational purposes only. See course materials for usage restrictions.

---

## Additional Resources

- [RMAP Server Repository](https://github.com/nharrand/RMAP-Server)
- [Original Tatou Repository](https://github.com/nharrand/tatou)
- [API Specification](server/API.md)
- [Mutation Testing Report](MUTATION_TESTING_REPORT.md)
- [Fuzzing Configuration](server/fuzz/configuration.md)

---

**Last Updated:** December 03, 2025.  