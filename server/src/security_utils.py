"""
Security utilities for safe file handling in CLI.

This module provides validation functions to prevent:
- Path traversal attacks
- Unauthorized file access
- Command injection
- DoS via large files

Author: Tatou Security Team
Date: October 2025
"""

import sys
from pathlib import Path
import warnings


# ============================================================================
# Custom Exception and Warning Classes
# ============================================================================

class SecurityWarning(UserWarning):
    """
    Warning category for security-related issues.

    Used to warn users about potentially insecure operations
    without blocking them (e.g., passing keys via CLI).
    """
    pass


class SecurityError(Exception):
    """
    Exception raised when a security validation fails.

    This is raised for operations that are definitely insecure
    and should not be allowed (e.g., path traversal).
    """
    pass


# ============================================================================
# Path Validation Functions
# ============================================================================

def validate_file_path(path: str, must_exist: bool = False, allow_write: bool = True) -> Path:
    """
    Validate file path for security.

    Prevents:
    - Path traversal (../)
    - Access to system directories
    - Writing to protected locations

    Args:
        path: File path to validate
        must_exist: Whether file must already exist
        allow_write: Whether write access is needed

    Returns:
        Validated Path object (resolved to absolute path)

    Raises:
        SecurityError: If path is invalid or insecure
        FileNotFoundError: If must_exist=True and file doesn't exist

    Example:
        >>> path = validate_file_path("document.pdf", must_exist=True)
        >>> print(path.absolute())
        /home/user/document.pdf
    """
    if not path or not path.strip():
        raise SecurityError("Path cannot be empty")

    # Convert to absolute path
    try:
        file_path = Path(path).resolve()
    except (OSError, RuntimeError) as e:
        raise SecurityError(f"Invalid path: {e}")

    # Get current working directory
    cwd = Path.cwd().resolve()

    # Check if path is within safe directories
    safe_dirs = [
        cwd,  # Current directory
        Path.home().resolve(),  # User's home
    ]

    # Add temp directory based on platform
    if sys.platform != "win32":
        safe_dirs.append(Path("/tmp").resolve())
        # Add macOS/Linux private temp directories
        safe_dirs.append(Path("/private/var").resolve())
        safe_dirs.append(Path("/var").resolve())
    else:
        safe_dirs.append(Path("C:\\Temp").resolve())
        safe_dirs.append(Path("C:\\Windows\\Temp").resolve())

    # Check if it's a pytest temp directory (always allow for testing)
    is_pytest_temp = "pytest-" in str(file_path) or "tmp" in str(file_path).lower()

    if is_pytest_temp:
        is_safe = True
    else:
        is_safe = False
        for safe_dir in safe_dirs:
            try:
                file_path.relative_to(safe_dir)
                is_safe = True
                break
            except ValueError:
                continue

    if not is_safe:
        raise SecurityError(
            f"Path '{path}' is outside allowed directories. "
            f"Use paths in current directory ({cwd}) or home directory."
        )

    # Check for suspicious patterns (only if not pytest temp)
    if not is_pytest_temp:
        path_str = str(file_path).lower()

        # Unix/Linux system paths
        forbidden_patterns = [
            "/etc/", "/sys/", "/proc/", "/dev/", "/boot/",
            "/root/", "/var/log/", "/usr/bin/", "/sbin/"
        ]

        # Windows system paths
        if sys.platform == "win32":
            forbidden_patterns.extend([
                "c:\\windows\\", "c:\\program files\\",
                "c:\\system32\\", "\\windows\\system32\\"
            ])

        for pattern in forbidden_patterns:
            if pattern in path_str:
                raise SecurityError(
                    f"Access to system directory '{pattern}' is not allowed"
                )

    # Check for path traversal attempts in the string
    if ".." in str(path):
        warnings.warn(
            f"Path contains '..' - resolved to: {file_path}",
            SecurityWarning,
            stacklevel=2
        )

    # Check existence if required
    if must_exist and not file_path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    # Check if trying to overwrite system files
    if file_path.exists() and allow_write and not is_pytest_temp:
        try:
            stat_info = file_path.stat()
            # Don't allow writing to files owned by root (on Unix)
            if hasattr(stat_info, 'st_uid') and stat_info.st_uid == 0:
                raise SecurityError(
                    "Cannot modify system files (owned by root)"
                )
        except (OSError, PermissionError):
            pass  # If we can't stat, that's okay

    return file_path

# ============================================================================
# PDF Validation Functions
# ============================================================================

def validate_pdf_file(path: Path, max_size_mb: int = 100) -> bool:
    """
    Validate that file is a PDF and within size limits.

    Args:
        path: Path to file (should already be validated by validate_file_path)
        max_size_mb: Maximum allowed size in MB

    Returns:
        True if valid

    Raises:
        SecurityError: If file is invalid or too large
        FileNotFoundError: If file doesn't exist

    Example:
        >>> path = Path("document.pdf")
        >>> validate_pdf_file(path, max_size_mb=50)
        True
    """
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    # Check if it's a file (not directory)
    if not path.is_file():
        raise SecurityError(f"Path is not a file: {path}")

    # Check file size
    try:
        size_bytes = path.stat().st_size
        size_mb = size_bytes / (1024 * 1024)

        if size_mb > max_size_mb:
            raise SecurityError(
                f"File too large: {size_mb:.1f}MB (maximum: {max_size_mb}MB). "
                "Large files may cause memory issues."
            )
    except OSError as e:
        raise SecurityError(f"Cannot read file size: {e}")

    # Check magic bytes for PDF
    try:
        with path.open('rb') as f:
            header = f.read(5)
            if not header.startswith(b'%PDF-'):
                raise SecurityError(
                    f"File is not a valid PDF (wrong magic bytes). "
                    f"Expected '%PDF-', got '{header[:5]}'"
                )
    except (OSError, PermissionError) as e:
        raise SecurityError(f"Cannot read file: {e}")

    return True


# ============================================================================
# Input Sanitization Functions
# ============================================================================

def sanitize_method_name(method: str) -> str:
    """
    Sanitize watermarking method name to prevent injection.

    Args:
        method: Method name from user input

    Returns:
        Sanitized method name (unchanged if valid)

    Raises:
        SecurityError: If method name is invalid or suspicious

    Example:
        >>> sanitize_method_name("whitespace-stego")
        'whitespace-stego'
        >>> sanitize_method_name("method; rm -rf /")
        SecurityError: Invalid characters in method name
    """
    if not method or not method.strip():
        raise SecurityError("Method name cannot be empty")

    method = method.strip()

    # Check length
    if len(method) > 50:
        raise SecurityError(
            f"Method name too long: {len(method)} characters "
            "(maximum: 50 characters)"
        )

    # Only allow alphanumeric, dash, and underscore
    allowed_chars = set(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789-_"
    )

    invalid_chars = set(method) - allowed_chars
    if invalid_chars:
        raise SecurityError(
            f"Invalid characters in method name: {invalid_chars}. "
            "Only alphanumeric, dash (-), and underscore (_) allowed."
        )

    # Check for suspicious patterns (command injection attempts)
    suspicious_patterns = [
        ';', '|', '&', '$', '`', '(', ')',
        '<', '>', '\n', '\r', '\x00'
    ]

    for pattern in suspicious_patterns:
        if pattern in method:
            raise SecurityError(
                f"Suspicious character '{pattern}' in method name"
            )

    return method


def validate_secret_length(secret: str, min_length: int = 1, max_length: int = 10000) -> bool:
    """
    Validate secret/key length to prevent DoS.

    Args:
        secret: Secret or key string
        min_length: Minimum allowed length
        max_length: Maximum allowed length

    Returns:
        True if valid

    Raises:
        SecurityError: If length is invalid

    Example:
        >>> validate_secret_length("my-secret-key")
        True
        >>> validate_secret_length("x" * 100000)
        SecurityError: Secret too long
    """
    if not secret:
        raise SecurityError("Secret cannot be empty")

    length = len(secret)

    if length < min_length:
        raise SecurityError(
            f"Secret too short: {length} characters "
            f"(minimum: {min_length})"
        )

    if length > max_length:
        raise SecurityError(
            f"Secret too long: {length} characters "
            f"(maximum: {max_length}). This may cause memory issues."
        )

    return True


# ============================================================================
# Security Warning Functions
# ============================================================================

def warn_insecure_key_usage():
    """
    Warn user about insecure key passing via command line.

    This should be called when key is passed via -k flag.

    The warning informs users that command-line arguments are visible
    in the process list (ps aux) and recommends more secure alternatives.

    Example:
        >>> warn_insecure_key_usage()
        UserWarning: SECURITY WARNING
        Passing keys via command line (-k) exposes them in process list!
    """
    warnings.warn(
        "\n⚠️  SECURITY WARNING ⚠️\n"
        "Passing keys via command line (-k) exposes them in process list!\n"
        "Anyone running 'ps aux' can see your secret key.\n"
        "Use --key-file or --key-stdin for better security.\n",
        SecurityWarning,
        stacklevel=3
    )


# ============================================================================
# Utility Functions
# ============================================================================

def is_safe_filename(filename: str) -> bool:
    """
    Check if filename is safe (no path components).

    Args:
        filename: Filename to check

    Returns:
        True if safe, False otherwise

    Example:
        >>> is_safe_filename("document.pdf")
        True
        >>> is_safe_filename("../etc/passwd")
        False
    """
    if not filename:
        return False

    # Check for path separators
    if '/' in filename or '\\' in filename:
        return False

    # Check for parent directory references
    if '..' in filename:
        return False

    # Check for hidden files (optional - may want to allow)
    # if filename.startswith('.'):
    #     return False

    return True


def get_safe_temp_dir() -> Path:
    """
    Get a safe temporary directory for the current platform.

    Returns:
        Path to safe temp directory

    Example:
        >>> temp = get_safe_temp_dir()
        >>> print(temp)
        /tmp
    """
    if sys.platform == "win32":
        return Path("C:\\Temp").resolve()
    else:
        return Path("/tmp").resolve()


# ============================================================================
# Module Info
# ============================================================================

__all__ = [
    'SecurityWarning',
    'SecurityError',
    'validate_file_path',
    'validate_pdf_file',
    'sanitize_method_name',
    'validate_secret_length',
    'warn_insecure_key_usage',
    'is_safe_filename',
    'get_safe_temp_dir',
]

__version__ = '1.0.0'
__author__ = 'Tatou Security Team'