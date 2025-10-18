"""
Command-line interface for PDF watermarking.

Usage:
    watermarking_cli.py methods
    watermarking_cli.py explore <input>
    watermarking_cli.py embed -m <method> -s <secret> -k <key> <input> <output>
    watermarking_cli.py extract -m <method> -k <key> <input>
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

# Import watermarking utilities
from watermarking_utils import (
    METHODS,
    apply_watermark,
    read_watermark,
    explore_pdf,
    is_watermarking_applicable
)

# Import security utilities
from security_utils import (
    validate_file_path,
    validate_pdf_file,
    sanitize_method_name,
    validate_secret_length,
    warn_insecure_key_usage,
    SecurityError
)


def _read_text_from_file(filepath: str) -> str:
    """
    Read text content from a file securely.

    Args:
        filepath: Path to the file

    Returns:
        File contents as string

    Raises:
        FileNotFoundError: If file doesn't exist
        SecurityError: If path is invalid
    """
    # Validate path first
    path = validate_file_path(filepath, must_exist=True, allow_write=False)

    try:
        with path.open('r', encoding='utf-8') as f:
            content = f.read()
        return content
    except (OSError, PermissionError) as e:
        raise SecurityError(f"Cannot read file {filepath}: {e}")


def _read_text_from_stdin() -> str:
    """
    Read text from standard input.

    Returns:
        Text from stdin
    """
    return sys.stdin.read()


def _resolve_secret(args: argparse.Namespace) -> str:
    """
    Resolve secret from command line arguments.

    Priority: direct arg > file > stdin

    Args:
        args: Parsed command line arguments

    Returns:
        Secret string

    Raises:
        ValueError: If no secret provided
        SecurityError: If secret is invalid
    """
    secret = None

    if hasattr(args, 'secret') and args.secret is not None:
        secret = args.secret
    elif hasattr(args, 'secret_file') and args.secret_file is not None:
        secret = _read_text_from_file(args.secret_file).strip("\n\r")
    elif hasattr(args, 'secret_stdin') and args.secret_stdin:
        secret = _read_text_from_stdin().strip("\n\r")

    if secret is None:
        raise ValueError(
            "No secret provided. "
            "Use -s, --secret-file, or --secret-stdin"
        )

    # Validate secret length
    validate_secret_length(secret, min_length=1, max_length=10000)

    return secret


def _resolve_key(args: argparse.Namespace) -> str:
    """
    Resolve encryption key from command line arguments securely.

    Priority: direct arg > file > stdin > prompt

    Args:
        args: Parsed command line arguments

    Returns:
        Key string

    Raises:
        ValueError: If no key provided
        SecurityError: If key is invalid
    """
    key = None

    if hasattr(args, 'key') and args.key is not None:
        # Warn about insecure usage
        warn_insecure_key_usage()
        key = args.key
    elif hasattr(args, 'key_file') and args.key_file is not None:
        key = _read_text_from_file(args.key_file).strip("\n\r")
    elif hasattr(args, 'key_stdin') and args.key_stdin:
        key = _read_text_from_stdin().strip("\n\r")
    elif hasattr(args, 'key_prompt') and args.key_prompt:
        import getpass
        key = getpass.getpass("Enter encryption key: ")

    if key is None:
        raise ValueError(
            "No key provided. "
            "Use -k, --key-file, --key-stdin, or --key-prompt"
        )

    # Validate key length
    validate_secret_length(key, min_length=1, max_length=10000)

    return key


def cmd_methods(args: argparse.Namespace) -> int:
    """
    List available watermarking methods.

    Args:
        args: Command line arguments (unused)

    Returns:
        Exit code (0 for success)
    """
    print("Available watermarking methods:")
    for method_name in METHODS.keys():
        print(f"  - {method_name}")
    return 0


def cmd_explore(args: argparse.Namespace) -> int:
    """
    Explore PDF structure securely.

    Args:
        args: Command line arguments with 'input' attribute

    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Validate input path
        input_path = validate_file_path(args.input, must_exist=True, allow_write=False)

        # Validate it's a PDF
        validate_pdf_file(input_path)

        print(f"Exploring PDF: {input_path}")
        info = explore_pdf(input_path)

        print("\nPDF Information:")
        for key, value in info.items():
            print(f"  {key}: {value}")

        print("\nApplicable methods:")
        for method_name in METHODS.keys():
            applicable = is_watermarking_applicable(
                method=method_name,
                pdf=input_path,
                position=None
            )
            status = "✓" if applicable else "✗"
            print(f"  {status} {method_name}")

        return 0

    except (SecurityError, FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


def cmd_embed(args: argparse.Namespace) -> int:
    """
    Embed watermark into PDF securely.

    Args:
        args: Command line arguments

    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Sanitize method name
        method = sanitize_method_name(args.method)

        # Validate paths
        input_path = validate_file_path(args.input, must_exist=True, allow_write=False)
        output_path = validate_file_path(args.output, must_exist=False, allow_write=True)

        # Validate input is a PDF
        validate_pdf_file(input_path, max_size_mb=100)

        # Get key and secret securely
        key = _resolve_key(args)
        secret = _resolve_secret(args)

        # Get position if specified
        position = args.position if hasattr(args, 'position') else None

        # Check if method is applicable
        if not is_watermarking_applicable(
            method=method,
            pdf=input_path,
            position=position
        ):
            print(
                f"Error: Method '{method}' is not applicable to this PDF",
                file=sys.stderr
            )
            return 1

        print(f"Embedding watermark using method: {method}")

        # Apply watermark
        watermarked = apply_watermark(
            method=method,
            pdf=input_path,
            secret=secret,
            key=key,
            position=position
        )

        # Write output safely
        output_path.write_bytes(watermarked)

        print(f"✓ Watermarked PDF written to: {output_path}")
        return 0

    except (SecurityError, FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def cmd_extract(args: argparse.Namespace) -> int:
    """
    Extract watermark from PDF securely.

    Args:
        args: Command line arguments

    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Sanitize method name
        method = sanitize_method_name(args.method)

        # Validate path
        input_path = validate_file_path(args.input, must_exist=True, allow_write=False)

        # Validate input is a PDF
        validate_pdf_file(input_path, max_size_mb=100)

        # Get key securely
        key = _resolve_key(args)

        print(f"Extracting watermark using method: {method}")

        # Read watermark
        secret = read_watermark(
            method=method,
            pdf=input_path,
            key=key
        )

        print(f"Extracted secret: {secret}")
        return 0

    except (SecurityError, FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


def _build_parser() -> argparse.ArgumentParser:
    """
    Build argument parser for CLI.

    Returns:
        Configured ArgumentParser
    """
    parser = argparse.ArgumentParser(
        description="PDF Watermarking CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Methods command
    subparsers.add_parser('methods', help='List available watermarking methods')

    # Explore command
    explore_parser = subparsers.add_parser('explore', help='Explore PDF structure')
    explore_parser.add_argument('input', help='Input PDF file')

    # Embed command
    embed_parser = subparsers.add_parser('embed', help='Embed watermark')
    embed_parser.add_argument('input', help='Input PDF file')
    embed_parser.add_argument('output', help='Output PDF file')
    embed_parser.add_argument('-m', '--method', required=True, help='Watermarking method')
    embed_parser.add_argument('-s', '--secret', help='Secret to embed')
    embed_parser.add_argument('--secret-file', help='Read secret from file (secure)')
    embed_parser.add_argument('--secret-stdin', action='store_true', help='Read secret from stdin')
    embed_parser.add_argument('-k', '--key', help='Encryption key (WARNING: visible in ps)')
    embed_parser.add_argument('--key-file', help='Read key from file (secure)')
    embed_parser.add_argument('--key-stdin', action='store_true', help='Read key from stdin')
    embed_parser.add_argument('--key-prompt', action='store_true', help='Prompt for key')
    embed_parser.add_argument('-p', '--position', help='Position for watermark')

    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract watermark')
    extract_parser.add_argument('input', help='Input PDF file')
    extract_parser.add_argument('-m', '--method', required=True, help='Watermarking method')
    extract_parser.add_argument('-k', '--key', help='Encryption key (WARNING: visible in ps)')
    extract_parser.add_argument('--key-file', help='Read key from file (secure)')
    extract_parser.add_argument('--key-stdin', action='store_true', help='Read key from stdin')
    extract_parser.add_argument('--key-prompt', action='store_true', help='Prompt for key')

    return parser


def main(argv=None) -> int:
    """
    Main entry point for CLI.

    Args:
        argv: Command line arguments (None = sys.argv)

    Returns:
        Exit code
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    # Route to appropriate command handler
    if args.command == 'methods':
        return cmd_methods(args)
    elif args.command == 'explore':
        return cmd_explore(args)
    elif args.command == 'embed':
        return cmd_embed(args)
    elif args.command == 'extract':
        return cmd_extract(args)
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())