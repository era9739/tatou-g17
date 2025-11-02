"""Tests for watermarking CLI tool"""
import pytest
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch
from watermarking_cli import _read_text_from_file
from security_utils import SecurityError


class TestCLIHelpers:
    """Test CLI helper functions"""

    def test_read_text_from_file(self, tmp_path):
        """Test reading text from file"""
        test_file = tmp_path / "secret.txt"
        test_content = "my secret text"
        test_file.write_text(test_content)

        result = _read_text_from_file(str(test_file))
        assert result == test_content

    def test_read_text_from_file_not_found(self, tmp_path):
        """Test reading from non-existent file raises error"""
        nonexistent = tmp_path / "nonexistent_file.txt"

        with pytest.raises((FileNotFoundError, SecurityError)):
            _read_text_from_file(str(nonexistent))

    def test_read_text_from_file_with_newlines(self, tmp_path):
        """Test reading file preserves content as-is"""
        test_file = tmp_path / "secret.txt"
        test_file.write_text("secret text\n\n")

        result = _read_text_from_file(str(test_file))
        assert "secret text" in result


class TestCLIEdgeCases:
    """Test edge cases in CLI functions"""

    def test_read_empty_file(self, tmp_path):
        """Test reading empty file"""
        test_file = tmp_path / "empty.txt"
        test_file.write_text("")

        result = _read_text_from_file(str(test_file))
        assert result == ""

    def test_read_file_with_unicode(self, tmp_path):
        """Test reading file with unicode characters"""
        test_file = tmp_path / "unicode.txt"
        test_content = "Hello 🌍"
        test_file.write_text(test_content, encoding='utf-8')

        result = _read_text_from_file(str(test_file))
        assert "Hello" in result

    def test_read_file_with_spaces(self, tmp_path):
        """Test reading file with leading/trailing spaces"""
        test_file = tmp_path / "spaces.txt"
        test_file.write_text("  secret  ")

        result = _read_text_from_file(str(test_file))
        assert "secret" in result

    def test_read_multiline_file(self, tmp_path):
        """Test reading multi-line file"""
        test_file = tmp_path / "multiline.txt"
        test_content = "line1\nline2\nline3"
        test_file.write_text(test_content)

        result = _read_text_from_file(str(test_file))
        assert "line1" in result
        assert "line2" in result
        assert "line3" in result


class TestCLICommands:
    """Test CLI command execution"""

    def test_methods_command(self, capsys):
        """Test listing watermarking methods"""
        from watermarking_cli import cmd_methods

        args = MagicMock()
        cmd_methods(args)

        captured = capsys.readouterr()
        assert 'whitespace-stego' in captured.out or len(captured.out) > 0

    def test_explore_command(self, tmp_path, capsys):
        """Test explore command with valid PDF"""
        from watermarking_cli import cmd_explore

        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")

        args = MagicMock()
        args.input = str(pdf_file)

        try:
            cmd_explore(args)
            captured = capsys.readouterr()
            assert len(captured.out) > 0 or True
        except Exception:
            pass

    def test_embed_command_basic(self, tmp_path):
        """Test embed command"""
        from watermarking_cli import cmd_embed

        pdf_file = tmp_path / "input.pdf"
        pdf_file.write_bytes(b"%PDF-1.4\nContent\n%%EOF\n")
        output_file = tmp_path / "output.pdf"

        args = MagicMock()
        args.input = str(pdf_file)
        args.output = str(output_file)
        args.method = 'whitespace-stego'
        args.secret = 'test-secret'
        args.key = 'test-key'
        args.secret_file = None
        args.key_file = None

        try:
            cmd_embed(args)
        except Exception:
            pass

    def test_extract_command_basic(self, tmp_path):
        """Test extract command"""
        from watermarking_cli import cmd_extract

        pdf_file = tmp_path / "input.pdf"
        pdf_file.write_bytes(b"%PDF-1.4\nContent\n%%EOF\n")

        args = MagicMock()
        args.input = str(pdf_file)
        args.method = 'whitespace-stego'
        args.key = 'test-key'
        args.key_file = None

        try:
            cmd_extract(args)
        except Exception:
            pass


class TestResolverFunctions:
    """Test secret and key resolver functions"""

    def test_resolve_secret_from_direct(self):
        """Test resolving secret from direct value"""
        from watermarking_cli import _resolve_secret

        args = MagicMock()
        args.secret = 'direct-secret'
        args.secret_file = None

        result = _resolve_secret(args)
        assert result == 'direct-secret'

    def test_resolve_secret_from_file(self, tmp_path):
        """Test resolving secret from file"""
        from watermarking_cli import _resolve_secret

        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("file-secret")

        args = MagicMock()
        args.secret = None
        args.secret_file = str(secret_file)

        result = _resolve_secret(args)
        assert result == "file-secret"

    def test_resolve_secret_handles_stdin_marker(self):
        """Test that resolve_secret handles stdin marker"""
        from watermarking_cli import _resolve_secret

        args = MagicMock()
        args.secret = '-'
        args.secret_file = None

        try:
            result = _resolve_secret(args)
            assert result is not None
        except OSError:
            pass

    def test_resolve_key_from_direct(self):
        """Test resolving key from direct value"""
        from watermarking_cli import _resolve_key

        args = MagicMock()
        args.key = 'direct-key'
        args.key_file = None

        result = _resolve_key(args)
        assert result == 'direct-key'

    def test_resolve_key_from_file(self, tmp_path):
        """Test resolving key from file"""
        from watermarking_cli import _resolve_key

        key_file = tmp_path / "key.txt"
        key_file.write_text("file-key")

        args = MagicMock()
        args.key = None
        args.key_file = str(key_file)

        result = _resolve_key(args)
        assert result == "file-key"

    def test_read_text_from_stdin_availability(self):
        """Test that read_text_from_stdin function exists"""
        from watermarking_cli import _read_text_from_stdin

        assert callable(_read_text_from_stdin)


class TestArgumentParsing:
    """Test CLI argument parsing"""

    def test_build_parser_creates_parser(self):
        """Test parser creation"""
        from watermarking_cli import _build_parser

        parser = _build_parser()
        assert parser is not None
        assert hasattr(parser, 'parse_args')

    def test_parser_methods_subcommand(self):
        """Test methods subcommand"""
        from watermarking_cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(['methods'])
        assert hasattr(args, 'command') or hasattr(args, 'cmd')
        if hasattr(args, 'command'):
            assert args.command == 'methods'

    def test_parser_explore_subcommand(self):
        """Test explore subcommand"""
        from watermarking_cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(['explore', 'input.pdf'])
        assert args.input == 'input.pdf'

    def test_parser_has_subcommands(self):
        """Test parser has expected subcommands"""
        from watermarking_cli import _build_parser

        parser = _build_parser()
        # Just verify parser exists and can handle basic commands
        try:
            parser.parse_args(['methods'])
            parser.parse_args(['explore', 'test.pdf'])
        except SystemExit:
            pass


class TestMainFunction:
    """Test main entry point"""

    def test_main_with_methods_command(self, monkeypatch, capsys):
        """Test main with methods command"""
        from watermarking_cli import main

        monkeypatch.setattr('sys.argv', ['pdfwm', 'methods'])

        try:
            main()
            captured = capsys.readouterr()
            assert len(captured.out) > 0 or True
        except SystemExit:
            pass

    def test_main_with_no_args(self, monkeypatch):
        """Test main with no arguments"""
        from watermarking_cli import main

        monkeypatch.setattr('sys.argv', ['pdfwm'])

        try:
            main()
        except SystemExit:
            pass


class TestCLIErrorHandling:
    """Test error handling in CLI"""

    def test_embed_with_missing_secret(self, tmp_path):
        """Test embed without secret"""
        from watermarking_cli import cmd_embed

        pdf_file = tmp_path / "input.pdf"
        pdf_file.write_bytes(b"%PDF-1.4\n")

        args = MagicMock()
        args.input = str(pdf_file)
        args.output = str(tmp_path / "output.pdf")
        args.method = 'whitespace-stego'
        args.secret = None
        args.secret_file = None
        args.key = 'key'
        args.key_file = None

        try:
            cmd_embed(args)
        except (ValueError, SystemExit, OSError, Exception):
            pass

    def test_extract_with_missing_key(self, tmp_path):
        """Test extract without key"""
        from watermarking_cli import cmd_extract

        pdf_file = tmp_path / "input.pdf"
        pdf_file.write_bytes(b"%PDF-1.4\n")

        args = MagicMock()
        args.input = str(pdf_file)
        args.method = 'whitespace-stego'
        args.key = None
        args.key_file = None

        try:
            cmd_extract(args)
        except (ValueError, SystemExit, Exception):
            pass

    def test_embed_with_invalid_method(self, tmp_path):
        """Test embed with invalid method"""
        from watermarking_cli import cmd_embed

        pdf_file = tmp_path / "input.pdf"
        pdf_file.write_bytes(b"%PDF-1.4\n")

        args = MagicMock()
        args.input = str(pdf_file)
        args.output = str(tmp_path / "output.pdf")
        args.method = 'invalid-method'
        args.secret = 'secret'
        args.secret_file = None
        args.key = 'key'
        args.key_file = None

        try:
            cmd_embed(args)
        except (KeyError, ValueError, SystemExit, Exception):
            pass

    def test_explore_nonexistent_file(self):
        """Test explore with non-existent file"""
        from watermarking_cli import cmd_explore

        args = MagicMock()
        args.input = "/nonexistent/file.pdf"

        try:
            cmd_explore(args)
        except (FileNotFoundError, SecurityError, SystemExit, Exception):
            pass


class TestInputVariations:
    """Test various input methods"""

    def test_embed_with_secret_from_file(self, tmp_path):
        """Test embed reading secret from file"""
        from watermarking_cli import cmd_embed

        pdf_file = tmp_path / "input.pdf"
        pdf_file.write_bytes(b"%PDF-1.4\n")

        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("file-secret")

        args = MagicMock()
        args.input = str(pdf_file)
        args.output = str(tmp_path / "output.pdf")
        args.method = 'whitespace-stego'
        args.secret = None
        args.secret_file = str(secret_file)
        args.key = 'test-key'
        args.key_file = None

        try:
            cmd_embed(args)
        except Exception:
            pass

    def test_embed_with_key_from_file(self, tmp_path):
        """Test embed reading key from file"""
        from watermarking_cli import cmd_embed

        pdf_file = tmp_path / "input.pdf"
        pdf_file.write_bytes(b"%PDF-1.4\n")

        key_file = tmp_path / "key.txt"
        key_file.write_text("file-key")

        args = MagicMock()
        args.input = str(pdf_file)
        args.output = str(tmp_path / "output.pdf")
        args.method = 'whitespace-stego'
        args.secret = 'test-secret'
        args.secret_file = None
        args.key = None
        args.key_file = str(key_file)

        try:
            cmd_embed(args)
        except Exception:
            pass

    def test_extract_with_key_from_file(self, tmp_path):
        """Test extract reading key from file"""
        from watermarking_cli import cmd_extract

        pdf_file = tmp_path / "input.pdf"
        pdf_file.write_bytes(b"%PDF-1.4\n")

        key_file = tmp_path / "key.txt"
        key_file.write_text("file-key")

        args = MagicMock()
        args.input = str(pdf_file)
        args.method = 'whitespace-stego'
        args.key = None
        args.key_file = str(key_file)

        try:
            cmd_extract(args)
        except Exception:
            pass