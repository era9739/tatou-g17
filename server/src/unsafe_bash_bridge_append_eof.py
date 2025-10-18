"""unsafe_bash_bridge_append_eof.py

Toy watermarking method that appends an authenticated payload *after* the
PDF's final EOF marker but by calling a bash command. Technically you could bridge
any watermarking implementation this way. Don't, unless you know how to sanitize user inputs.

"""

from __future__ import annotations

from typing import Final

from watermarking_method import (
    SecretNotFoundError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class UnsafeBashBridgeAppendEOF(WatermarkingMethod):
    """Toy method that appends a watermark record after the PDF EOF."""

    name: Final[str] = "bash-bridge-eof"

    @staticmethod
    def get_usage() -> str:
        return "Toy method that appends a watermark record after the PDF EOF. Position and key are ignored."

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` and ``key`` parameters are accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)

        # SAFE IMPLEMENTATION (for testing):
        # Simply append the secret after the PDF data
        if not data.endswith(b"\n"):
            data += b"\n"

        return data + secret.encode("utf-8")

        # UNSAFE ALTERNATIVE (commented out - demonstrates vulnerability):
        # If you were to do this, it would be vulnerable to command injection:
        # cmd = f"cat '{pdf.resolve()}' && echo -n '{secret}'"  # DANGEROUS!
        # - User could inject: secret = "`rm -rf /`"
        # - Or: secret = "'; malicious_command; echo '"
        # subprocess.run(cmd, shell=True, ...)  # NEVER DO THIS!

    def is_watermark_applicable(
        self,
        pdf,
        position: str | None = None,
    ) -> bool:
        return True

    def read_secret(self, pdf, key: str) -> str:
        """Extract the secret if present.

        Reads everything after %%EOF.
        """
        data = load_pdf_bytes(pdf)

        # Find %%EOF marker
        eof_marker = b"%%EOF"
        idx = data.rfind(eof_marker)

        if idx == -1:
            raise SecretNotFoundError("No %%EOF marker found in PDF")

        # Get everything after %%EOF
        after_eof = data[idx + len(eof_marker) :]

        # Strip newlines at the beginning (the one after %%EOF)
        secret = after_eof.lstrip(b"\n").rstrip(b"\n\r\t ")

        if not secret:
            raise SecretNotFoundError("No watermark data found after %%EOF")

        # UNSAFE ALTERNATIVE (commented out):
        # This demonstrates vulnerable subprocess usage:
        # cmd = f"tail -c +{idx + len(eof_marker) + 1} '{pdf.resolve()}'"
        # subprocess.run(cmd, shell=True, ...)  # Path injection possible!

        return secret.decode("utf-8", errors="ignore")


__all__ = ["UnsafeBashBridgeAppendEOF"]
