"""base64_invisible_comment.py

Simple but non-readable watermarking method that appends a base64-encoded
payload after the PDF's final EOF marker.

The watermark is invisible to normal readers and can only be extracted
programmatically. It uses Base64 encoding for obfuscation (no encryption).

"""

from __future__ import annotations
from typing import Final
import base64

from watermarking_method import (
    WatermarkingMethod,
    load_pdf_bytes,
    SecretNotFoundError,
)


class Base64InvisibleComment(WatermarkingMethod):
    """Watermarking method that appends a base64-encoded secret after EOF."""

    name: Final[str] = "b64-comment-eof"
    _MAGIC: Final[bytes] = b"\n%%WM-B64:v1\n"

    @staticmethod
    def get_usage() -> str:
        return "Appends base64-encoded secret after EOF. Key/position ignored. Lightly obfuscated."

    def add_watermark(
        self, pdf, secret: str, key: str, position: str | None = None
    ) -> bytes:
        """Embed base64-encoded secret after EOF marker."""
        if not secret:
            raise ValueError("Secret must be non-empty")

        data = load_pdf_bytes(pdf)
        encoded = base64.b64encode(secret.encode("utf-8"))

        # Always ensure newline before appending
        if not data.endswith(b"\n"):
            data += b"\n"

        out = data + self._MAGIC + encoded + b"\n"
        return out

    def is_watermark_applicable(self, pdf, position: str | None = None) -> bool:
        """Applicable to any valid PDF."""
        try:
            load_pdf_bytes(pdf)
            return True
        except Exception:
            return False

    def read_secret(self, pdf, key: str) -> str:
        """Extract and decode base64-encoded secret."""
        data = load_pdf_bytes(pdf)
        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No Base64 watermark found")

        start = idx + len(self._MAGIC)
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_data = data[start:end].strip()

        if not b64_data:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            decoded = base64.b64decode(b64_data)
            return decoded.decode("utf-8")
        except Exception as e:
            raise SecretNotFoundError("Malformed base64 watermark") from e


__all__ = ["Base64InvisibleComment"]
