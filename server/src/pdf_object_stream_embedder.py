import zlib
from watermarking_method import (
    WatermarkingMethod,
    load_pdf_bytes,
    SecretNotFoundError,
)

class PdfObjectStreamEmbedder(WatermarkingMethod):

    name = "pdf-object-stream-embedder"
    _OBJ_ID = 9999  # Arbitrary high number

    @staticmethod
    def get_usage() -> str:
        return "Embeds secret in a compressed, unreferenced object stream near EOF. Key/position ignored."

    def add_watermark(self, pdf, secret: str, key: str, position: str | None = None) -> bytes:
        if not secret:
            raise ValueError("Secret must be non-empty")
        data = load_pdf_bytes(pdf)
        compressed = zlib.compress(secret.encode("utf-8"))
        stream = (
            f"\n{self._OBJ_ID} 0 obj\n"
            f"<< /Length {len(compressed)} >>\n"
            f"stream\n"
        ).encode("utf-8") + compressed + b"\nendstream\nendobj\n"
        return data + stream

    def is_watermark_applicable(self, pdf, position: str | None = None) -> bool:
        try:
            load_pdf_bytes(pdf)
            return True
        except Exception:
            return False

    def read_secret(self, pdf, key: str) -> str:
        data = load_pdf_bytes(pdf)
        marker = f"{self._OBJ_ID} 0 obj".encode("utf-8")
        idx = data.find(marker)
        if idx == -1:
            raise SecretNotFoundError("No hidden object stream found")
        start = data.find(b"stream\n", idx) + len("stream\n")
        end = data.find(b"\nendstream", start)
        compressed = data[start:end]
        try:
            return zlib.decompress(compressed).decode("utf-8")
        except Exception as e:
            raise SecretNotFoundError("Failed to decompress hidden stream") from e
