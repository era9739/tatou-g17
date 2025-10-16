import unittest
from server.src.pdf_object_stream_embedder import PdfObjectStreamEmbedder
from server.src.watermarking_method import SecretNotFoundError


class TestPdfObjectStreamEmbedder(unittest.TestCase):
    def setUp(self):
        self.embedder = PdfObjectStreamEmbedder()
        self.sample_pdf = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
        self.secret = "This secret"  # ✅ Updated secret
        self.key = "unused-key"

    def test_add_and_read_watermark(self):
        watermarked_pdf = self.embedder.add_watermark(self.sample_pdf, self.secret, self.key)
        extracted = self.embedder.read_secret(watermarked_pdf, self.key)
        self.assertEqual(extracted, self.secret)

    def test_read_secret_failure(self):
        with self.assertRaises(SecretNotFoundError):
            self.embedder.read_secret(self.sample_pdf, self.key)

    def test_is_watermark_applicable(self):
        self.assertTrue(self.embedder.is_watermark_applicable(self.sample_pdf))

    def test_get_usage(self):
        usage = self.embedder.get_usage()
        self.assertIn("Embeds secret", usage)

if __name__ == "__main__":
    unittest.main()
