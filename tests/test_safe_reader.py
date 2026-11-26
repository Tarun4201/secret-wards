import sys
import unittest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import decode


class TestSafeReader(unittest.TestCase):
    def test_fr01_utf8_decoding(self):
        raw = "Hello world, नमस्ते".encode()
        self.assertEqual(decode(raw), "Hello world, नमस्ते")

    def test_fr01_utf8_bom_decoding(self):
        raw = b"\xef\xbb\xbfPatient Data"
        self.assertEqual(decode(raw), "Patient Data")

    def test_fr01_utf16_le_decoding(self):
        raw = "Medical Record".encode("utf-16-le")
        self.assertEqual(decode(raw), "Medical Record")

    def test_fr01_utf16_be_decoding(self):
        raw = "Hospital Summary".encode("utf-16-be")
        self.assertEqual(decode(raw), "Hospital Summary")

    def test_fr01_cp1252_decoding(self):
        raw = "Doctor’s Note".encode("cp1252")
        self.assertIsNotNone(decode(raw))


if __name__ == "__main__":
    unittest.main()
