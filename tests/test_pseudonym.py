import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main


class TestPseudonym(unittest.TestCase):
    def setUp(self):
        self.original_secret = main.SECRET

    def tearDown(self):
        main.SECRET = self.original_secret

    def test_fr09_pseudonym_format(self):
        main.SECRET = b"secret-alpha"
        psn = main.pseudonym("patient-12345")
        self.assertTrue(psn.startswith("PSN-"))
        self.assertEqual(len(psn), 10)  # PSN- + 6 base32 chars

    def test_nfr02_determinism_same_secret(self):
        main.SECRET = b"fixed-key-1"
        psn1 = main.pseudonym("cluster-abc")
        psn2 = main.pseudonym("cluster-abc")
        self.assertEqual(psn1, psn2)

    def test_nfr02_different_secret_changes_pseudonym(self):
        main.SECRET = b"secret-one"
        psn1 = main.pseudonym("cluster-abc")
        main.SECRET = b"secret-two"
        psn2 = main.pseudonym("cluster-abc")
        self.assertNotEqual(psn1, psn2)

    def test_nfr03_secret_not_in_pseudonym(self):
        secret_bytes = b"super-confidential-raksha-token"
        main.SECRET = secret_bytes
        psn = main.pseudonym("patient-cluster-x")
        self.assertNotIn("confidential", psn)
        self.assertNotIn(secret_bytes.decode(), psn)


if __name__ == "__main__":
    unittest.main()
