import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main
from main import PatientCluster


class TestLinkage(unittest.TestCase):
    def setUp(self):
        self.original_secret = main.SECRET
        main.SECRET = b"linkage-test-secret"

    def tearDown(self):
        main.SECRET = self.original_secret

    def test_fr08_strong_id_linking(self):
        linker = PatientCluster()
        # Record 1 from hospital A
        linker.add_evidence("hospA:row:0", {"uhid": "SNJ/24/100", "patient_name": "Ramesh Kumar"})
        # Record 2 from hospital B with same phone
        linker.add_evidence("hospB:row:5", {"uhid": "SNJ/24/100", "patient_name": "Ramesh Kumar"})

        linker.link()

        psn1 = linker.get_pseudonym("hospA:row:0")
        psn2 = linker.get_pseudonym("hospB:row:5")
        self.assertIsNotNone(psn1)
        self.assertEqual(psn1, psn2)

    def test_fr08_contradiction_blocks_merge(self):
        linker = PatientCluster()
        # rec:1 and rec:3 belong to same male patient (corroborated)
        linker.add_evidence("rec:1", {"phone": "9876543210", "gender": "M", "age": "25"})
        linker.add_evidence("rec:3", {"phone": "9876543210", "gender": "M", "age": "25"})
        # rec:2 shares the same phone number but is a 60-year-old female (contradiction)
        linker.add_evidence("rec:2", {"phone": "9876543210", "gender": "F", "age": "60"})

        linker.link()

        c1 = linker.record_to_cluster.get("rec:1")
        c2 = linker.record_to_cluster.get("rec:2")
        self.assertIsNotNone(c1)
        self.assertNotEqual(c1, c2)

    def test_fr08_unlinked_singletons_remain_null(self):
        linker = PatientCluster()
        linker.add_evidence("rec:solo", {"patient_name": "Unique Name Without Match"})
        linker.link()

        self.assertIsNone(linker.get_pseudonym("rec:solo"))


if __name__ == "__main__":
    unittest.main()
