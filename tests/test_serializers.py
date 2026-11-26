import csv
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import PatientCluster, process_csv, process_json


class TestSerializers(unittest.TestCase):
    def test_fr12_fr13_csv_locators_and_structure(self):
        csv_text = "id,name,diagnosis\n1,Ramesh,Fever\n2,Suresh,Cough\n"
        records = []
        linker = PatientCluster()
        out = process_csv(csv_text, ",", "test.csv", records, linker)

        self.assertEqual(len(records), 2)
        # First data row is row:0 per PRD FR-13
        self.assertEqual(records[0]["loc"], "row:0")
        self.assertEqual(records[1]["loc"], "row:1")
        self.assertEqual(records[0]["file"], "sanitized/test.csv")

        # Delimiter preserved
        rows = list(csv.reader(io.StringIO(out)))
        self.assertEqual(len(rows), 3)  # header + 2 rows
        self.assertEqual(rows[0], ["id", "name", "diagnosis"])
        self.assertEqual(rows[1][2], "Fever")

    def test_fr12_tsv_delimiter_preserved(self):
        tsv_text = "id\tname\tdiagnosis\n10\tAnita\tHeadache\n"
        records = []
        linker = PatientCluster()
        out = process_csv(tsv_text, "\t", "data.tsv", records, linker)

        self.assertIn("\t", out)
        rows = list(csv.reader(io.StringIO(out), delimiter="\t"))
        self.assertEqual(rows[0], ["id", "name", "diagnosis"])
        self.assertEqual(rows[1][0], "10")
        self.assertEqual(rows[1][2], "Headache")

    def test_fr12_fr13_json_structure_and_locators(self):
        json_data = {
            "hospital": "Sanjeevani",
            "patients": [
                {"patient_name": "Priya", "disease": "Malaria"},
                {"patient_name": "Sunita", "disease": "Dengue"}
            ]
        }
        json_text = json.dumps(json_data)
        records = []
        linker = PatientCluster()
        out = process_json(json_text, "patients.json", records, linker)

        parsed = json.loads(out)
        self.assertEqual(parsed["hospital"], "Sanjeevani")
        self.assertEqual(parsed["patients"][0]["disease"], "Malaria")
        self.assertEqual(parsed["patients"][1]["disease"], "Dengue")

        # Locators must be JSON Pointers
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["loc"], "/patients/0")
        self.assertEqual(records[1]["loc"], "/patients/1")


if __name__ == "__main__":
    unittest.main()
