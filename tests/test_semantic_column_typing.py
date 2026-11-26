"""Tier 2/3 Tests: Semantic Column Typing for Unseen Formats (Technique 6)
Requirements: FR-03, FR-12
"""
import unittest

from main import PatientCluster, infer_column_type_from_values, process_csv


class TestSemanticColumnTyping(unittest.TestCase):
    def test_infer_phone_column_from_values(self):
        """Unseen header with phone numbers is inferred as PHONE."""
        values = ["9876543210", "9811223344", "+91 9988776655", "8765432109"]
        col_type = infer_column_type_from_values(values)
        self.assertEqual(col_type, "PHONE")

    def test_infer_aadhaar_column_from_values(self):
        """Unseen header with Aadhaar numbers is inferred as AADHAAR."""
        values = ["2345 6789 0123", "3456 7890 1234", "4567 8901 2345"]
        col_type = infer_column_type_from_values(values)
        self.assertEqual(col_type, "AADHAAR")

    def test_infer_name_column_from_values(self):
        """Unseen header with Indian names is inferred as PATIENT_NAME."""
        values = ["Ramesh Kumar", "Sita Devi", "Abdul Hamid", "Priya Sharma"]
        col_type = infer_column_type_from_values(values)
        self.assertEqual(col_type, "PATIENT_NAME")

    def test_safe_clinical_column_remains_none(self):
        """Clinical numerical lab values are not misclassified as PII."""
        values = ["120/80", "130/85", "110/70", "125/82"]
        col_type = infer_column_type_from_values(values)
        self.assertIsNone(col_type)

    def test_unseen_header_in_csv_is_sanitized_via_inference(self):
        """CSV with completely unknown header names (e.g. fld_1, fld_2) has PII columns sanitized."""
        linker = PatientCluster()
        records = []
        raw_csv = (
            "fld_1,fld_2,clinical_note\n"
            "9876543210,Ramesh Kumar,Normal sinus rhythm\n"
            "9811223344,Priya Sharma,Fever resolved\n"
            "8877665544,Abdul Hamid,BP 120/80\n"
        )

        sanitized = process_csv(raw_csv, ",", "unseen.csv", records, linker)

        # Phone numbers should be redacted
        self.assertNotIn("9876543210", sanitized)
        # Names should be redacted
        self.assertNotIn("Ramesh Kumar", sanitized)
        # Clinical values preserved
        self.assertIn("Normal sinus rhythm", sanitized)
        self.assertIn("BP 120/80", sanitized)


if __name__ == "__main__":
    unittest.main()
