"""Tier 1 Tests: FHIR R4 Serialization & Reference Resolution
Requirements: FR-01, FR-12, FR-13
"""
import json
import unittest

from main import PatientCluster, process_json


class TestFHIRSerialization(unittest.TestCase):
    def test_fr12_fhir_bundle_sanitization_and_structure(self):
        """FHIR R4 Bundle retains its valid structure, loc is doc, and patient references resolve."""
        bundle = {
            "resourceType": "Bundle",
            "type": "collection",
            "entry": [
                {
                    "fullUrl": "urn:uuid:patient-1",
                    "resource": {
                        "resourceType": "Patient",
                        "id": "pat-raw-123",
                        "name": [{"family": "Verma", "given": ["Rakesh"]}],
                        "telecom": [{"system": "phone", "value": "9876543210"}],
                        "gender": "male",
                        "birthDate": "1975-06-20",
                        "address": [{"city": "Varanasi", "postalCode": "221001"}]
                    }
                },
                {
                    "fullUrl": "urn:uuid:cond-1",
                    "resource": {
                        "resourceType": "Condition",
                        "code": {
                            "coding": [{"system": "http://snomed.info/sct", "code": "38341003", "display": "Hypertension"}]
                        },
                        "subject": {"reference": "Patient/pat-raw-123"}
                    }
                }
            ]
        }

        records = []
        linker = PatientCluster()
        out = process_json(json.dumps(bundle), "fhir_bundle.json", records, linker)

        # 1. Locator must be "doc" for FHIR Bundle
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["loc"], "doc")
        self.assertEqual(records[0]["file"], "sanitized/fhir_bundle.json")

        parsed = json.loads(out)
        self.assertEqual(parsed["resourceType"], "Bundle")
        self.assertEqual(len(parsed["entry"]), 2)

        # 2. Patient identifiers redacted
        pat_res = parsed["entry"][0]["resource"]
        self.assertEqual(pat_res["name"][0]["given"][0], "[PATIENT_NAME]")
        self.assertEqual(pat_res["name"][0]["family"], "[PATIENT_NAME]")
        self.assertEqual(pat_res["telecom"][0]["value"], "[PHONE]")

        # 3. Clinical condition preserved
        cond_res = parsed["entry"][1]["resource"]
        self.assertEqual(cond_res["code"]["coding"][0]["display"], "Hypertension")


if __name__ == "__main__":
    unittest.main()
