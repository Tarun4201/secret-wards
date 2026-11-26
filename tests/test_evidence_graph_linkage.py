"""Tier 2 Tests: Evidence-Graph Linkage with Negative Evidence (Technique 3)
Requirements: FR-08, NFR-02
"""
import unittest

from main import PatientCluster


class TestEvidenceGraphLinkage(unittest.TestCase):
    def test_fr08_different_unique_ids_must_not_link(self):
        """Two records with different Aadhaar/UHID must never merge despite matching other fields."""
        linker = PatientCluster()
        linker.add_evidence("rec:1", {
            "patient_name": "Rohan Sharma",
            "aadhaar": "123456789012",
            "phone": "9876543210",
            "age": "30",
            "gender": "M"
        })
        linker.add_evidence("rec:2", {
            "patient_name": "Rohan Sharma",
            "aadhaar": "987654321098",  # Different Aadhaar!
            "phone": "9876543210",
            "age": "30",
            "gender": "M"
        })
        linker.link()

        c1 = linker.record_to_cluster.get("rec:1")
        c2 = linker.record_to_cluster.get("rec:2")
        # Both unlinked (None) is correct — they must not share a cluster
        same_cluster = (c1 is not None and c2 is not None and c1 == c2)
        self.assertFalse(same_cluster, "Records with different Aadhaar numbers must never merge")

    def test_fr08_family_phone_trap_does_not_merge(self):
        """Family members sharing a phone with distinctly different names must NOT merge."""
        linker = PatientCluster()
        linker.add_evidence("rec:father", {
            "patient_name": "Ramesh Kumar Sharma",
            "phone": "9998887776",
            "gender": "M",
            "age": "55"
        })
        linker.add_evidence("rec:son", {
            "patient_name": "Anil Sharma",
            "phone": "9998887776",  # Shared family phone
            "gender": "M",
            "age": "22"
        })
        linker.link()

        c1 = linker.record_to_cluster.get("rec:father")
        c2 = linker.record_to_cluster.get("rec:son")
        # Both unlinked (None) is correct — they must not share a cluster
        same_cluster = (c1 is not None and c2 is not None and c1 == c2)
        self.assertFalse(same_cluster, "Family phone sharing with distinct names must not be merged")

    def test_fr08_candidate_margin_scoring_links_confident_fragment(self):
        """A fragment with high evidence score (>=0.8) and clear margin (>=0.2) joins the cluster."""
        linker = PatientCluster()
        # Seed cluster with UHID
        linker.add_evidence("rec:anchor", {
            "patient_name": "Mohammad Rizwan",
            "uhid": "UHID-2023-9999",
            "relative_name": "S/o Abdul Hamid",
            "village": "Rampur",
            "age": "42",
            "gender": "M"
        })
        linker.add_evidence("rec:anchor2", {
            "uhid": "UHID-2023-9999",
            "village": "Rampur",
            "gender": "M"
        })
        # Fragment with matching name skeleton, matching relative, matching village, matching age
        linker.add_evidence("rec:frag", {
            "patient_name": "Mohd Rizwan",  # Cross-script / abbreviation variant
            "relative_name": "S/o Abdul Hamid",
            "village": "Rampur",
            "age": "42",
            "gender": "M"
        })
        linker.link()

        c_anchor = linker.record_to_cluster.get("rec:anchor")
        c_frag = linker.record_to_cluster.get("rec:frag")
        self.assertIsNotNone(c_anchor)
        self.assertEqual(c_anchor, c_frag, "Confident fragment with high margin must join the cluster")

    def test_fr08_ambiguous_fragment_remains_null(self):
        """A weak/ambiguous fragment with low score or no clear runner-up margin stays unlinked."""
        linker = PatientCluster()
        # Two different clusters with similar partial cues
        linker.add_evidence("rec:c1", {
            "uhid": "UHID-1111",
            "patient_name": "Sita Devi",
            "village": "Sonpur"
        })
        linker.add_evidence("rec:c1_b", {
            "uhid": "UHID-1111",
            "village": "Sonpur"
        })
        linker.add_evidence("rec:c2", {
            "uhid": "UHID-2222",
            "patient_name": "Gita Devi",
            "village": "Sonpur"
        })
        linker.add_evidence("rec:c2_b", {
            "uhid": "UHID-2222",
            "village": "Sonpur"
        })
        # Ambiguous weak fragment: only "Devi" and "Sonpur", no relative, no age
        linker.add_evidence("rec:weak", {
            "patient_name": "Devi",
            "village": "Sonpur"
        })
        linker.link()

        self.assertIsNone(linker.get_pseudonym("rec:weak"), "Ambiguous weak fragment must remain unlinked (patient: null)")


if __name__ == "__main__":
    unittest.main()
