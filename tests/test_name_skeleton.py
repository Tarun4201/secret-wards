import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import name_skeleton


class TestNameSkeleton(unittest.TestCase):
    def test_fr04_fr08_cross_script_mohammad_variants(self):
        # Mohammad, Mohd, Md., मोहम्मद must produce the same skeleton key
        k1 = name_skeleton("Mohammad")
        k2 = name_skeleton("Mohd.")
        k3 = name_skeleton("Md.")
        k4 = name_skeleton("मोहम्मद")

        self.assertEqual(k1, k2)
        self.assertEqual(k1, k3)
        self.assertEqual(k1, k4)

    def test_fr04_honorifics_stripped(self):
        k1 = name_skeleton("Ramesh Kumar Ji")
        k2 = name_skeleton("Shri Ramesh Kumar")
        k3 = name_skeleton("Ramesh Kumar")
        self.assertEqual(k1, k3)
        self.assertEqual(k2, k3)

    def test_fr04_different_names_do_not_collide(self):
        k1 = name_skeleton("Ramesh")
        k2 = name_skeleton("Suresh")
        self.assertNotEqual(k1, k2)


if __name__ == "__main__":
    unittest.main()
