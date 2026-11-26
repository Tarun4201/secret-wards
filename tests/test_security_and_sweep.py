import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestSecurityAndSweep(unittest.TestCase):
    def test_nfr01_dependency_guard_no_llms_in_requirements(self):
        req_path = Path(__file__).resolve().parent.parent / "requirements.txt"
        content = req_path.read_text().lower()
        banned = ["openai", "anthropic", "langchain", "transformers", "torch", "huggingface", "llama", "mistral"]
        for b in banned:
            self.assertNotIn(b, content, f"Banned LLM dependency found: {b}")

    def test_nfr01_dependency_guard_no_llm_imports_in_main(self):
        main_path = Path(__file__).resolve().parent.parent / "main.py"
        content = main_path.read_text().lower()
        banned = ["import openai", "import anthropic", "import langchain", "import transformers", "import torch"]
        for b in banned:
            self.assertNotIn(b, content, f"Banned import found in main.py: {b}")


if __name__ == "__main__":
    unittest.main()
