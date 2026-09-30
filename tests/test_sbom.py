import json
import os
import unittest
from src.sbom_generator import SBOMGenerator

class TestSBOMGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = SBOMGenerator()
        self.fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "sample_cyclonedx.json")

    def test_load_fixture_sbom(self):
        with open(self.fixture_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertTrue(self.generator.validate_sbom(data))
        self.assertEqual(len(data["components"]), 3)

    def test_synthetic_sbom_generation(self):
        sbom = self.generator.generate("test.registry/app:latest")
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.5")
        self.assertTrue(len(sbom["components"]) >= 2)
        self.assertTrue(self.generator.validate_sbom(sbom))

    def test_invalid_sbom_format(self):
        with self.assertRaises(ValueError):
            self.generator.validate_sbom({"bomFormat": "InvalidFormat"})

if __name__ == "__main__":
    unittest.main()
