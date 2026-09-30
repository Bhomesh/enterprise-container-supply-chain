import unittest
from src.cosign_signer import CosignSigner

class TestCosignSigner(unittest.TestCase):
    def setUp(self):
        self.signer = CosignSigner()
        self.sample_digest = "sha256:7b1e42fa023e1e2d7e00f5763bd8e68cf6a17b2b09ef3cb535ce98926943ac33"
        self.image_ref = "intake.registry.corp/payments/core-api:1.0.0-rc1"

    def test_slsa_provenance_generation(self):
        prov = self.signer.generate_slsa_provenance(self.image_ref, self.sample_digest)
        self.assertEqual(prov["_type"], "https://in-toto.io/Statement/v0.1")
        self.assertEqual(prov["predicateType"], "https://slsa.dev/provenance/v0.2")
        self.assertEqual(prov["subject"][0]["name"], self.image_ref)
        self.assertIn("7b1e42fa023e1e2d7e00f5763bd8e68cf6a17b2b09ef3cb535ce98926943ac33", prov["subject"][0]["digest"]["sha256"])

    def test_sign_and_verify(self):
        sig = self.signer.sign_digest(self.image_ref, self.sample_digest)
        self.assertEqual(sig["status"], "SIGNED_AND_ATTESTED")
        self.assertTrue(self.signer.verify_signature(sig))

if __name__ == "__main__":
    unittest.main()
