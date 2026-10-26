import os
import unittest
import warnings

from blackwall_llm_shield.core import (
    AgentIdentityRegistry,
    AuditTrail,
    classify_identifiers,
    is_valid_au_abn,
    is_valid_au_medicare,
    is_valid_au_tfn,
    is_valid_nz_ird,
    is_valid_nzbn,
    mask_text,
)


class ChecksumTests(unittest.TestCase):
    def test_nz_ird_published_test_numbers(self):
        self.assertTrue(is_valid_nz_ird("49-091-850"))
        self.assertTrue(is_valid_nz_ird("136-410-132"))
        self.assertTrue(is_valid_nz_ird("49091850"))

    def test_nz_ird_rejects_bad_checksums_and_out_of_range(self):
        self.assertFalse(is_valid_nz_ird("123-456-789"))
        self.assertFalse(is_valid_nz_ird("9-999-999"))
        self.assertFalse(is_valid_nz_ird("200-000-000"))

    def test_au_tfn_and_medicare(self):
        self.assertTrue(is_valid_au_tfn("123 456 782"))
        self.assertFalse(is_valid_au_tfn("123 456 789"))
        self.assertTrue(is_valid_au_medicare("2123 45670 1"))
        self.assertFalse(is_valid_au_medicare("2423 51673 1"))

    def test_business_identifiers(self):
        self.assertTrue(is_valid_au_abn("51 824 753 556"))
        self.assertFalse(is_valid_au_abn("51 824 753 557"))
        # mod-89 passes but no ABN can start with 10 (found by cross-checking against python-stdnum)
        self.assertFalse(is_valid_au_abn("10708502264"))
        self.assertTrue(is_valid_nzbn("9429051850012"))
        self.assertFalse(is_valid_nzbn("9429051850013"))


class MaskingTests(unittest.TestCase):
    def test_ird_is_masked_as_ird_not_phone(self):
        result = mask_text("Employee IRD 49-091-850 starts Monday.")
        types = [f["type"] for f in result["findings"]]
        self.assertIn("nz_ird", types)
        self.assertNotIn("49-091-850", result["masked"])

    def test_business_numbers_survive_masking(self):
        text = "Example Services Ltd, NZBN 9429051850012, ABN 51 824 753 556."
        result = mask_text(text)
        self.assertIn("9429051850012", result["masked"])
        self.assertIn("51 824 753 556", result["masked"])
        kinds = {item["type"] for item in classify_identifiers(text)}
        self.assertTrue({"nzbn", "au_abn"} <= kinds)

    def test_tender_wording_is_left_alone(self):
        text = "The Supplier must hold public liability insurance of not less than $10,000,000 for any one occurrence."
        self.assertEqual(mask_text(text)["masked"], text)

    def test_invalid_tfn_shaped_number_is_not_labelled_tfn(self):
        result = mask_text("Reference 123 456 789 applies.")
        self.assertNotIn("tfn", [f["type"] for f in result["findings"]])


class SecretTests(unittest.TestCase):
    def test_no_shared_default_secret(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            a, b = AuditTrail(), AuditTrail()
            r1, r2 = AgentIdentityRegistry(), AgentIdentityRegistry()
        self.assertNotEqual(a.secret, b.secret)
        self.assertNotEqual(r1.secret, r2.secret)
        self.assertNotIn("blackwall", a.secret)
        self.assertGreaterEqual(len(a.secret), 64)

    def test_environment_secret_is_used(self):
        os.environ["BLACKWALL_AUDIT_SECRET"] = "x" * 40
        try:
            self.assertEqual(AuditTrail().secret, "x" * 40)
        finally:
            del os.environ["BLACKWALL_AUDIT_SECRET"]

    def test_explicit_secret_wins(self):
        self.assertEqual(AuditTrail(secret="given-secret-value").secret, "given-secret-value")


if __name__ == "__main__":
    unittest.main()
