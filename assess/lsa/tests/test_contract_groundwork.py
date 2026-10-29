#!/usr/bin/env python3
"""Tests for shared contract groundwork (Issue #272).

Validates:
1. finding.schema.json accepts the bfla / mass_assignment categories, their id
   prefixes and subtypes, and the optional kfp1 fingerprint.
2. route-inventory.schema.json accepts optional privilege and body_bindings.
3. Both SARIF exporters emit rule metadata (CWE, OWASP API tags) for the new
   categories and carry the fingerprint in partialFingerprints.
4. Summary counts and reports include new categories only when present.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
ROOT = KIT.parent.parent
sys.path.insert(0, str(KIT / "scripts"))
sys.path.insert(0, str(ROOT))

from findings_to_sarif import to_sarif  # noqa: E402
from merge_findings import count_by_category, load_validator  # noqa: E402
from render_report import JA_CATEGORY_LABELS, _build_category_bar_svg  # noqa: E402
from operate.lsa_sarif.lsa_to_sarif import convert_findings_to_sarif  # noqa: E402

FINGERPRINT = "kfp1:" + "a" * 64


def _finding(**overrides: object) -> dict:
    base = {
        "finding_id": "BFLA-R-0001-1",
        "category": "bfla",
        "subtype": "missing_role_check",
        "title": "User deletion reachable by any authenticated user",
        "location": {"file": "admin/users.php", "start_line": 12},
        "evidence": [{"file": "admin/users.php", "line": 12, "code": "delete_user($_GET['id']);", "why": "no role check"}],
        "severity": "high",
        "confidence": "high",
        "cwe": ["CWE-285"],
        "recommendation": "Require the admin role before the handler runs.",
        "status": "unverified",
    }
    base.update(overrides)
    return base


def _mass_assignment() -> dict:
    return _finding(
        finding_id="MASS-R-0002-1",
        category="mass_assignment",
        subtype="whole_object_binding",
        title="Profile update binds the whole request body to the User model",
        cwe=["CWE-915"],
        fingerprint=FINGERPRINT,
    )


class TestFindingSchema(unittest.TestCase):
    def setUp(self) -> None:
        self.validate = load_validator("finding.schema.json")

    def test_existing_bola_finding_still_valid(self) -> None:
        legacy = _finding(finding_id="BOLA-R-0003-1", category="bola", subtype="missing_ownership_check", cwe=["CWE-639"])
        self.assertEqual(self.validate(legacy), [])

    def test_bfla_finding_valid(self) -> None:
        self.assertEqual(self.validate(_finding()), [])

    def test_bfla_new_subtypes_valid(self) -> None:
        for subtype in ("role_from_request", "client_side_role_check"):
            with self.subTest(subtype=subtype):
                self.assertEqual(self.validate(_finding(subtype=subtype)), [])

    def test_mass_assignment_finding_with_fingerprint_valid(self) -> None:
        self.assertEqual(self.validate(_mass_assignment()), [])
        doc = _mass_assignment()
        doc["subtype"] = "privileged_field_writable"
        self.assertEqual(self.validate(doc), [])

    def test_unknown_category_rejected(self) -> None:
        self.assertNotEqual(self.validate(_finding(category="xss")), [])

    def test_unknown_id_prefix_rejected(self) -> None:
        self.assertNotEqual(self.validate(_finding(finding_id="PRIV-R-1")), [])

    def test_malformed_fingerprint_rejected(self) -> None:
        for bad in ("kfp1:xyz", "a" * 64, "kfp2:" + "a" * 64, "kfp1:" + "A" * 64):
            with self.subTest(fingerprint=bad):
                self.assertNotEqual(self.validate(_finding(fingerprint=bad)), [])


class TestRouteInventorySchema(unittest.TestCase):
    def setUp(self) -> None:
        self.validate = load_validator("route-inventory.schema.json")
        self.route = {
            "route_id": "R-0001",
            "method": ["POST"],
            "path": "/admin/users/delete",
            "handler": {"file": "admin/users.php", "line": 3},
            "id_inputs": [],
            "guards": [],
            "data_ops": [{"op": "delete", "target": "users"}],
            "needs_bola_audit": False,
        }

    def test_route_without_new_fields_valid(self) -> None:
        self.assertEqual(self.validate({"routes": [self.route]}), [])

    def test_privilege_and_body_bindings_valid(self) -> None:
        route = dict(self.route)
        route["privilege"] = "privileged"
        route["body_bindings"] = [
            {"target": "User", "style": "whole_object", "file": "admin/users.php", "line": 9},
            {"target": "Profile", "style": "allowlist"},
        ]
        self.assertEqual(self.validate({"routes": [route]}), [])

    def test_invalid_privilege_rejected(self) -> None:
        route = dict(self.route, privilege="root")
        self.assertNotEqual(self.validate({"routes": [route]}), [])

    def test_invalid_binding_style_rejected(self) -> None:
        route = dict(self.route, body_bindings=[{"target": "User", "style": "partial"}])
        self.assertNotEqual(self.validate({"routes": [route]}), [])


class TestLsaSarifExport(unittest.TestCase):
    def setUp(self) -> None:
        self.sarif = to_sarif({"findings": [_finding(), _mass_assignment()]})
        self.run = self.sarif["runs"][0]
        self.rules = {r["id"]: r for r in self.run["tool"]["driver"]["rules"]}

    def test_rule_text_for_new_categories(self) -> None:
        bfla = self.rules["lsa/bfla/missing_role_check"]
        mass = self.rules["lsa/mass_assignment/whole_object_binding"]
        self.assertIn("function level authorization", bfla["shortDescription"]["text"].lower())
        self.assertIn("mass assignment", mass["shortDescription"]["text"].lower())

    def test_owasp_api_tags_for_new_categories(self) -> None:
        self.assertIn("OWASP-API5:2023-BFLA", self.rules["lsa/bfla/missing_role_check"]["properties"]["tags"])
        self.assertIn(
            "OWASP-API3:2023-BOPLA",
            self.rules["lsa/mass_assignment/whole_object_binding"]["properties"]["tags"],
        )

    def test_cwe_taxa_cover_new_categories(self) -> None:
        taxa_ids = {t["id"] for t in self.run["taxonomies"][0]["taxa"]}
        self.assertTrue({"CWE-285", "CWE-915"} <= taxa_ids)
        mass_result = next(r for r in self.run["results"] if r["ruleId"].startswith("lsa/mass_assignment/"))
        self.assertEqual([t["id"] for t in mass_result["taxa"]], ["CWE-915"])

    def test_fingerprint_emitted_only_when_present(self) -> None:
        by_rule = {r["ruleId"]: r for r in self.run["results"]}
        mass_fp = by_rule["lsa/mass_assignment/whole_object_binding"]["partialFingerprints"]
        bfla_fp = by_rule["lsa/bfla/missing_role_check"]["partialFingerprints"]
        self.assertEqual(mass_fp["komainu/v1"], FINGERPRINT)
        self.assertEqual(mass_fp["lsaFindingId"], "MASS-R-0002-1")
        self.assertNotIn("komainu/v1", bfla_fp)


class TestOperateSarifExport(unittest.TestCase):
    def test_rule_ids_and_fingerprint(self) -> None:
        sarif = convert_findings_to_sarif([_finding(cwe=285), {**_mass_assignment(), "cwe": 915}])
        run = sarif["runs"][0]
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(rule_ids, {"KOMAINU-BFLA-CWE285", "KOMAINU-MASS-CWE915"})
        mass = next(r for r in run["results"] if r["ruleId"] == "KOMAINU-MASS-CWE915")
        self.assertEqual(mass["partialFingerprints"], {"komainu/v1": FINGERPRINT})
        bfla = next(r for r in run["results"] if r["ruleId"] == "KOMAINU-BFLA-CWE285")
        self.assertNotIn("partialFingerprints", bfla)

    def test_default_cwe_for_new_categories(self) -> None:
        sarif = convert_findings_to_sarif([_finding(cwe=None), {**_mass_assignment(), "cwe": None}])
        rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        self.assertEqual(rule_ids, {"KOMAINU-BFLA-CWE285", "KOMAINU-MASS-CWE915"})


class TestSummaryAndReports(unittest.TestCase):
    def test_count_keeps_legacy_shape_without_new_categories(self) -> None:
        counts = count_by_category([{"category": "bola"}, {"category": "sql_injection"}])
        self.assertEqual(counts, {"bola": 1, "sql_injection": 1, "nosql_injection": 0})

    def test_count_adds_new_categories_when_present(self) -> None:
        counts = count_by_category([{"category": "bfla"}, {"category": "mass_assignment"}, {"category": "bfla"}])
        self.assertEqual(
            counts,
            {"bola": 0, "sql_injection": 0, "nosql_injection": 0, "bfla": 2, "mass_assignment": 1},
        )

    def test_japanese_labels_for_new_categories(self) -> None:
        self.assertIn("BFLA", JA_CATEGORY_LABELS["bfla"])
        self.assertIn("マスアサインメント", JA_CATEGORY_LABELS["mass_assignment"])

    def test_bar_chart_shows_new_categories_only_when_present(self) -> None:
        legacy = _build_category_bar_svg({"bola": 1, "sql_injection": 0, "nosql_injection": 0}, 1)
        self.assertNotIn("CWE-915", legacy)
        self.assertIn('viewBox="0 0 360 170"', legacy)
        extended = _build_category_bar_svg(
            {"bola": 1, "sql_injection": 0, "nosql_injection": 0, "bfla": 1, "mass_assignment": 1}, 3
        )
        self.assertIn("CWE-285", extended)
        self.assertIn("CWE-915", extended)
        self.assertIn('viewBox="0 0 360 270"', extended)


if __name__ == "__main__":
    unittest.main()
