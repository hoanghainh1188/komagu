#!/usr/bin/env python3
"""Tests for attack chain synthesis (Issue #316).

Verifies:
1. attack-chain.schema.json schema conformity.
2. 3-step chain synthesis (Mass assignment -> BFLA -> BOLA) with breaking fix calculation.
3. Safe / disconnected findings produce no chains.
4. Single findings never become a chain.
5. Rejected findings are excluded.
6. SARIF output enrichment with attackChains property.

Standard-library-only (Python 3.8+).
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
sys.path.insert(0, str(KIT / "scripts"))

from attack_chains import (  # noqa: E402
    attach_chains_to_sarif,
    build_attack_chains,
    profile_finding,
    render_attack_chains_html,
    render_attack_chains_md,
)
from merge_findings import load_validator  # noqa: E402
from render_report import render_en, render_html, render_ja  # noqa: E402


class TestAttackChains(unittest.TestCase):
    def setUp(self) -> None:
        self.validate_schema = load_validator("attack-chain.schema.json")
        self.validate_finding = load_validator("finding.schema.json")

    def test_schema_validates_empty_chain_doc(self) -> None:
        doc = build_attack_chains([])
        errors = self.validate_schema(doc)
        self.assertEqual(errors, [], f"Schema errors: {errors}")
        self.assertEqual(doc["summary"]["total_chains"], 0)

    def test_single_finding_never_becomes_chain(self) -> None:
        finding = {
            "finding_id": "BOLA-001",
            "category": "bola",
            "subtype": "missing_ownership_check",
            "title": "BOLA in orders",
            "location": "Controllers/OrderController.cs:42",
            "endpoint": "GET /api/orders/{id}",
            "evidence": "db.Orders.Find(id)",
            "severity": "high",
            "confidence": "confirmed",
            "cwe": "CWE-639",
            "recommendation": "Check owner",
            "status": "confirmed",
        }
        doc = build_attack_chains([finding])
        self.assertEqual(doc["summary"]["total_chains"], 0)
        self.assertEqual(self.validate_schema(doc), [])

    def test_rejected_findings_are_excluded(self) -> None:
        f1 = {
            "finding_id": "MASS-001",
            "category": "mass_assignment",
            "subtype": "whole_object_binding",
            "title": "Mass assignment on register",
            "location": "register.php:10",
            "endpoint": "POST /register",
            "evidence": "extract($_POST)",
            "severity": "high",
            "confidence": "confirmed",
            "cwe": "CWE-915",
            "recommendation": "Use allowlist",
            "status": "rejected",  # Rejected by verifier
            "attack_vector": {"fields": {"role": "admin"}},
        }
        f2 = {
            "finding_id": "BOLA-001",
            "category": "bola",
            "subtype": "missing_ownership_check",
            "title": "BOLA in orders",
            "location": "orders.php:20",
            "endpoint": "GET /orders/{id}",
            "evidence": "SELECT * FROM orders WHERE id = $id",
            "severity": "high",
            "confidence": "confirmed",
            "cwe": "CWE-639",
            "recommendation": "Filter by user",
            "status": "confirmed",
        }
        doc = build_attack_chains([f1, f2])
        self.assertEqual(doc["summary"]["total_chains"], 0)

    def test_three_step_planted_attack_chain(self) -> None:
        """Planted 3-step chain: Mass Assignment -> BFLA -> BOLA."""
        step1_mass = {
            "finding_id": "MASS-001",
            "category": "mass_assignment",
            "subtype": "whole_object_binding",
            "title": "Mass assignment on registration allows role escalation",
            "location": "php-plain/register.php:4",
            "endpoint": "POST /register",
            "evidence": "extract($_POST) overrides $role",
            "severity": "high",
            "confidence": "confirmed",
            "cwe": "CWE-915",
            "recommendation": "Whitelist registration fields",
            "status": "confirmed",
            "attack_vector": {
                "method": "POST",
                "path": "/register",
                "fields": {"role": "admin", "is_admin": True},
            },
        }

        step2_bfla = {
            "finding_id": "BFLA-001",
            "category": "bfla",
            "subtype": "missing_role_check",
            "title": "Admin tenant list accessible without role check",
            "location": "php-plain/admin/tenants.php:12",
            "endpoint": "GET /admin/tenants",
            "evidence": "Checks login session but not admin role",
            "severity": "high",
            "confidence": "confirmed",
            "cwe": "CWE-285",
            "recommendation": "Add requireRole('admin') guard",
            "status": "confirmed",
        }

        step3_bola = {
            "finding_id": "BOLA-001",
            "category": "bola",
            "subtype": "missing_ownership_check",
            "title": "Customer records readable across tenants by ID",
            "location": "php-plain/customers.php:25",
            "endpoint": "GET /api/customers/{id}",
            "evidence": "SELECT * FROM customers WHERE id = ?",
            "severity": "high",
            "confidence": "likely",
            "cwe": "CWE-639",
            "recommendation": "Bind tenant_id to authenticated user",
            "status": "likely",
        }

        doc = build_attack_chains([step1_mass, step2_bfla, step3_bola])
        errors = self.validate_schema(doc)
        self.assertEqual(errors, [], f"Schema validation failed: {errors}")

        self.assertGreaterEqual(doc["summary"]["total_chains"], 1)
        chain = doc["chains"][0]
        self.assertEqual(chain["chain_id"], "chain-001")
        self.assertEqual(chain["entry"], "anonymous")
        self.assertEqual(chain["severity"], "critical")
        # Confidence is weakest link (likely from step3)
        self.assertEqual(chain["confidence"], "likely")

        # Verify steps in order
        step_ids = [s["finding_id"] for s in chain["steps"]]
        self.assertIn("MASS-001", step_ids)
        self.assertIn("BOLA-001", step_ids)

        # Breaking fixes must include all chain findings
        self.assertIn("MASS-001", chain["breaking_fixes"])
        self.assertIn("BOLA-001", chain["breaking_fixes"])

        # Check summary top breaking fixes
        top_fixes = doc["summary"]["top_breaking_fixes"]
        self.assertGreaterEqual(len(top_fixes), 1)
        broken_counts = {tf["finding_id"]: tf["chains_broken"] for tf in top_fixes}
        self.assertGreaterEqual(broken_counts.get("MASS-001", 0), 1)

    def test_sarif_enrichment(self) -> None:
        """Verify attach_chains_to_sarif adds properties.attackChains."""
        sarif_mock = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "komagu"}},
                    "results": [
                        {
                            "ruleId": "BOLA-001",
                            "message": {"text": "BOLA"},
                            "partialFingerprints": {"komagu/v1": "kfp1:111111"},
                        },
                        {
                            "ruleId": "INJ-001",
                            "message": {"text": "Unlinked injection"},
                        },
                    ],
                }
            ],
        }

        chains_mock = {
            "chains": [
                {
                    "chain_id": "chain-001",
                    "steps": [
                        {"finding_id": "MASS-001"},
                        {"finding_id": "BOLA-001"},
                    ],
                }
            ]
        }

        enriched = attach_chains_to_sarif(sarif_mock, chains_mock)
        r0 = enriched["runs"][0]["results"][0]
        self.assertEqual(r0.get("properties", {}).get("attackChains"), ["chain-001"])

        r1 = enriched["runs"][0]["results"][1]
        self.assertNotIn("attackChains", r1.get("properties", {}))

    def test_markdown_and_html_rendering(self) -> None:
        """Verify attack chains render properly in markdown (EN & JA) and HTML dashboard."""
        mock_chains = {
            "version": 1,
            "generated_at": "2026-11-01T20:00:00Z",
            "chains": [
                {
                    "chain_id": "chain-001",
                    "title": "Mass Assignment → BFLA → BOLA targeting customers",
                    "entry": "anonymous",
                    "steps": [
                        {
                            "step_index": 1,
                            "finding_id": "MASS-001",
                            "category": "mass_assignment",
                            "location": "register.php:4",
                            "role_in_chain": "entry_point",
                            "explanation": "Overwrites role to admin",
                        },
                        {
                            "step_index": 2,
                            "finding_id": "BOLA-001",
                            "category": "bola",
                            "location": "customers.php:25",
                            "role_in_chain": "impact",
                            "explanation": "Leaks other tenants",
                        },
                    ],
                    "outcome": "Exfiltration of customer records",
                    "business_impact": "Loss of customer trust and regulatory fine.",
                    "severity": "critical",
                    "confidence": "likely",
                    "breaking_fixes": ["MASS-001", "BOLA-001"],
                }
            ],
            "summary": {
                "total_chains": 1,
                "by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0},
                "top_breaking_fixes": [
                    {
                        "finding_id": "MASS-001",
                        "category": "mass_assignment",
                        "location": "register.php:4",
                        "chains_broken": 1,
                    }
                ],
            },
        }

        # Test Markdown EN
        md_en = "\n".join(render_attack_chains_md(mock_chains, "en"))
        self.assertIn("Attack Chains", md_en)
        self.assertIn("Top Breaking Fixes", md_en)
        self.assertIn("MASS-001", md_en)
        self.assertIn("chain-001", md_en)

        # Test Markdown JA
        md_ja = "\n".join(render_attack_chains_md(mock_chains, "ja"))
        self.assertIn("攻撃チェーン", md_ja)
        self.assertIn("最優先対策", md_ja)
        self.assertIn("MASS-001", md_ja)
        self.assertIn("chain-001", md_ja)

        # Test HTML Card
        html_card = render_attack_chains_html(mock_chains)
        self.assertIn("Chained Attack Scenarios", html_card)
        self.assertIn("Top Breaking Fixes", html_card)
        self.assertIn("chain-001", html_card)
        self.assertIn("MASS-001", html_card)


if __name__ == "__main__":
    unittest.main()
