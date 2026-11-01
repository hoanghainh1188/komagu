#!/usr/bin/env python3
"""Tests for security debt forecasting (Issue #318).

Verifies:
1. forecast.schema.json schema conformity.
2. Insufficient history detection (< 6 snapshots or < 28 days span).
3. Converging burndown calculations (P10 <= P50 <= P90).
4. Flat and diverging trajectory handling without false promises.
5. Target deadline evaluation (on_track, at_risk, off_track).
6. What-if velocity simulation.
7. Markdown (EN & JA) and HTML card rendering.

Standard-library-only (Python 3.8+).
"""
from __future__ import annotations

import datetime
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
sys.path.insert(0, str(KIT / "scripts"))

from forecast import project_debt, render_forecast_html, render_forecast_md  # noqa: E402
from merge_findings import load_validator  # noqa: E402


class TestForecast(unittest.TestCase):
    def setUp(self) -> None:
        self.validate_schema = load_validator("forecast.schema.json")

    def test_schema_validates_empty_and_insufficient_history(self) -> None:
        doc = project_debt([])
        errors = self.validate_schema(doc)
        self.assertEqual(errors, [], f"Schema validation errors: {errors}")
        self.assertFalse(doc["has_enough_history"])
        self.assertIn("Requires at least", doc["reason_if_insufficient"])

    def test_insufficient_snapshots_or_span(self) -> None:
        # 4 snapshots over 10 days
        history = [
            {"date": "2026-09-01", "open": 20, "new": 2, "fixed": 1, "regressed": 0, "by_severity": {"critical": 5, "high": 10}},
            {"date": "2026-09-03", "open": 19, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 4, "high": 10}},
            {"date": "2026-09-06", "open": 18, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 3, "high": 10}},
            {"date": "2026-09-10", "open": 16, "new": 0, "fixed": 2, "regressed": 0, "by_severity": {"critical": 2, "high": 10}},
        ]
        doc = project_debt(history)
        self.assertFalse(doc["has_enough_history"])
        for p in doc["projections"]:
            self.assertEqual(p["status"], "insufficient_history")
            self.assertIsNone(p["target_zero_date_p50"])
        self.assertEqual(self.validate_schema(doc), [])

    def test_converging_burndown_and_targets(self) -> None:
        # 7 snapshots spanning 42 days, steady fix velocity
        history = [
            {"date": "2026-08-01", "open": 30, "new": 1, "fixed": 3, "regressed": 0, "by_severity": {"critical": 6, "high": 12}},
            {"date": "2026-08-08", "open": 28, "new": 1, "fixed": 3, "regressed": 0, "by_severity": {"critical": 5, "high": 11}},
            {"date": "2026-08-15", "open": 25, "new": 0, "fixed": 3, "regressed": 0, "by_severity": {"critical": 4, "high": 10}},
            {"date": "2026-08-22", "open": 22, "new": 1, "fixed": 4, "regressed": 0, "by_severity": {"critical": 3, "high": 9}},
            {"date": "2026-08-29", "open": 19, "new": 1, "fixed": 4, "regressed": 0, "by_severity": {"critical": 2, "high": 8}},
            {"date": "2026-09-05", "open": 16, "new": 0, "fixed": 3, "regressed": 0, "by_severity": {"critical": 1, "high": 8}},
            {"date": "2026-09-12", "open": 13, "new": 0, "fixed": 3, "regressed": 0, "by_severity": {"critical": 1, "high": 7}},
        ]
        targets = {
            "critical": "2026-10-15",  # Generous target
            "overall": "2026-10-01",   # Very tight target -> should be off_track
        }

        doc = project_debt(history, targets=targets, today="2026-09-12")
        errors = self.validate_schema(doc)
        self.assertEqual(errors, [], f"Schema validation failed: {errors}")
        self.assertTrue(doc["has_enough_history"])

        # Check rates
        self.assertGreater(doc["rates"]["fix_rate_per_week"], 2.0)
        self.assertLess(doc["rates"]["net_rate_per_week"], -1.0)

        crit_proj = next(p for p in doc["projections"] if p["severity"] == "critical")
        self.assertEqual(crit_proj["status"], "converging")
        self.assertIsNotNone(crit_proj["target_zero_date_p50"])
        # Dates must be sorted chronologically: P10 <= P50 <= P90
        p10 = datetime.datetime.strptime(crit_proj["target_zero_date_p10"], "%Y-%m-%d")
        p50 = datetime.datetime.strptime(crit_proj["target_zero_date_p50"], "%Y-%m-%d")
        p90 = datetime.datetime.strptime(crit_proj["target_zero_date_p90"], "%Y-%m-%d")
        self.assertLessEqual(p10, p50)
        self.assertLessEqual(p50, p90)

        # Critical target is generous -> on_track or at_risk
        self.assertIn(crit_proj["target_status"], ("on_track", "at_risk"))

        overall_proj = next(p for p in doc["projections"] if p["severity"] == "overall")
        # 13 items open, net rate ~ -3/wk -> ~4 weeks (mid October). Target is Oct 1 -> off_track
        self.assertEqual(overall_proj["target_status"], "off_track")

    def test_diverging_or_flat_history(self) -> None:
        # History where incoming defects exceed fixes
        history = [
            {"date": "2026-08-01", "open": 10, "new": 4, "fixed": 1, "regressed": 0, "by_severity": {"critical": 2, "high": 4}},
            {"date": "2026-08-08", "open": 13, "new": 4, "fixed": 1, "regressed": 0, "by_severity": {"critical": 3, "high": 5}},
            {"date": "2026-08-15", "open": 16, "new": 3, "fixed": 0, "regressed": 0, "by_severity": {"critical": 3, "high": 6}},
            {"date": "2026-08-22", "open": 18, "new": 3, "fixed": 1, "regressed": 0, "by_severity": {"critical": 4, "high": 7}},
            {"date": "2026-08-29", "open": 20, "new": 3, "fixed": 1, "regressed": 0, "by_severity": {"critical": 5, "high": 8}},
            {"date": "2026-09-05", "open": 22, "new": 3, "fixed": 1, "regressed": 0, "by_severity": {"critical": 5, "high": 9}},
            {"date": "2026-09-12", "open": 25, "new": 4, "fixed": 1, "regressed": 0, "by_severity": {"critical": 6, "high": 10}},
        ]
        doc = project_debt(history, targets={"overall": "2026-12-31"}, today="2026-09-12")
        self.assertTrue(doc["has_enough_history"])
        overall_proj = next(p for p in doc["projections"] if p["severity"] == "overall")
        self.assertEqual(overall_proj["status"], "diverging")
        self.assertIsNone(overall_proj["target_zero_date_p50"])
        self.assertEqual(overall_proj["target_status"], "not_converging")

    def test_what_if_scenarios(self) -> None:
        history = [
            {"date": "2026-08-01", "open": 20, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 4, "high": 8}},
            {"date": "2026-08-08", "open": 19, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 4, "high": 7}},
            {"date": "2026-08-15", "open": 18, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 3, "high": 7}},
            {"date": "2026-08-22", "open": 17, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 3, "high": 6}},
            {"date": "2026-08-29", "open": 16, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 2, "high": 6}},
            {"date": "2026-09-05", "open": 15, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 2, "high": 5}},
            {"date": "2026-09-12", "open": 14, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 1, "high": 5}},
        ]
        what_ifs = [
            {"id": "add_dev", "fix_rate_delta": 3.0, "description": "Add 1 developer (+3 fixes/wk)"}
        ]
        doc = project_debt(history, what_if_modifiers=what_ifs, today="2026-09-12")
        self.assertEqual(len(doc["scenarios"]), 2)
        sc = doc["scenarios"][1]
        self.assertEqual(sc["scenario_id"], "add_dev")
        self.assertIn("Estimated ~", sc["projected_date_range"])

    def test_markdown_and_html_rendering(self) -> None:
        history = [
            {"date": "2026-08-01", "open": 10, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 2, "high": 4}},
            {"date": "2026-08-08", "open": 9, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 2, "high": 3}},
            {"date": "2026-08-15", "open": 8, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 1, "high": 3}},
            {"date": "2026-08-22", "open": 7, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 1, "high": 2}},
            {"date": "2026-08-29", "open": 6, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 1, "high": 1}},
            {"date": "2026-09-05", "open": 5, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 0, "high": 1}},
            {"date": "2026-09-12", "open": 4, "new": 1, "fixed": 2, "regressed": 0, "by_severity": {"critical": 0, "high": 0}},
        ]
        doc = project_debt(history, targets={"critical": "2026-10-01"})
        md_en = "\n".join(render_forecast_md(doc, "en"))
        self.assertIn("Outlook & Debt Forecast", md_en)
        self.assertIn("Arrival Rate", md_en)

        md_ja = "\n".join(render_forecast_md(doc, "ja"))
        self.assertIn("見通しとセキュリティ負債予測", md_ja)
        self.assertIn("目標達成予測", md_ja)

        html_card = render_forecast_html(doc)
        self.assertIn("Outlook &amp; Debt Forecast", html_card)
        self.assertIn("Arrival Rate", html_card)


if __name__ == "__main__":
    unittest.main()
