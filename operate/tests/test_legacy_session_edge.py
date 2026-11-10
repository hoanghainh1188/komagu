#!/usr/bin/env python3
"""Gaps found rehearsing the pilot runbook on a running Struts / JSESSIONID application (#374)."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from operate.ai.runner import HeadlessAIRunner  # noqa: E402
from operate.cli.commands import protect  # noqa: E402
from operate.cross_user_tester.runner import generate_test_cases_from_findings  # noqa: E402
from remediate.edge.coraza.virtual_patcher import VirtualPatcher  # noqa: E402

EDGE = REPO_ROOT / "remediate" / "edge"


def protect_args(**overrides) -> argparse.Namespace:
    values = dict(target=None, config=None, up=False, down=False, status=False,
                  virtual_patch=None, patch_out=None, dry_run=False)
    return argparse.Namespace(**{**values, **overrides})


class ProtectWiringTests(unittest.TestCase):
    def run_up(self, **overrides):
        with patch.object(protect.shutil, "which", return_value="/usr/bin/docker"), \
                patch.object(protect.subprocess, "run", return_value=MagicMock(returncode=0)) as run:
            code = protect.execute_protect(protect_args(up=True, **overrides))
        return code, run

    def test_target_reaches_compose(self) -> None:
        code, run = self.run_up(target="http://host.docker.internal:18080")
        self.assertEqual(code, 0)
        self.assertEqual(run.call_args.kwargs["env"]["KOMAGU_UPSTREAM"], "http://host.docker.internal:18080")

    def test_custom_kong_config_reaches_compose(self) -> None:
        config = EDGE / "kong" / "kong-legacy-session.yaml"
        _, run = self.run_up(config=str(config))
        self.assertEqual(run.call_args.kwargs["env"]["KOMAGU_KONG_CONFIG"], str(config.resolve()))

    def test_patch_out_file_is_loaded_by_the_stack(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            conf = Path(td) / "virtual-patches.conf"
            conf.write_text("# none\n", encoding="utf-8")
            _, run = self.run_up(patch_out=str(conf))
            self.assertEqual(run.call_args.kwargs["env"]["KOMAGU_VIRTUAL_PATCH_FILE"], str(conf.resolve()))

    def test_missing_patch_file_stops_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            code, run = self.run_up(patch_out=str(Path(td) / "absent.conf"))
        self.assertEqual(code, 2)
        run.assert_not_called()

    def test_invalid_target_stops_before_docker(self) -> None:
        for bad in ("ftp://host:1", "host:8080", "http://"):
            code, run = self.run_up(target=bad)
            self.assertEqual(code, 2, bad)
            run.assert_not_called()

    def test_stack_reads_the_settings(self) -> None:
        compose = (EDGE / "docker-compose.yml").read_text(encoding="utf-8")
        caddy = (EDGE / "coraza" / "Caddyfile").read_text(encoding="utf-8")
        self.assertIn("{$KOMAGU_UPSTREAM:http://mock-backend:5000}", caddy)
        self.assertIn("KOMAGU_UPSTREAM: ${KOMAGU_UPSTREAM:-http://mock-backend:5000}", compose)
        self.assertIn("${KOMAGU_KONG_CONFIG:-./kong/kong.yaml}:/kong/declarative/kong.yaml:ro", compose)
        self.assertIn("${KOMAGU_VIRTUAL_PATCH_FILE:-./coraza/rules/virtual-patches.conf}:/etc/coraza/rules/virtual-patches.conf:ro", compose)
        self.assertIn('"${KOMAGU_EDGE_BIND:-0.0.0.0}:8000:8000"', compose)
        self.assertIn("host.docker.internal:host-gateway", compose)

    def test_legacy_kong_profile_routes_everything_without_jwt(self) -> None:
        text = (EDGE / "kong" / "kong-legacy-session.yaml").read_text(encoding="utf-8")
        self.assertIn("- /\n", text)
        self.assertIn("strip_path: false", text)
        self.assertIn("name: rate-limiting", text)
        self.assertIn("limit_by: ip", text)
        self.assertNotIn("name: jwt", text)


class VirtualPatchSessionAppTests(unittest.TestCase):
    def test_bola_on_session_route_gets_no_authorization_rule(self) -> None:
        """A missing Authorization header says nothing on a JSESSIONID app: the rule would block every user."""
        text, manifest = VirtualPatcher().generate_patches_from_findings([
            {"finding_id": "BOLA-R-1", "category": "bola", "endpoint": {"method": "ANY", "path": "/order/detail.do"}},
        ])
        self.assertEqual(manifest, [])
        self.assertNotIn("REQUEST_HEADERS:Authorization", text)
        self.assertIn("BOLA-R-1", text)

    def test_bola_on_api_route_is_unchanged(self) -> None:
        text, manifest = VirtualPatcher().generate_patches_from_findings([
            {"finding_id": "BOLA-R-2", "category": "bola", "endpoint": {"method": "GET", "path": "/api/orders/{id}"}},
        ])
        self.assertEqual(len(manifest), 1)
        self.assertIn("REQUEST_HEADERS:Authorization", text)

    def test_injection_without_a_route_gets_no_rule_on_an_invented_path(self) -> None:
        text, manifest = VirtualPatcher().generate_patches_from_findings([
            {"finding_id": "INJ-I-1", "category": "sql_injection", "location": {"file": "A.java", "start_line": 3}},
        ])
        self.assertEqual(manifest, [])
        self.assertNotIn('"@rx ^/api"', text)
        self.assertIn("INJ-I-1", text)


class FromScanLegacyRequestTests(unittest.TestCase):
    def cases(self, path: str, method: str = "ANY", **attack_vector):
        finding = {"finding_id": "BOLA-R-1", "category": "bola", "status": "confirmed", "title": "t",
                   "endpoint": {"method": method, "path": path}}
        if attack_vector:
            finding["attack_vector"] = attack_vector
        with tempfile.TemporaryDirectory() as td:
            scan = Path(td) / "findings.json"
            scan.write_text(json.dumps({"findings": [finding]}), encoding="utf-8")
            return generate_test_cases_from_findings(str(scan), "101", "token")

    def test_any_on_a_read_action_is_get_with_the_id_parameter(self) -> None:
        case = self.cases("/order/detail.do")[0]
        self.assertEqual((case.method, case.path), ("GET", "/order/detail.do?id=101"))

    def test_any_on_a_write_action_is_a_form_post(self) -> None:
        case = self.cases("/order/update.do")[0]
        self.assertEqual(case.method, "POST")
        self.assertEqual(case.payload["id"], "101")

    def test_write_word_must_be_a_whole_word(self) -> None:
        for path in ("/order/loadDetail.do", "/order/addressList.do", "/order/additionalInfo.do"):
            self.assertEqual(self.cases(path)[0].method, "GET", path)
        for path in ("/order/saveOrder.do", "/order/addItem.do", "/order/doUpdate.do", "/order/order_delete.do"):
            self.assertEqual(self.cases(path)[0].method, "POST", path)

    def test_target_param_names_the_id(self) -> None:
        case = self.cases("/invoice/view.do", target_param="invoiceId")[0]
        self.assertEqual(case.path, "/invoice/view.do?invoiceId=101")

    def test_explicit_method_wins(self) -> None:
        self.assertEqual(self.cases("/order/update.do", method="GET")[0].method, "GET")


class AttackVectorFromRouteTests(unittest.TestCase):
    def test_id_like_input_becomes_target_param(self) -> None:
        route = {"id_inputs": [{"name": "page", "source": "any"}, {"name": "invoiceId", "source": "any"}]}
        finding = HeadlessAIRunner._with_route_target({"finding_id": "B"}, route)
        self.assertEqual(finding["attack_vector"]["target_param"], "invoiceId")

    def test_model_value_is_kept(self) -> None:
        route = {"id_inputs": [{"name": "invoiceId", "source": "any"}]}
        finding = {"finding_id": "B", "attack_vector": {"target_param": "orderNo"}}
        self.assertEqual(HeadlessAIRunner._with_route_target(finding, route)["attack_vector"]["target_param"], "orderNo")


class FixDiffFormatTests(unittest.TestCase):
    def test_manual_fix_findings_are_listed_when_no_diff_exists(self) -> None:
        """All Java legacy findings are manual, so --format diff used to print nothing and exit 0 (#374)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "src").mkdir()
            (root / "src" / "detail.jsp").write_text("<% out.print(request.getParameter(\"id\")); %>\n", encoding="utf-8")
            findings = root / "findings.json"
            findings.write_text(json.dumps({"findings": [{
                "finding_id": "BOLA-R-7", "category": "bola", "status": "confirmed", "severity": "high",
                "subtype": "missing_ownership_check", "title": "t",
                "location": {"file": "src/detail.jsp", "start_line": 1},
                "endpoint": {"method": "GET", "path": "/detail.jsp"}}]}), encoding="utf-8")
            res = subprocess.run([sys.executable, str(REPO_ROOT / "bin" / "komagu"), "fix", str(root), "--findings",
                                  str(findings), "--dry-run", "--format", "diff"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("BOLA-R-7", res.stderr)
        self.assertIn("src/detail.jsp", res.stderr)


class MergeReportsDroppedFindingsTests(unittest.TestCase):
    def test_validation_errors_reach_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "findings").mkdir()
            (out / "findings" / "bad.json").write_text('[{"some": "item"}]', encoding="utf-8")
            res = subprocess.run([sys.executable, str(REPO_ROOT / "assess/lsa/scripts/merge_findings.py"), str(out)],
                                 capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)
        self.assertIn("bad.json", res.stderr)


if __name__ == "__main__":
    unittest.main()
