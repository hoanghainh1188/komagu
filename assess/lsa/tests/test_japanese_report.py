#!/usr/bin/env python3
"""Tests for LSA Japanese Report Generation (Issue #15).

Verifies:
1. render_report.py correctly renders Japanese reports with standard cybersecurity terminology.
2. CLI options --lang ja and --lang all produce report.ja.md and report.md.
3. Custom output paths via --out-file.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
sys.path.insert(0, str(KIT / "scripts"))

from render_report import render  # noqa: E402


class TestJapaneseReportGeneration(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp_dir.name)

        # Prepare mock findings.json, coverage.json, and stack-profile.json
        findings_data = {
            "summary": {
                "total": 2,
                "by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
                "by_category": {"bola": 1, "sql_injection": 1},
                "by_status": {"confirmed": 2},
            },
            "findings": [
                {
                    "finding_id": "BOLA-orders-001",
                    "category": "bola",
                    "subtype": "missing_ownership_check",
                    "title": "受注詳細画面における所有権チェック欠如",
                    "location": {"file": "controllers/OrderController.php", "start_line": 42},
                    "endpoint": {"method": "GET", "path": "/api/orders/{id}"},
                    "evidence": [
                        {
                            "file": "controllers/OrderController.php",
                            "line": 45,
                            "code": "$order = Order::find($_GET['id']);",
                            "why": "セッションのユーザーIDと照合せず、パラメータのIDのみでレコードを取得している",
                        }
                    ],
                    "severity": "high",
                    "confidence": "confirmed",
                    "cwe": ["CWE-639"],
                    "owasp": ["API1:2023"],
                    "attack_scenario": "攻撃者BがURL内の受注IDを改変し、被害者Aの機密注文情報を閲覧する。",
                    "impact": "他顧客の個人情報および購入履歴の漏洩。",
                    "recommendation": "セッションから取得したTenantIdおよびOwnerUserIdをクエリ条件に付与する。",
                    "fix_example": "$order = Order::where('id', $id)->where('user_id', $currentUser->id)->firstOrFail();",
                    "status": "confirmed",
                },
                {
                    "finding_id": "INJ-search-001",
                    "category": "sql_injection",
                    "subtype": "string_concatenation",
                    "title": "検索処理における文字列連結によるSQLインジェクション",
                    "location": {"file": "models/SearchDao.php", "start_line": 20},
                    "endpoint": {"method": "GET", "path": "/api/search"},
                    "evidence": [
                        {
                            "file": "models/SearchDao.php",
                            "line": 22,
                            "code": "$sql = 'SELECT * FROM items WHERE name = ' . $_GET['q'];",
                            "why": "未検証の外部入力パラメータをSQL文へ直接結合している",
                        }
                    ],
                    "severity": "critical",
                    "confidence": "confirmed",
                    "cwe": ["CWE-89"],
                    "owasp": ["A03:2021"],
                    "attack_scenario": "クエリパラメータに' OR '1'='1を入力し、テーブル全件のデータを不正抽出する。",
                    "impact": "データベース内の全テーブル参照およびデータ改ざん。",
                    "recommendation": "プレースホルダーを用いたプリペアドステートメントを使用する。",
                    "status": "confirmed",
                },
            ],
        }

        coverage_data = {
            "inventoried": 15,
            "route_candidates": 20,
            "bola_routes_to_audit": 10,
            "injection_candidates": 8,
        }

        stack_data = {
            "stacks": [{"id": "php-legacy"}, {"id": "mysql"}]
        }

        (self.out / "findings.json").write_text(json.dumps(findings_data), encoding="utf-8")
        (self.out / "coverage.json").write_text(json.dumps(coverage_data), encoding="utf-8")
        (self.out / "stack-profile.json").write_text(json.dumps(stack_data), encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_render_japanese_content(self) -> None:
        """Verify Japanese report has expected headers, taxonomy labels, and sections."""
        report = render(self.out, "TestProject", lang="ja")

        # Verify Header and Metadata
        self.assertIn("# セキュリティ監査報告書 — TestProject", report)
        self.assertIn("機密区分: 社外秘 (CONFIDENTIAL)", report)
        self.assertIn("BOLA/IDOR（オブジェクトレベルの認可不備）", report)
        self.assertIn("インベントリ登録エンドポイント数", report)

        # Verify Sections
        self.assertIn("## 1. エグゼクティブサマリー", report)
        self.assertIn("## 2. 検出事項の概要", report)
        self.assertIn("## 3. 検出事項の詳細", report)
        self.assertIn("## 4. 根本的恒久対策", report)
        self.assertIn("## 5. 調査範囲と制約事項", report)
        self.assertIn("## 付録A — 検証により棄却された検出事項", report)
        self.assertIn("## 付録B — 監査手法とプロセス", report)

        # Verify Terminology Mapping
        self.assertIn("緊急 (Critical)", report)
        self.assertIn("高 (High)", report)
        self.assertIn("確定 (Confirmed)", report)
        self.assertIn("SQLインジェクション (SQLi)", report)
        self.assertIn("攻撃シナリオ:", report)
        self.assertIn("影響度 (Impact):", report)
        self.assertIn("脆弱性の根拠コード (Evidence):", report)
        self.assertIn("推奨対策 (Recommendation):", report)
        self.assertIn("本監査は侵入テスト（ペネトレーションテスト）ではありません。", report)

    def test_cli_lang_options(self) -> None:
        """Verify CLI produces report.ja.md with --lang ja and both with --lang all."""
        script = str(KIT / "scripts" / "render_report.py")

        # 1. Default (en) -> produces report.md only
        res = subprocess.run([sys.executable, script, str(self.out)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertTrue((self.out / "report.md").is_file())
        self.assertFalse((self.out / "report.ja.md").is_file())

        # 2. --lang ja -> produces report.ja.md
        res = subprocess.run([sys.executable, script, str(self.out), "--lang", "ja"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertTrue((self.out / "report.ja.md").is_file())
        ja_content = (self.out / "report.ja.md").read_text(encoding="utf-8")
        self.assertIn("# セキュリティ監査報告書", ja_content)

        # 3. --lang all -> produces both
        (self.out / "report.md").unlink()
        (self.out / "report.ja.md").unlink()
        res = subprocess.run([sys.executable, script, str(self.out), "--lang", "all"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertTrue((self.out / "report.md").is_file())
        self.assertTrue((self.out / "report.ja.md").is_file())

        # 4. --out-file custom.md
        custom_out = self.out / "custom-report.md"
        res = subprocess.run(
            [sys.executable, script, str(self.out), "--lang", "ja", "--out-file", str(custom_out)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertTrue(custom_out.is_file())
        self.assertIn("# セキュリティ監査報告書", custom_out.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
