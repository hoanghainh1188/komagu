#!/usr/bin/env python3
"""Render OUT/report.md or OUT/report.ja.md from findings.json, coverage.json and stack-profile.json.

Usage: render_report.py OUT [--project NAME] [--lang {en,ja,all}] [--out-file PATH]
Sections marked <!-- LLM: ... --> are filled by the reporter agent afterwards.
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import KIT_VERSION, read_json  # noqa: E402

SEV = ["critical", "high", "medium", "low", "info"]

JA_SEV_LABELS = {
    "critical": "緊急 (Critical)",
    "high": "高 (High)",
    "medium": "中 (Medium)",
    "low": "低 (Low)",
    "info": "情報 (Info)",
}

JA_CONF_LABELS = {
    "confirmed": "確定 (Confirmed)",
    "likely": "高確度 (Likely)",
    "medium": "中 (Medium)",
    "low": "低 (Low)",
}

JA_CATEGORY_LABELS = {
    "bola": "オブジェクトレベルの認可不備 (BOLA/IDOR)",
    "sql_injection": "SQLインジェクション (SQLi)",
    "nosql_injection": "NoSQLインジェクション (NoSQLi)",
}

JA_STATUS_LABELS = {
    "new": "新規 (New)",
    "confirmed": "確認済 (Confirmed)",
    "disputed": "係争中 (Disputed)",
    "fixed": "修正済 (Fixed)",
    "suppressed": "除外 (Suppressed)",
    "unverified": "未検証 (Unverified)",
    "rejected": "棄却 (Rejected)",
}


def md_escape(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def render(out: Path, project: str, lang: str = "en") -> str:
    if lang == "ja":
        return render_ja(out, project)
    return render_en(out, project)


def render_en(out: Path, project: str) -> str:
    fj = read_json(out / "findings.json")
    cov = read_json(out / "coverage.json") if (out / "coverage.json").exists() else {}
    prof = read_json(out / "stack-profile.json") if (out / "stack-profile.json").exists() else {"stacks": []}
    s = fj["summary"]
    active = [f for f in fj["findings"] if f["status"] != "rejected"]
    rejected = [f for f in fj["findings"] if f["status"] == "rejected"]
    L = []
    L += [f"# Security Audit Report — {project}", "",
          "> **Classification: CONFIDENTIAL.** AI-assisted static review. All findings require human review "
          "(record decisions in `review-log.md`, created from `templates/review-log.md`) before they are shared outside the team.", "",
          "| Item | Value |", "|---|---|",
          f"| Date | {dt.date.today().isoformat()} |",
          f"| Kit version | {KIT_VERSION} |",
          f"| Scope | BOLA/IDOR; SQL/HQL/NoSQL queries built from input |",
          f"| Stacks | {', '.join(x['id'] for x in prof['stacks']) or '-'} |",
          f"| Endpoints inventoried | {cov.get('inventoried', '-')} (candidates: {cov.get('route_candidates', '-')}) |",
          f"| Endpoints audited for BOLA | {cov.get('bola_routes_to_audit', '-')} |",
          f"| Injection candidates reviewed | {cov.get('injection_candidates', '-')} |", ""]
    L += ["## 1. Executive summary", "", "<!-- LLM: reporter agent writes max 8 bullets here -->", ""]
    L += ["## 2. Findings overview", "",
          "| Severity | " + " | ".join(SEV) + " |", "|---|" + "---|" * len(SEV),
          "| Count | " + " | ".join(str(s["by_severity"].get(x, 0)) for x in SEV) + " |", "",
          "| Category | Count |", "|---|---|"]
    L += [f"| {c} | {n} |" for c, n in s["by_category"].items()]
    L += ["", f"Status: " + ", ".join(f"{k}={v}" for k, v in s["by_status"].items()), ""]
    L += ["## 3. Findings", "",
          "| ID | Sev | Conf | Status | Category | Endpoint | Location | Title |", "|---|---|---|---|---|---|---|---|"]
    for f in active:
        ep = f.get("endpoint") or {}
        L.append(f"| {f['finding_id']} | {f['severity']} | {f['confidence']} | {f['status']} | {f['category']} | "
                 f"{md_escape(ep.get('method', ''))} {md_escape(ep.get('path', ''))} | "
                 f"`{f['location']['file']}:{f['location']['start_line']}` | {md_escape(f['title'])} |")
    L.append("")
    for f in active:
        ep = f.get("endpoint") or {}
        L += [f"### {f['finding_id']} — {f['title']}", "",
              f"- **Severity / confidence:** {f['severity']} / {f['confidence']}  ",
              f"- **Status:** {f['status']}  ",
              f"- **Category:** {f['category']} ({f['subtype']}) — {', '.join(f.get('cwe', []))} {', '.join(f.get('owasp', []))}  ",
              f"- **Endpoint:** {ep.get('method', '-')} {ep.get('path', '-')}  ",
              f"- **Location:** `{f['location']['file']}:{f['location']['start_line']}`", ""]
        if f.get("attack_scenario"):
            L += [f"**Scenario.** {f['attack_scenario']}", ""]
        if f.get("impact"):
            L += [f"**Impact.** {f['impact']}", ""]
        L += ["**Evidence.**", ""]
        for e in f["evidence"]:
            code = (e.get("code") or "").replace("`", "'")
            L.append(f"- `{e['file']}:{e['line']}` — {e['why']}" + (f"  \n  `{code}`" if code else ""))
        L.append("")
        if f.get("data_flow"):
            L += ["**Data flow.** " + " → ".join(f["data_flow"]), ""]
        L += [f"**Recommendation.** {f['recommendation']}", ""]
        if f.get("fix_example"):
            L += ["```", f["fix_example"], "```", ""]
        v = f.get("verification") or {}
        if v:
            L += [f"*Verifier:* {v.get('verdict')} — checked: {', '.join(v.get('checked') or [])}. {v.get('notes') or ''}", ""]
    L += ["## 4. Systemic fixes", "", "<!-- LLM: reporter agent writes max 5 systemic fixes here -->", ""]
    L += ["## 5. Coverage and limitations", ""]
    for k in ("missing_from_inventory", "bola_routes_without_verdict", "injection_candidates_without_verdict", "findings_without_verification"):
        if k in cov:
            L.append(f"- {k.replace('_', ' ')}: {len(cov[k])}" + (f" ({', '.join(cov[k][:10])}{' …' if len(cov[k]) > 10 else ''})" if cov[k] else ""))
    L += ["", "<!-- LLM: reporter agent lists limitations here -->", ""]
    L += ["## Appendix A — Findings rejected by the verifier", ""]
    if rejected:
        L += ["| ID | Location | Reason |", "|---|---|---|"]
        for f in rejected:
            v = f.get("verification") or {}
            L.append(f"| {f['finding_id']} | `{f['location']['file']}:{f['location']['start_line']}` | {md_escape(v.get('notes') or '')} |")
    else:
        L.append("None.")
    L += ["", "## Appendix B — Method", "",
          "1. Deterministic pre-scan (stack detection, endpoint candidates, query-building candidates).",
          "2. AI agents: auth-model extraction, route inventory, BOLA audit, injection audit.",
          "3. Independent AI verifier tries to refute each finding.",
          "4. Human review and sign-off (`review-log.md`).", "",
          "This is not a penetration test. Absence of findings does not prove absence of vulnerabilities.", ""]
    return "\n".join(L)


def render_ja(out: Path, project: str) -> str:
    fj = read_json(out / "findings.json")
    cov = read_json(out / "coverage.json") if (out / "coverage.json").exists() else {}
    prof = read_json(out / "stack-profile.json") if (out / "stack-profile.json").exists() else {"stacks": []}
    s = fj["summary"]
    active = [f for f in fj["findings"] if f["status"] != "rejected"]
    rejected = [f for f in fj["findings"] if f["status"] == "rejected"]
    L = []
    L += [f"# セキュリティ監査報告書 — {project}", "",
          "> **機密区分: 社外秘 (CONFIDENTIAL)** 本報告書はAI支援による静的コードレビュー結果です。"
          "外部共有前に必ず人間のレビュー担当者による確認・承認が必要です"
          "（判定結果は `review-log.md` に記録）。", "",
          "| 項目 | 値 |", "|---|---|",
          f"| 診断実施日 | {dt.date.today().isoformat()} |",
          f"| 監査キットバージョン | {KIT_VERSION} |",
          f"| 監査対象スコープ | BOLA/IDOR（オブジェクトレベルの認可不備）および外部入力によるSQL/HQL/NoSQLクエリ構築 |",
          f"| 検出技術スタック | {', '.join(x['id'] for x in prof['stacks']) or '-'} |",
          f"| インベントリ登録エンドポイント数 | {cov.get('inventoried', '-')} (候補数: {cov.get('route_candidates', '-')}) |",
          f"| BOLA監査対象エンドポイント数 | {cov.get('bola_routes_to_audit', '-')} |",
          f"| レビュー対象インジェクション候補数 | {cov.get('injection_candidates', '-')} |", ""]
    L += ["## 1. エグゼクティブサマリー", "",
          "<!-- LLM: reporter agent writes max 8 bullets here (日本語で記載: 全体のリスクレベル、事業影響の大きい上位3件の検出事項、根本原因) -->", ""]
    L += ["## 2. 検出事項の概要", "",
          "| 重要度 | " + " | ".join(JA_SEV_LABELS[x] for x in SEV) + " |",
          "|---|" + "---|" * len(SEV),
          "| 件数 | " + " | ".join(str(s["by_severity"].get(x, 0)) for x in SEV) + " |", "",
          "| 脆弱性分類 | 件数 |", "|---|---|"]
    for c, n in s["by_category"].items():
        cat_label = JA_CATEGORY_LABELS.get(c, c)
        L.append(f"| {cat_label} | {n} |")
    status_summary = ", ".join(f"{JA_STATUS_LABELS.get(k, k)}={v}" for k, v in s["by_status"].items())
    L += ["", f"ステータス内訳: {status_summary}", ""]
    L += ["## 3. 検出事項の詳細", "",
          "| ID | 重要度 | 確信度 | ステータス | 脆弱性分類 | 対象エンドポイント | 該当箇所 | タイトル |",
          "|---|---|---|---|---|---|---|---|"]
    for f in active:
        ep = f.get("endpoint") or {}
        sev_label = JA_SEV_LABELS.get(f['severity'], f['severity'])
        conf_label = JA_CONF_LABELS.get(f['confidence'], f['confidence'])
        status_label = JA_STATUS_LABELS.get(f['status'], f['status'])
        cat_label = JA_CATEGORY_LABELS.get(f['category'], f['category'])
        L.append(f"| {f['finding_id']} | {sev_label} | {conf_label} | {status_label} | {cat_label} | "
                 f"{md_escape(ep.get('method', ''))} {md_escape(ep.get('path', ''))} | "
                 f"`{f['location']['file']}:{f['location']['start_line']}` | {md_escape(f['title'])} |")
    L.append("")
    for f in active:
        ep = f.get("endpoint") or {}
        sev_label = JA_SEV_LABELS.get(f['severity'], f['severity'])
        conf_label = JA_CONF_LABELS.get(f['confidence'], f['confidence'])
        status_label = JA_STATUS_LABELS.get(f['status'], f['status'])
        cat_label = JA_CATEGORY_LABELS.get(f['category'], f['category'])
        L += [f"### {f['finding_id']} — {f['title']}", "",
              f"- **重要度 / 確信度:** {sev_label} / {conf_label}  ",
              f"- **ステータス:** {status_label}  ",
              f"- **脆弱性分類:** {cat_label} ({f['subtype']}) — {', '.join(f.get('cwe', []))} {', '.join(f.get('owasp', []))}  ",
              f"- **対象エンドポイント:** {ep.get('method', '-')} {ep.get('path', '-')}  ",
              f"- **該当箇所:** `{f['location']['file']}:{f['location']['start_line']}`", ""]
        if f.get("attack_scenario"):
            L += [f"**攻撃シナリオ:** {f['attack_scenario']}", ""]
        if f.get("impact"):
            L += [f"**影響度 (Impact):** {f['impact']}", ""]
        L += ["**脆弱性の根拠コード (Evidence):**", ""]
        for e in f["evidence"]:
            code = (e.get("code") or "").replace("`", "'")
            L.append(f"- `{e['file']}:{e['line']}` — {e['why']}" + (f"  \n  `{code}`" if code else ""))
        L.append("")
        if f.get("data_flow"):
            L += ["**データフロー:** " + " → ".join(f["data_flow"]), ""]
        L += [f"**推奨対策 (Recommendation):** {f['recommendation']}", ""]
        if f.get("fix_example"):
            L += ["```", f["fix_example"], "```", ""]
        v = f.get("verification") or {}
        if v:
            verdict_label = JA_STATUS_LABELS.get(v.get('verdict'), v.get('verdict'))
            L += [f"*検証結果 (Verifier):* {verdict_label} — 確認対象: {', '.join(v.get('checked') or [])}. {v.get('notes') or ''}", ""]
    L += ["## 4. 根本的恒久対策", "",
          "<!-- LLM: reporter agent writes max 5 systemic fixes here (日本語で記載: 共通認可ヘルパー、パラメータバインディングDAO等のアーキテクチャ改修案と工数見積 S/M/L) -->", ""]
    L += ["## 5. 調査範囲と制約事項", ""]
    for k in ("missing_from_inventory", "bola_routes_without_verdict", "injection_candidates_without_verdict", "findings_without_verification"):
        if k in cov:
            L.append(f"- {k.replace('_', ' ')}: {len(cov[k])}" + (f" ({', '.join(cov[k][:10])}{' …' if len(cov[k]) > 10 else ''})" if cov[k] else ""))
    L += ["", "<!-- LLM: reporter agent lists limitations here (日本語で記載: ストアドプロシージャ、動的インクルード、設定による除外パス等) -->", ""]
    L += ["## 付録A — 検証により棄却された検出事項", ""]
    if rejected:
        L += ["| ID | 該当箇所 | 棄却理由 |", "|---|---|---|"]
        for f in rejected:
            v = f.get("verification") or {}
            L.append(f"| {f['finding_id']} | `{f['location']['file']}:{f['location']['start_line']}` | {md_escape(v.get('notes') or '')} |")
    else:
        L.append("なし。")
    L += ["", "## 付録B — 監査手法とプロセス", "",
          "1. **決定論的静的事前スキャン**: 技術スタック判定、エンドポイント候補抽出、クエリ生成箇所抽出。",
          "2. **独立したAI監査エージェント群**: 認可モデル抽出、エンドポイント詳細精査、BOLA監査、インジェクション監査。",
          "3. **懐疑的AI検証エージェント（Skeptic）**: 検出事項に対する反論テストを実施し、既存の防御制御による誤検知を排除。",
          "4. **人間のエンジニアによる最終確認と承認**: `review-log.md` による判定記録とサインオフ。", "",
          "**免責事項:** 本監査は侵入テスト（ペネトレーションテスト）ではありません。脆弱性が検出されなかったことは、脆弱性の非存在を証明するものではありません。", ""]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out", help="Path to output directory containing findings.json")
    ap.add_argument("--project", help="Project name displayed in header")
    ap.add_argument(
        "--lang",
        choices=["en", "ja", "all"],
        default="en",
        help="Language for report generation: en (default), ja (Japanese), or all",
    )
    ap.add_argument("--out-file", help="Explicit output file path")
    a = ap.parse_args()

    out = Path(a.out)
    project = a.project or out.resolve().name

    if a.out_file:
        out_path = Path(a.out_file)
        lang = a.lang if a.lang in ("en", "ja") else "en"
        out_path.write_text(render(out, project, lang=lang), encoding="utf-8")
        print(f"wrote {out_path}")
        return 0

    if a.lang in ("en", "all"):
        en_path = out / "report.md"
        en_path.write_text(render(out, project, lang="en"), encoding="utf-8")
        print(f"wrote {en_path}")

    if a.lang in ("ja", "all"):
        ja_path = out / "report.ja.md"
        ja_path.write_text(render(out, project, lang="ja"), encoding="utf-8")
        print(f"wrote {ja_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
