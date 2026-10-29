#!/usr/bin/env python3
"""Render OUT/report.md, OUT/report.ja.md, or OUT/report.html from findings.json, coverage.json and stack-profile.json.

Usage: render_report.py OUT [--project NAME] [--lang {en,ja,all}] [--format {md,html,all}] [--out-file PATH]
Sections marked <!-- LLM: ... --> in Markdown reports are filled by the reporter agent afterwards.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import KIT_VERSION, read_json  # noqa: E402
from trend import render_trend_html, render_trend_md  # noqa: E402

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
    "high": "高 (High)",
    "medium": "中 (Medium)",
    "low": "低 (Low)",
}

JA_CATEGORY_LABELS = {
    "bola": "オブジェクトレベルの認可不備 (BOLA/IDOR)",
    "sql_injection": "SQLインジェクション (SQLi)",
    "nosql_injection": "NoSQLインジェクション (NoSQLi)",
    "bfla": "機能レベルの認可不備 (BFLA)",
    "mass_assignment": "マスアサインメント (Mass Assignment)",
}

JA_STATUS_LABELS = {
    "new": "新規 (New)",
    "confirmed": "確認済 (Confirmed)",
    "needs_review": "要確認 (Needs Review)",
    "disputed": "係争中 (Disputed)",
    "fixed": "修正済 (Fixed)",
    "suppressed": "除外 (Suppressed)",
    "unverified": "未検証 (Unverified)",
    "rejected": "棄却 (Rejected)",
}


def _load_trend(out: Path) -> Dict[str, Any]:
    """Trend from baseline.py (OUT/baseline-diff.json); empty when no baseline step ran."""
    path = out / "baseline-diff.json"
    if not path.is_file():
        return {}
    try:
        trend = read_json(path).get("trend") or {}
    except (OSError, ValueError, AttributeError):
        return {}
    return trend if trend.get("history") else {}


def md_escape(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


# Coverage rows for BFLA / mass assignment: (coverage key, EN label, JA label).
# Shown only when coverage.json has the key (audits from kit versions with phase 4c).
PRIVILEGE_COVERAGE_ROWS = (
    ("bfla_routes_to_audit", "Privileged routes audited for BFLA", "BFLA監査対象の特権エンドポイント数"),
    ("mass_candidates", "Mass assignment candidates reviewed", "レビュー対象マスアサインメント候補数"),
)

DEFAULT_FIX = {
    "bfla": "// Check the required role from the session before the handler runs (one shared admin guard).",
    "mass_assignment": "// Copy only editable fields from the request (allow-list / DTO); set privileged fields on the server.",
}
DEFAULT_FIX_OTHER = "// Parameterize query and bind tenant/user ownership predicate from session."


def privilege_coverage_rows(cov: Dict[str, Any], lang: str) -> List[str]:
    """Markdown table rows for BFLA / mass assignment coverage, if present."""
    col = 2 if lang == "ja" else 1
    return [f"| {row[col]} | {cov[row[0]]} |" for row in PRIVILEGE_COVERAGE_ROWS if row[0] in cov]


def render(out: Path, project: str, lang: str = "en", fmt: str = "md") -> str:
    if fmt == "html":
        return render_html(out, project, default_lang=lang if lang in ("en", "ja") else "en")
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
          f"| Scope | BOLA/IDOR; SQL/HQL/NoSQL queries built from input; BFLA (missing role checks); mass assignment |",
          f"| Stacks | {', '.join(x['id'] for x in prof['stacks']) or '-'} |",
          f"| Endpoints inventoried | {cov.get('inventoried', '-')} (candidates: {cov.get('route_candidates', '-')}) |",
          f"| Endpoints audited for BOLA | {cov.get('bola_routes_to_audit', '-')} |",
          f"| Injection candidates reviewed | {cov.get('injection_candidates', '-')} |"]
    L += privilege_coverage_rows(cov, "en") + [""]
    L += ["## 1. Executive summary", "", "<!-- LLM: reporter agent writes max 8 bullets here -->", ""]
    L += ["## 2. Findings overview", "",
          "| Severity | " + " | ".join(SEV) + " |", "|---|" + "---|" * len(SEV),
          "| Count | " + " | ".join(str(s["by_severity"].get(x, 0)) for x in SEV) + " |", "",
          "| Category | Count |", "|---|---|"]
    L += [f"| {c} | {n} |" for c, n in s["by_category"].items()]
    L += ["", f"Status: " + ", ".join(f"{k}={v}" for k, v in s["by_status"].items()), ""]
    trend = _load_trend(out)
    if trend:
        L += render_trend_md(trend, "en")
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
    for k in ("missing_from_inventory", "bola_routes_without_verdict", "injection_candidates_without_verdict",
              "bfla_routes_without_verdict", "mass_candidates_without_verdict", "findings_without_verification"):
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
          f"| 監査対象スコープ | BOLA/IDOR（オブジェクトレベルの認可不備）、外部入力によるSQL/HQL/NoSQLクエリ構築、BFLA（機能レベルの認可不備）、マスアサインメント |",
          f"| 検出技術スタック | {', '.join(x['id'] for x in prof['stacks']) or '-'} |",
          f"| インベントリ登録エンドポイント数 | {cov.get('inventoried', '-')} (候補数: {cov.get('route_candidates', '-')}) |",
          f"| BOLA監査対象エンドポイント数 | {cov.get('bola_routes_to_audit', '-')} |",
          f"| レビュー対象インジェクション候補数 | {cov.get('injection_candidates', '-')} |"]
    L += privilege_coverage_rows(cov, "ja") + [""]
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
    trend = _load_trend(out)
    if trend:
        L += render_trend_md(trend, "ja")
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
    for k in ("missing_from_inventory", "bola_routes_without_verdict", "injection_candidates_without_verdict",
              "bfla_routes_without_verdict", "mass_candidates_without_verdict", "findings_without_verification"):
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


def _compute_overall_risk(by_sev: Dict[str, int]) -> Dict[str, str]:
    """Compute overall risk rating badge metadata."""
    if by_sev.get("critical", 0) > 0:
        return {"level": "critical", "en": "CRITICAL RISK", "ja": "総合リスク: 緊急 (CRITICAL)"}
    if by_sev.get("high", 0) > 0:
        return {"level": "high", "en": "HIGH RISK", "ja": "総合リスク: 高 (HIGH)"}
    if by_sev.get("medium", 0) > 0:
        return {"level": "medium", "en": "MEDIUM RISK", "ja": "総合リスク: 中 (MEDIUM)"}
    if by_sev.get("low", 0) > 0:
        return {"level": "low", "en": "LOW RISK", "ja": "総合リスク: 低 (LOW)"}
    return {"level": "info", "en": "MINIMAL RISK", "ja": "総合リスク: 情報 (MINIMAL)"}


def _build_severity_donut_svg(by_sev: Dict[str, int], total_active: int) -> str:
    """Build an inline SVG donut chart for severity distribution."""
    colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#2563eb",
        "info": "#64748b",
    }
    radius = 60
    circumference = 2 * 3.141592653589793 * radius
    if total_active <= 0:
        return (
            '<svg viewBox="0 0 160 160" class="donut-svg" role="img" aria-label="Severity DistributionChart">'
            '<circle cx="80" cy="80" r="60" fill="none" stroke="#e2e8f0" stroke-width="20"/>'
            '<text x="80" y="85" text-anchor="middle" class="donut-total">0</text>'
            "</svg>"
        )

    offset = 0.0
    segments: List[str] = []
    for s_key in SEV:
        count = by_sev.get(s_key, 0)
        if count <= 0:
            continue
        seg_len = (count / total_active) * circumference
        segments.append(
            f'<circle cx="80" cy="80" r="{radius}" fill="none" stroke="{colors[s_key]}" '
            f'stroke-width="20" stroke-dasharray="{seg_len:.2f} {circumference:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 80 80)" />'
        )
        offset += seg_len

    return (
        '<svg viewBox="0 0 160 160" class="donut-svg" role="img" aria-label="Severity Distribution Chart">'
        '<circle cx="80" cy="80" r="60" fill="none" stroke="#f1f5f9" stroke-width="20"/>'
        + "".join(segments)
        + f'<text x="80" y="76" text-anchor="middle" class="donut-total">{total_active}</text>'
        + '<text x="80" y="96" text-anchor="middle" class="donut-sub" data-en="Active" data-ja="有効検出">Active</text>'
        + "</svg>"
    )


def _build_category_bar_svg(by_cat: Dict[str, int], total_active: int) -> str:
    """Build an inline SVG horizontal bar chart for vulnerability category & CWE breakdown."""
    cats = [
        ("bola", "BOLA / IDOR (CWE-639)", "認可不備 BOLA (CWE-639)", "#7c3aed"),
        ("sql_injection", "SQL Injection (CWE-89)", "SQLインジェクション (CWE-89)", "#dc2626"),
        ("nosql_injection", "NoSQL Injection (CWE-943)", "NoSQLインジェクション (CWE-943)", "#ea580c"),
    ]
    # Newer categories get a bar only when the scan found them
    cats += [
        c for c in (
            ("bfla", "BFLA (CWE-285)", "機能レベル認可不備 BFLA (CWE-285)", "#0891b2"),
            ("mass_assignment", "Mass Assignment (CWE-915)", "マスアサインメント (CWE-915)", "#ca8a04"),
        )
        if by_cat.get(c[0], 0) > 0
    ]
    denom = max(total_active, 1)
    rows: List[str] = []
    y = 20
    for key, label_en, label_ja, color in cats:
        count = by_cat.get(key, 0)
        pct = int(round((count / denom) * 100)) if total_active > 0 else 0
        bar_w = max(int((count / denom) * 240), 4 if count > 0 else 0)
        rows.append(
            f'<g transform="translate(0, {y})">'
            f'<text x="0" y="14" class="bar-label" data-en="{html.escape(label_en)}" data-ja="{html.escape(label_ja)}">{html.escape(label_en)}</text>'
            f'<text x="360" y="14" text-anchor="end" class="bar-count">{count} ({pct}%)</text>'
            f'<rect x="0" y="22" width="360" height="12" rx="6" fill="#f1f5f9" />'
            f'<rect x="0" y="22" width="{bar_w}" height="12" rx="6" fill="{color}" />'
            f"</g>"
        )
        y += 50
    return (
        f'<svg viewBox="0 0 360 {y}" class="bar-svg" role="img" aria-label="Category Breakdown Chart">'
        + "".join(rows)
        + "</svg>"
    )


def render_html(out: Path, project: str, default_lang: str = "en") -> str:
    """Render a self-contained, zero-dependency interactive HTML5 security audit dashboard."""
    fj = read_json(out / "findings.json")
    cov = read_json(out / "coverage.json") if (out / "coverage.json").exists() else {}
    prof = read_json(out / "stack-profile.json") if (out / "stack-profile.json").exists() else {"stacks": []}
    s = fj["summary"]
    active: List[Dict[str, Any]] = [f for f in fj["findings"] if f["status"] != "rejected"]
    rejected: List[Dict[str, Any]] = [f for f in fj["findings"] if f["status"] == "rejected"]

    by_sev = {k: int(s.get("by_severity", {}).get(k, 0)) for k in SEV}
    by_cat = {k: int(v) for k, v in s.get("by_category", {}).items()}
    total_active = len(active)
    risk = _compute_overall_risk(by_sev)
    audit_date = dt.date.today().isoformat()
    stacks_list = [x["id"] for x in prof.get("stacks", [])] or ["-"]

    # Extract distinct stack prefixes from finding file paths for stack filter dropdown
    detected_prefixes = sorted(
        {
            f["location"]["file"].split("/")[0]
            for f in active
            if "/" in f.get("location", {}).get("file", "")
        }
    )

    donut_svg = _build_severity_donut_svg(by_sev, total_active)
    cat_svg = _build_category_bar_svg(by_cat, total_active)
    priv_kpi = "".join(
        f" | {label}: {html.escape(str(cov[key]))}"
        for key, label in (("bfla_routes_to_audit", "BFLA"), ("mass_candidates", "Mass"))
        if key in cov
    )
    extra_cat_options = "\n        ".join(
        f'<option value="{key}" data-en="{en}" data-ja="{ja}">{en}</option>'
        for key, en, ja in (
            ("bfla", "BFLA (CWE-285)", "機能レベル認可不備 BFLA (CWE-285)"),
            ("mass_assignment", "Mass Assignment (CWE-915)", "マスアサインメント (CWE-915)"),
        )
        if by_cat.get(key, 0) > 0
    )
    trend = _load_trend(out)
    trend_card = render_trend_html(trend) if trend else ""

    # Build severity legend rows
    sev_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#2563eb",
        "info": "#64748b",
    }
    sev_legend_items: List[str] = []
    for k in SEV:
        c_val = by_sev.get(k, 0)
        pct = int(round((c_val / max(total_active, 1)) * 100)) if total_active > 0 else 0
        en_lbl = k.capitalize()
        ja_lbl = JA_SEV_LABELS.get(k, k)
        sev_legend_items.append(
            f'<div class="legend-row">'
            f'<span class="legend-dot" style="background:{sev_colors[k]}"></span>'
            f'<span class="legend-name" data-en="{html.escape(en_lbl)}" data-ja="{html.escape(ja_lbl)}">{html.escape(en_lbl)}</span>'
            f'<span class="legend-val">{c_val} <small>({pct}%)</small></span>'
            f"</div>"
        )

    # Build findings rows + expandable drawers
    finding_rows_html: List[str] = []
    for idx, f in enumerate(active):
        fid = f["finding_id"]
        sev = f["severity"]
        conf = f["confidence"]
        status = f["status"]
        cat = f["category"]
        subtype = f.get("subtype", "")
        ep = f.get("endpoint") or {}
        method = ep.get("method", "GET")
        path = ep.get("path", "-")
        loc_file = f["location"]["file"]
        loc_line = f["location"]["start_line"]
        stack_prefix = loc_file.split("/")[0] if "/" in loc_file else "default"
        title = f["title"]
        cwe_list = ", ".join(f.get("cwe", []))
        owasp_list = ", ".join(f.get("owasp", []))
        scenario = f.get("attack_scenario") or "-"
        impact = f.get("impact") or "-"
        rec = f.get("recommendation") or "-"
        fix_code = f.get("fix_example") or DEFAULT_FIX.get(cat, DEFAULT_FIX_OTHER)
        data_flow = " → ".join(f.get("data_flow") or [])

        evidence_items: List[str] = []
        for ev in f.get("evidence", []):
            ev_loc = f"{ev.get('file', '')}:{ev.get('line', '')}"
            ev_why = ev.get("why", "")
            ev_code = ev.get("code", "")
            evidence_items.append(
                f'<div class="ev-item">'
                f'<div class="ev-meta"><code>{html.escape(ev_loc)}</code> — {html.escape(ev_why)}</div>'
                + (f'<pre class="code-block vuln-code"><code>{html.escape(ev_code)}</code></pre>' if ev_code else "")
                + "</div>"
            )

        v = f.get("verification") or {}
        v_verdict = v.get("verdict", status)
        v_checked = ", ".join(v.get("checked") or []) or "-"
        v_notes = v.get("notes") or "-"

        sev_ja = JA_SEV_LABELS.get(sev, sev)
        cat_ja = JA_CATEGORY_LABELS.get(cat, cat)
        status_ja = JA_STATUS_LABELS.get(status, status)

        search_blob = f"{fid} {sev} {cat} {subtype} {method} {path} {loc_file}:{loc_line} {title} {cwe_list} {owasp_list}".lower()

        finding_rows_html.append(
            f'<tr class="finding-row" data-idx="{idx}" data-sev="{html.escape(sev)}" '
            f'data-cat="{html.escape(cat)}" data-stack="{html.escape(stack_prefix)}" '
            f'data-search="{html.escape(search_blob)}" onclick="toggleDrawer({idx})">'
            f'<td class="mono font-semibold">{html.escape(fid)}</td>'
            f'<td><span class="badge sev-{html.escape(sev)}" data-en="{html.escape(sev.upper())}" data-ja="{html.escape(sev_ja)}">{html.escape(sev.upper())}</span></td>'
            f'<td><span class="status-pill status-{html.escape(status)}" data-en="{html.escape(status)}" data-ja="{html.escape(status_ja)}">{html.escape(status)}</span></td>'
            f'<td><div class="cat-cell" data-en="{html.escape(cat)}" data-ja="{html.escape(cat_ja)}">{html.escape(cat)}</div>'
            f'<div class="cwe-sub">{html.escape(cwe_list)} {html.escape(owasp_list)}</div></td>'
            f'<td class="mono"><span class="method-tag">{html.escape(str(method))}</span> {html.escape(str(path))}</td>'
            f'<td class="mono loc-cell">{html.escape(loc_file)}:{loc_line}</td>'
            f'<td class="title-cell">{html.escape(title)}</td>'
            f'<td class="action-cell"><button type="button" class="btn-inspect" onclick="event.stopPropagation(); toggleDrawer({idx})" '
            f'data-en="Inspect &amp; Fix" data-ja="詳細・対策">Inspect &amp; Fix</button></td>'
            f"</tr>"
            f'<tr id="drawer-{idx}" class="drawer-row" style="display:none;">'
            f'<td colspan="8">'
            f'<div class="drawer-panel">'
            f'<div class="drawer-grid">'
            f'<div class="drawer-col">'
            f'<h4 data-en="Attack Scenario &amp; Business Impact" data-ja="攻撃シナリオ・事業影響 (Attack Scenario &amp; Impact)">Attack Scenario &amp; Business Impact</h4>'
            f'<p><strong>Scenario:</strong> {html.escape(scenario)}</p>'
            f'<p><strong>Impact:</strong> {html.escape(impact)}</p>'
            + (f'<p><strong>Data Flow:</strong> <code class="flow-code">{html.escape(data_flow)}</code></p>' if data_flow else "")
            + f'<h4 data-en="Vulnerable Code Evidence" data-ja="脆弱性の根拠コード (Evidence)">Vulnerable Code Evidence</h4>'
            + "".join(evidence_items)
            + f"</div>"
            f'<div class="drawer-col">'
            f'<div class="remediation-header">'
            f'<h4 data-en="Recommended Remediation &amp; Patch" data-ja="推奨対策・修正コード例 (Remediation)">Recommended Remediation &amp; Patch</h4>'
            f'<button type="button" class="btn-copy" onclick="copyPatch({idx}, this)" '
            f'data-en="Copy Remediation Patch" data-ja="修正コードをコピー">Copy Remediation Patch</button>'
            f"</div>"
            f'<p class="rec-text">{html.escape(rec)}</p>'
            f'<pre class="code-block fix-code"><code id="patch-code-{idx}">{html.escape(fix_code)}</code></pre>'
            f'<div class="verifier-box">'
            f'<strong data-en="Skeptic Verifier Audit Trail:" data-ja="懐疑的AI検証エージェント判定履歴 (Verifier):">Skeptic Verifier Audit Trail:</strong> '
            f'<span class="mono">{html.escape(str(v_verdict))}</span> '
            f'(Checked: <code>{html.escape(v_checked)}</code>) — {html.escape(v_notes)}'
            f"</div>"
            f"</div>"
            f"</div>"
            f"</div>"
            f"</td>"
            f"</tr>"
        )

    # Rejected rows
    rejected_rows_html: List[str] = []
    for rf in rejected:
        rv = rf.get("verification") or {}
        rejected_rows_html.append(
            f"<tr>"
            f'<td class="mono">{html.escape(rf["finding_id"])}</td>'
            f'<td class="mono">{html.escape(rf["location"]["file"])}:{rf["location"]["start_line"]}</td>'
            f'<td>{html.escape(rv.get("notes") or "-")}</td>'
            f"</tr>"
        )

    stack_options_html = "".join(
        f'<option value="{html.escape(sp)}">{html.escape(sp)}</option>' for sp in detected_prefixes
    )

    stacks_badges_html = "".join(
        f'<span class="stack-badge">{html.escape(st)}</span>' for st in stacks_list
    )

    return f"""<!DOCTYPE html>
<html lang="{html.escape(default_lang)}">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Komainu Security Audit Dashboard — {html.escape(project)}</title>
<style>
  :root {{
    --bg: #f8fafc;
    --card: #ffffff;
    --border: #e2e8f0;
    --text: #0f172a;
    --muted: #475569;
    --primary: #1e293b;
    --accent: #2563eb;
    --crit: #dc2626;
    --crit-bg: #fef2f2;
    --high: #ea580c;
    --high-bg: #fff7ed;
    --med: #d97706;
    --med-bg: #fffbeb;
    --low: #2563eb;
    --low-bg: #eff6ff;
    --ok: #16a34a;
    --ok-bg: #f0fdf4;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Hiragino Sans", "Noto Sans JP", sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }}
  .container {{
    max-width: 1360px;
    margin: 0 auto;
    padding: 24px;
  }}
  .exec-header {{
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    color: #f8fafc;
    border-radius: 14px;
    padding: 24px 28px;
    margin-bottom: 24px;
    box-shadow: 0 10px 25px -5px rgba(15, 23, 42, 0.25);
  }}
  .header-top {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 16px;
  }}
  .brand-kicker {{
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #94a3b8;
    margin-bottom: 4px;
  }}
  .exec-title {{
    margin: 0 0 8px 0;
    font-size: 26px;
    font-weight: 700;
  }}
  .conf-banner {{
    display: inline-block;
    background: rgba(220, 38, 38, 0.2);
    border: 1px solid rgba(248, 113, 113, 0.45);
    color: #fecaca;
    font-size: 12px;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: 999px;
  }}
  .header-controls {{
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }}
  .risk-pill {{
    padding: 6px 14px;
    border-radius: 8px;
    font-weight: 700;
    font-size: 13px;
    letter-spacing: 0.03em;
  }}
  .risk-critical {{ background: #dc2626; color: #fff; }}
  .risk-high {{ background: #ea580c; color: #fff; }}
  .risk-medium {{ background: #d97706; color: #fff; }}
  .risk-low {{ background: #2563eb; color: #fff; }}
  .risk-info {{ background: #475569; color: #fff; }}
  .btn-ctrl {{
    background: rgba(255, 255, 255, 0.12);
    color: #f8fafc;
    border: 1px solid rgba(255, 255, 255, 0.25);
    padding: 7px 14px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 13px;
    font-weight: 600;
    transition: background 0.15s;
  }}
  .btn-ctrl:hover {{ background: rgba(255, 255, 255, 0.22); }}
  .meta-bar {{
    margin-top: 18px;
    padding-top: 14px;
    border-top: 1px solid rgba(255, 255, 255, 0.12);
    display: flex;
    flex-wrap: wrap;
    gap: 20px;
    font-size: 13px;
    color: #cbd5e1;
  }}
  .stack-badge {{
    display: inline-block;
    background: rgba(255, 255, 255, 0.14);
    color: #e2e8f0;
    padding: 2px 8px;
    border-radius: 6px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 11px;
    margin-right: 4px;
  }}
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }}
  .kpi-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px 18px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
  }}
  .kpi-label {{
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 6px;
  }}
  .kpi-val {{
    font-size: 28px;
    font-weight: 800;
  }}
  .kpi-sub {{
    font-size: 12px;
    color: var(--muted);
    margin-top: 2px;
  }}
  .charts-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
    gap: 20px;
    margin-bottom: 24px;
  }}
  .card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    margin-bottom: 24px;
  }}
  .card-title {{
    margin: 0 0 16px 0;
    font-size: 17px;
    font-weight: 700;
    color: var(--text);
  }}
  .donut-wrap {{
    display: flex;
    align-items: center;
    gap: 24px;
    flex-wrap: wrap;
  }}
  .donut-svg {{ width: 155px; height: 155px; flex-shrink: 0; }}
  .donut-total {{ font-size: 26px; font-weight: 800; fill: #0f172a; }}
  .donut-sub {{ font-size: 11px; font-weight: 600; fill: #64748b; text-transform: uppercase; }}
  .legend-list {{ flex: 1; min-width: 180px; }}
  .legend-row {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 5px 0;
    border-bottom: 1px dashed #f1f5f9;
    font-size: 13px;
  }}
  .legend-dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
    display: inline-block;
    margin-right: 8px;
  }}
  .legend-name {{ flex: 1; font-weight: 500; }}
  .legend-val {{ font-weight: 700; }}
  .bar-svg {{ width: 100%; max-width: 440px; height: auto; }}
  .trend-svg {{ width: 100%; max-width: 520px; height: auto; display: block; margin-bottom: 16px; }}
  .bar-label {{ font-size: 12px; font-weight: 600; fill: #1e293b; }}
  .bar-count {{ font-size: 12px; font-weight: 700; fill: #475569; }}
  .filter-bar {{
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 16px;
    align-items: center;
  }}
  .filter-input, .filter-select {{
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: 8px;
    font-size: 13px;
    background: #fff;
    color: var(--text);
  }}
  .filter-input {{ flex: 1; min-width: 220px; }}
  .table-wrap {{ overflow-x: auto; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }}
  th, td {{
    padding: 11px 12px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}
  th {{
    background: #f8fafc;
    font-weight: 700;
    color: #334155;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }}
  .finding-row {{ cursor: pointer; transition: background 0.12s; }}
  .finding-row:hover {{ background: #f1f5f9; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }}
  .font-semibold {{ font-weight: 600; }}
  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
  }}
  .sev-critical {{ background: var(--crit-bg); color: var(--crit); border: 1px solid #fecaca; }}
  .sev-high {{ background: var(--high-bg); color: var(--high); border: 1px solid #fed7aa; }}
  .sev-medium {{ background: var(--med-bg); color: var(--med); border: 1px solid #fde68a; }}
  .sev-low {{ background: var(--low-bg); color: var(--low); border: 1px solid #bfdbfe; }}
  .sev-info {{ background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; }}
  .status-pill {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    background: #f1f5f9;
    color: #334155;
  }}
  .status-confirmed {{ background: #dcfce7; color: #15803d; }}
  .status-needs_review {{ background: #fef9c3; color: #854d0e; }}
  .cwe-sub {{ font-size: 11px; color: var(--muted); margin-top: 2px; }}
  .method-tag {{
    display: inline-block;
    background: #e2e8f0;
    color: #0f172a;
    padding: 1px 6px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 11px;
  }}
  .btn-inspect {{
    background: #eff6ff;
    color: #1d4ed8;
    border: 1px solid #bfdbfe;
    padding: 5px 10px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
  }}
  .btn-inspect:hover {{ background: #dbeafe; }}
  .drawer-row td {{ background: #f8fafc; padding: 0; }}
  .drawer-panel {{
    padding: 18px 22px;
    border-left: 4px solid var(--accent);
    background: #f8fafc;
  }}
  .drawer-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(420px, 1fr));
    gap: 20px;
  }}
  .drawer-col h4 {{ margin: 0 0 8px 0; font-size: 14px; color: #0f172a; }}
  .drawer-col p {{ margin: 0 0 10px 0; font-size: 13px; color: #334155; }}
  .remediation-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
  }}
  .btn-copy {{
    background: #0f172a;
    color: #fff;
    border: none;
    padding: 5px 11px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
  }}
  .btn-copy:hover {{ background: #334155; }}
  .code-block {{
    margin: 6px 0 12px 0;
    padding: 12px;
    border-radius: 8px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }}
  .vuln-code {{ background: #fef2f2; border: 1px solid #fecaca; color: #7f1d1d; }}
  .fix-code {{ background: #0f172a; color: #e2e8f0; border: 1px solid #1e293b; }}
  .verifier-box {{
    margin-top: 10px;
    padding: 10px 12px;
    background: #fff;
    border: 1px solid var(--border);
    border-radius: 8px;
    font-size: 12px;
    color: #475569;
  }}
  @media print {{
    body {{ background: #fff; }}
    .btn-ctrl, .filter-bar, .btn-inspect, .btn-copy {{ display: none !important; }}
    .drawer-row {{ display: table-row !important; }}
    .card, .kpi-card, .exec-header {{ box-shadow: none !important; break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="container">
  <header class="exec-header">
    <div class="header-top">
      <div>
        <div class="brand-kicker">Komainu Legacy Security Assessment (LSA v{html.escape(KIT_VERSION)})</div>
        <h1 class="exec-title" data-en="Security Audit Dashboard — {html.escape(project)}" data-ja="セキュリティ監査ダッシュボード — {html.escape(project)}">Security Audit Dashboard — {html.escape(project)}</h1>
        <span class="conf-banner" data-en="CONFIDENTIAL — HUMAN REVIEW REQUIRED BEFORE EXTERNAL SHARING" data-ja="社外秘 (CONFIDENTIAL) — 外部共有前に必ず人間によるレビュー・承認が必要">CONFIDENTIAL — HUMAN REVIEW REQUIRED BEFORE EXTERNAL SHARING</span>
      </div>
      <div class="header-controls">
        <span class="risk-pill risk-{html.escape(risk['level'])}" data-en="{html.escape(risk['en'])}" data-ja="{html.escape(risk['ja'])}">{html.escape(risk['en'])}</span>
        <button id="lang-toggle" type="button" class="btn-ctrl" onclick="toggleLanguage()" title="Switch Language / 言語切替">🌐 EN / 日本語</button>
        <button type="button" class="btn-ctrl" onclick="expandAllDrawers()" data-en="Expand All" data-ja="すべて展開">Expand All</button>
        <button type="button" class="btn-ctrl" onclick="window.print()" data-en="Print / PDF" data-ja="印刷 / PDF出力">Print / PDF</button>
      </div>
    </div>
    <div class="meta-bar">
      <div><strong data-en="Audit Date:" data-ja="診断実施日:">Audit Date:</strong> {html.escape(audit_date)}</div>
      <div><strong data-en="Scope:" data-ja="監査対象スコープ:">Scope:</strong> <span data-en="BOLA/IDOR (CWE-639), SQL/NoSQL Injection (CWE-89/CWE-943), BFLA (CWE-285) &amp; Mass Assignment (CWE-915)" data-ja="BOLA/IDOR（認可不備）、SQL/NoSQLインジェクション、BFLA（機能レベル認可不備）、マスアサインメント">BOLA/IDOR (CWE-639), SQL/NoSQL Injection (CWE-89/CWE-943), BFLA (CWE-285) &amp; Mass Assignment (CWE-915)</span></div>
      <div><strong data-en="Detected Stacks:" data-ja="検出技術スタック:">Detected Stacks:</strong> {stacks_badges_html}</div>
    </div>
  </header>

  <section class="kpi-grid" aria-label="Executive Metrics">
    <div class="kpi-card">
      <div class="kpi-label" data-en="Total Active Findings" data-ja="有効検出事項総数">Total Active Findings</div>
      <div class="kpi-val">{total_active}</div>
      <div class="kpi-sub" data-en="Confirmed + Needs Review" data-ja="確定済 + 要確認">Confirmed + Needs Review</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label" data-en="Critical Severity" data-ja="緊急 (Critical)">Critical Severity</div>
      <div class="kpi-val" style="color:var(--crit)">{by_sev['critical']}</div>
      <div class="kpi-sub" data-en="Immediate remediation" data-ja="即時対応が必要">Immediate remediation</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label" data-en="High Severity" data-ja="高 (High)">High Severity</div>
      <div class="kpi-val" style="color:var(--high)">{by_sev['high']}</div>
      <div class="kpi-sub" data-en="High business impact" data-ja="事業影響大">High business impact</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label" data-en="Medium / Low" data-ja="中・低 (Medium / Low)">Medium / Low</div>
      <div class="kpi-val" style="color:var(--med)">{by_sev['medium'] + by_sev['low']}</div>
      <div class="kpi-sub">Medium: {by_sev['medium']} / Low: {by_sev['low']}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label" data-en="Endpoints Inventoried" data-ja="登録エンドポイント数">Endpoints Inventoried</div>
      <div class="kpi-val">{cov.get('inventoried', '-')}</div>
      <div class="kpi-sub">BOLA Audited: {cov.get('bola_routes_to_audit', '-')} | Inj: {cov.get('injection_candidates', '-')}{priv_kpi}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label" data-en="Refuted by Skeptic" data-ja="Skeptic検証により棄却">Refuted by Skeptic</div>
      <div class="kpi-val" style="color:var(--ok)">{len(rejected)}</div>
      <div class="kpi-sub" data-en="False positives eliminated" data-ja="誤検知を自動排除">False positives eliminated</div>
    </div>
  </section>

  <section class="charts-grid" aria-label="Visual Risk Analytics">
    <div class="card" style="margin-bottom:0;">
      <h2 class="card-title" data-en="Severity Distribution" data-ja="重要度別分布 (Severity Distribution)">Severity Distribution</h2>
      <div class="donut-wrap">
        {donut_svg}
        <div class="legend-list">
          {"".join(sev_legend_items)}
        </div>
      </div>
    </div>
    <div class="card" style="margin-bottom:0;">
      <h2 class="card-title" data-en="Vulnerability Category &amp; CWE Breakdown" data-ja="脆弱性分類・CWE別内訳 (Category Breakdown)">Vulnerability Category &amp; CWE Breakdown</h2>
      {cat_svg}
    </div>
  </section>

  {trend_card}

  <section class="card" aria-label="Interactive Findings Table">
    <h2 class="card-title" data-en="Interactive Findings Explorer" data-ja="検出事項一覧・インタラクティブ検索 (Findings Explorer)">Interactive Findings Explorer</h2>
    <div class="filter-bar">
      <input id="search-input" type="search" class="filter-input" placeholder="Search ID, endpoint, file, CWE, title... / キーワード検索" oninput="applyFilters()" />
      <select id="sev-filter" class="filter-select" onchange="applyFilters()" aria-label="Filter by Severity">
        <option value="all" data-en="All Severities" data-ja="すべての重要度">All Severities</option>
        <option value="critical" data-en="Critical Only" data-ja="緊急 (Critical)">Critical Only</option>
        <option value="high" data-en="High Only" data-ja="高 (High)">High Only</option>
        <option value="medium" data-en="Medium Only" data-ja="中 (Medium)">Medium Only</option>
        <option value="low" data-en="Low Only" data-ja="低 (Low)">Low Only</option>
      </select>
      <select id="cat-filter" class="filter-select" onchange="applyFilters()" aria-label="Filter by Category">
        <option value="all" data-en="All Categories" data-ja="すべての脆弱性分類">All Categories</option>
        <option value="bola" data-en="BOLA / IDOR (CWE-639)" data-ja="認可不備 BOLA (CWE-639)">BOLA / IDOR (CWE-639)</option>
        <option value="sql_injection" data-en="SQL Injection (CWE-89)" data-ja="SQLインジェクション (CWE-89)">SQL Injection (CWE-89)</option>
        <option value="nosql_injection" data-en="NoSQL Injection (CWE-943)" data-ja="NoSQLインジェクション (CWE-943)">NoSQL Injection (CWE-943)</option>
        {extra_cat_options}
      </select>
      <select id="stack-filter" class="filter-select" onchange="applyFilters()" aria-label="Filter by Stack">
        <option value="all" data-en="All Stacks / Modules" data-ja="すべての技術スタック">All Stacks / Modules</option>
        {stack_options_html}
      </select>
      <span id="visible-count" class="mono" style="color:var(--muted);">{total_active} / {total_active}</span>
    </div>

    <div class="table-wrap">
      <table id="findings-table">
        <thead>
          <tr>
            <th>ID</th>
            <th data-en="Severity" data-ja="重要度">Severity</th>
            <th data-en="Status" data-ja="ステータス">Status</th>
            <th data-en="Category / CWE" data-ja="脆弱性分類 / CWE">Category / CWE</th>
            <th data-en="Endpoint" data-ja="対象エンドポイント">Endpoint</th>
            <th data-en="Location" data-ja="該当箇所">Location</th>
            <th data-en="Title" data-ja="タイトル">Title</th>
            <th data-en="Action" data-ja="操作">Action</th>
          </tr>
        </thead>
        <tbody>
          {"".join(finding_rows_html)}
        </tbody>
      </table>
    </div>
  </section>

  <section class="card" aria-label="Rejected Findings Appendix">
    <h2 class="card-title" data-en="Appendix A — Findings Refuted by Skeptic Verifier ({len(rejected)})" data-ja="付録A — 検証により棄却された検出事項 ({len(rejected)}件)">Appendix A — Findings Refuted by Skeptic Verifier ({len(rejected)})</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th data-en="Location" data-ja="該当箇所">Location</th>
            <th data-en="Refutation Reason" data-ja="棄却理由">Refutation Reason</th>
          </tr>
        </thead>
        <tbody>
          {"".join(rejected_rows_html) if rejected_rows_html else '<tr><td colspan="3" data-en="None." data-ja="なし。">None.</td></tr>'}
        </tbody>
      </table>
    </div>
  </section>
</div>

<script>
  let currentLang = "{html.escape(default_lang)}";
  let allExpanded = false;

  function applyLanguage(lang) {{
    currentLang = lang;
    document.documentElement.lang = lang;
    const nodes = document.querySelectorAll("[data-en][data-ja]");
    nodes.forEach(el => {{
      const val = el.getAttribute("data-" + lang);
      if (val !== null) {{
        el.textContent = val;
      }}
    }});
  }}

  function toggleLanguage() {{
    const next = currentLang === "en" ? "ja" : "en";
    applyLanguage(next);
  }}

  function toggleDrawer(idx) {{
    const row = document.getElementById("drawer-" + idx);
    if (!row) return;
    row.style.display = row.style.display === "none" ? "table-row" : "none";
  }}

  function expandAllDrawers() {{
    allExpanded = !allExpanded;
    document.querySelectorAll(".drawer-row").forEach(r => {{
      r.style.display = allExpanded ? "table-row" : "none";
    }});
  }}

  function copyPatch(idx, btn) {{
    const codeEl = document.getElementById("patch-code-" + idx);
    if (!codeEl) return;
    const text = codeEl.textContent || "";
    if (navigator.clipboard && navigator.clipboard.writeText) {{
      navigator.clipboard.writeText(text);
    }}
    const orig = btn.textContent;
    btn.textContent = currentLang === "ja" ? "コピー完了 ✓" : "Copied ✓";
    setTimeout(() => {{ btn.textContent = orig; }}, 1600);
  }}

  function applyFilters() {{
    const q = (document.getElementById("search-input").value || "").toLowerCase().trim();
    const sev = document.getElementById("sev-filter").value;
    const cat = document.getElementById("cat-filter").value;
    const st = document.getElementById("stack-filter").value;
    const rows = document.querySelectorAll(".finding-row");
    let shown = 0;

    rows.forEach(row => {{
      const idx = row.getAttribute("data-idx");
      const rSev = row.getAttribute("data-sev");
      const rCat = row.getAttribute("data-cat");
      const rStack = row.getAttribute("data-stack");
      const rSearch = row.getAttribute("data-search") || "";

      const matchSev = (sev === "all" || rSev === sev);
      const matchCat = (cat === "all" || rCat === cat);
      const matchStack = (st === "all" || rStack === st);
      const matchQ = (!q || rSearch.indexOf(q) !== -1);

      const visible = matchSev && matchCat && matchStack && matchQ;
      row.style.display = visible ? "" : "none";
      const drawer = document.getElementById("drawer-" + idx);
      if (!visible && drawer) {{
        drawer.style.display = "none";
      }}
      if (visible) shown += 1;
    }});

    const countEl = document.getElementById("visible-count");
    if (countEl) {{
      countEl.textContent = shown + " / " + rows.length;
    }}
  }}

  if (currentLang === "ja") {{
    applyLanguage("ja");
  }}
</script>
</body>
</html>
"""


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
    ap.add_argument(
        "--format",
        choices=["md", "html", "all"],
        default="md",
        help="Output format: md (default), html (interactive dashboard), or all",
    )
    ap.add_argument("--out-file", help="Explicit output file path")
    a = ap.parse_args()

    out = Path(a.out)
    project = a.project or out.resolve().name

    if a.out_file:
        out_path = Path(a.out_file)
        lang = a.lang if a.lang in ("en", "ja") else "en"
        fmt = "html" if (a.format == "html" or out_path.suffix.lower() == ".html") else "md"
        out_path.write_text(render(out, project, lang=lang, fmt=fmt), encoding="utf-8")
        print(f"wrote {out_path}")
        return 0

    if a.format in ("md", "all"):
        if a.lang in ("en", "all"):
            en_path = out / "report.md"
            en_path.write_text(render(out, project, lang="en", fmt="md"), encoding="utf-8")
            print(f"wrote {en_path}")

        if a.lang in ("ja", "all"):
            ja_path = out / "report.ja.md"
            ja_path.write_text(render(out, project, lang="ja", fmt="md"), encoding="utf-8")
            print(f"wrote {ja_path}")

    if a.format in ("html", "all"):
        default_lang = "ja" if a.lang == "ja" else "en"
        html_path = out / "report.html"
        html_path.write_text(render_html(out, project, default_lang=default_lang), encoding="utf-8")
        print(f"wrote {html_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
