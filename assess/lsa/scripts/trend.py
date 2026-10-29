#!/usr/bin/env python3
"""Scan history, mean time to fix (MTTR) and the trend report section.

History lives in baseline.json (`history`: one snapshot per scan day), so a
team commits a single file to track progress for the monthly report.
MTTR is computed from baseline entries: days from `first_seen` to `fixed_at`
for fixed entries with both dates. A finding that regressed keeps its original
`first_seen`.

Standard-library-only (Python 3.8+).
"""
from __future__ import annotations

import datetime
import html
from typing import Dict, List

SEVERITIES = ("critical", "high", "medium", "low", "info")
HISTORY_LIMIT = 365
REPORT_ROWS = 12


def snapshot(counts: Dict[str, int], findings: List[Dict], today: str) -> Dict:
    """One history point: open (active, unsuppressed) findings and this scan's changes."""
    open_findings = [f for f in findings if f.get("status") != "rejected" and not f.get("suppression")]
    return {
        "date": today,
        "open": len(open_findings),
        "new": counts.get("new", 0),
        "regressed": counts.get("regressed", 0),
        "fixed": counts.get("fixed", 0),
        "suppressed": counts.get("suppressed", 0),
        "by_severity": {s: sum(1 for f in open_findings if f.get("severity") == s) for s in SEVERITIES},
    }


def append_history(history: List[Dict], snap: Dict, limit: int = HISTORY_LIMIT) -> List[Dict]:
    """Return a new history with snap replacing any same-day point, sorted by date and capped."""
    kept = [dict(h) for h in history if isinstance(h, dict) and h.get("date") != snap["date"]]
    return sorted(kept + [dict(snap)], key=lambda h: str(h.get("date", "")))[-limit:]


def _days(start: str, end: str) -> int:
    return (datetime.date.fromisoformat(end) - datetime.date.fromisoformat(start)).days


def mttr_by_severity(entries: List[Dict]) -> Dict[str, Dict]:
    """Mean days from first_seen to fixed_at per severity, for fixed entries with both dates."""
    durations: Dict[str, List[int]] = {}
    for e in entries:
        if e.get("state") != "fixed" or not e.get("first_seen") or not e.get("fixed_at"):
            continue
        try:
            durations.setdefault(e.get("severity", "medium"), []).append(_days(e["first_seen"], e["fixed_at"]))
        except ValueError:
            continue
    return {
        s: {"fixed": len(durations[s]), "mean_days": round(sum(durations[s]) / len(durations[s]), 1)}
        for s in SEVERITIES if s in durations
    }


def render_trend_md(trend: Dict, lang: str = "en") -> List[str]:
    """Markdown lines for the trend section (English or Japanese)."""
    if lang == "ja":
        lines = ["## 検出推移と平均修正日数 (MTTR)", "",
                 "| 日付 | 未解決 | 新規 | 再発 | 修正済 | 抑制 |", "|---|---|---|---|---|---|"]
        mttr_head = ["", "| 重要度 | 修正件数 | 平均修正日数 |", "|---|---|---|"]
        empty = "修正済みの検出事項はまだありません。"
    else:
        lines = ["## Trend and time to fix", "",
                 "| Date | Open | New | Regressed | Fixed | Suppressed |", "|---|---|---|---|---|---|"]
        mttr_head = ["", "| Severity | Fixed | Mean days to fix |", "|---|---|---|"]
        empty = "No findings fixed yet."
    for h in trend.get("history", [])[-REPORT_ROWS:]:
        lines.append(f"| {h.get('date')} | {h.get('open', 0)} | {h.get('new', 0)} | {h.get('regressed', 0)} | "
                     f"{h.get('fixed', 0)} | {h.get('suppressed', 0)} |")
    mttr = trend.get("mttr") or {}
    if mttr:
        lines += mttr_head
        lines += [f"| {s} | {m['fixed']} | {m['mean_days']} |" for s, m in mttr.items()]
    else:
        lines += ["", empty]
    return lines + [""]


def _line_chart_svg(history: List[Dict]) -> str:
    width, height, pad = 360, 140, 24
    values = [int(h.get("open", 0)) for h in history]
    top = max(values + [1])
    step = (width - 2 * pad) / max(len(values) - 1, 1)
    points = [(pad + i * step, height - pad - (v / top) * (height - 2 * pad)) for i, v in enumerate(values)]
    coords = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    dots = "".join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="#7c3aed"/>' for x, y in points)
    first = html.escape(str(history[0].get("date", ""))) if history else ""
    last = html.escape(str(history[-1].get("date", ""))) if history else ""
    return (
        f'<svg viewBox="0 0 {width} {height}" class="trend-svg" role="img" aria-label="Open findings over time">'
        f'<line x1="{pad}" y1="{height - pad}" x2="{width - pad}" y2="{height - pad}" stroke="#e2e8f0"/>'
        f'<polyline points="{coords}" fill="none" stroke="#7c3aed" stroke-width="2"/>{dots}'
        f'<text x="{pad}" y="{height - 6}" font-size="10" fill="#64748b">{first}</text>'
        f'<text x="{width - pad}" y="{height - 6}" font-size="10" fill="#64748b" text-anchor="end">{last}</text>'
        f'<text x="{pad}" y="14" font-size="10" fill="#64748b">max {top}</text>'
        "</svg>"
    )


def render_trend_html(trend: Dict) -> str:
    """Self-contained bilingual HTML card with the open-findings line chart and MTTR table."""
    history = trend.get("history", [])[-REPORT_ROWS:]
    rows = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(h.get(k, 0)))}</td>"
                         for k in ("date", "open", "new", "regressed", "fixed", "suppressed")) + "</tr>"
        for h in history
    )
    mttr = trend.get("mttr") or {}
    mttr_rows = "".join(
        f"<tr><td>{html.escape(s)}</td><td>{m['fixed']}</td><td>{m['mean_days']}</td></tr>" for s, m in mttr.items()
    ) or '<tr><td colspan="3" data-en="No findings fixed yet." data-ja="修正済みの検出事項はまだありません。">No findings fixed yet.</td></tr>'
    head = "".join(
        f'<th data-en="{en}" data-ja="{ja}">{en}</th>'
        for en, ja in (("Date", "日付"), ("Open", "未解決"), ("New", "新規"), ("Regressed", "再発"),
                       ("Fixed", "修正済"), ("Suppressed", "抑制"))
    )
    return (
        '<section class="card" aria-label="Trend and time to fix">'
        '<h2 class="card-title" data-en="Trend and Time to Fix" data-ja="検出推移と平均修正日数">Trend and Time to Fix</h2>'
        f"{_line_chart_svg(history)}"
        f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>"
        '<h3 data-en="Mean Time to Fix (MTTR)" data-ja="平均修正日数 (MTTR)">Mean Time to Fix (MTTR)</h3>'
        '<table><thead><tr><th data-en="Severity" data-ja="重要度">Severity</th>'
        '<th data-en="Fixed" data-ja="修正件数">Fixed</th>'
        '<th data-en="Mean days" data-ja="平均日数">Mean days</th></tr></thead>'
        f"<tbody>{mttr_rows}</tbody></table>"
        "</section>"
    )
