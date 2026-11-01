#!/usr/bin/env python3
"""Forecast security debt burndown and target completion dates from scan history.

Standard-library-only (Python 3.8+).

Calculates arrival rate (new/regressed per week), fix rate (fixed per week),
and net burndown velocity. Projects 10th-90th percentile date ranges to reach
zero open vulnerabilities, evaluates target deadlines, and models what-if scenarios.
"""
from __future__ import annotations

import argparse
import datetime
import html
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SEVERITIES = ("critical", "high", "medium", "low", "info")
MIN_SNAPSHOTS = 6
MIN_SPAN_DAYS = 28


def parse_date(date_str: str) -> datetime.date:
    """Parse YYYY-MM-DD date string."""
    return datetime.datetime.strptime(date_str, "%Y-%m-%d").date()


def format_date(d: datetime.date) -> str:
    """Format date to YYYY-MM-DD string."""
    return d.strftime("%Y-%m-%d")


def calculate_history_span(history: List[Dict[str, Any]]) -> Tuple[int, Optional[datetime.date], Optional[datetime.date]]:
    """Return (span_days, start_date, end_date) for sorted history snapshots."""
    if not history:
        return 0, None, None
    valid_dates = []
    for h in history:
        try:
            valid_dates.append(parse_date(h["date"]))
        except (KeyError, ValueError, TypeError):
            continue
    if not valid_dates:
        return 0, None, None
    valid_dates.sort()
    start_d, end_d = valid_dates[0], valid_dates[-1]
    return (end_d - start_d).days, start_d, end_d


def calculate_weekly_intervals(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Compute weekly rates between successive snapshot intervals."""
    sorted_h = sorted(history, key=lambda x: str(x.get("date", "")))
    intervals = []
    for i in range(len(sorted_h) - 1):
        h1, h2 = sorted_h[i], sorted_h[i + 1]
        try:
            d1, d2 = parse_date(h1["date"]), parse_date(h2["date"])
        except (KeyError, ValueError, TypeError):
            continue
        days = (d2 - d1).days
        if days <= 0:
            continue

        scale = 7.0 / days
        open_delta = (h2.get("open", 0) - h1.get("open", 0)) * scale
        new_rate = h2.get("new", 0) * scale
        fixed_rate = h2.get("fixed", 0) * scale
        regressed_rate = h2.get("regressed", 0) * scale

        # Per severity deltas
        sev1 = h1.get("by_severity", {})
        sev2 = h2.get("by_severity", {})
        sev_deltas = {
            s: (sev2.get(s, 0) - sev1.get(s, 0)) * scale
            for s in SEVERITIES
        }

        intervals.append({
            "start": d1,
            "end": d2,
            "days": days,
            "open_delta_per_week": open_delta,
            "new_per_week": new_rate,
            "fixed_per_week": fixed_rate,
            "regressed_per_week": regressed_rate,
            "sev_deltas": sev_deltas,
        })
    return intervals


def compute_rates_and_percentiles(values: List[float]) -> Tuple[float, float, float]:
    """Compute (p10, p50, p90) values for a list of rates."""
    if not values:
        return 0.0, 0.0, 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)

    def percentile(p: float) -> float:
        k = (n - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_vals[int(k)]
        d0 = sorted_vals[int(f)] * (c - k)
        d1 = sorted_vals[int(c)] * (k - f)
        return d0 + d1

    return percentile(0.10), percentile(0.50), percentile(0.90)


def project_debt(
    history: List[Dict[str, Any]],
    targets: Optional[Dict[str, str]] = None,
    what_if_modifiers: Optional[List[Dict[str, Any]]] = None,
    today: Optional[str] = None,
) -> Dict[str, Any]:
    """Calculate rates and project debt burndown ranges.

    Conforms to contracts/schemas/forecast.schema.json.
    """
    targets = targets or {}
    what_if_modifiers = what_if_modifiers or []
    current_date = parse_date(today) if today else datetime.date.today()
    gen_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    span_days, start_date, end_date = calculate_history_span(history)
    history_summary = {
        "snapshot_count": len(history),
        "span_days": span_days,
        "start_date": format_date(start_date) if start_date else None,
        "end_date": format_date(end_date) if end_date else None,
    }

    # Guardrails: verify minimum required history
    if len(history) < MIN_SNAPSHOTS or span_days < MIN_SPAN_DAYS:
        latest = history[-1] if history else {}
        open_by_sev = latest.get("by_severity", {})
        projections = []
        for s in ("critical", "high", "overall"):
            cnt = latest.get("open", 0) if s == "overall" else open_by_sev.get(s, 0)
            projections.append({
                "severity": s,
                "current_open": cnt,
                "status": "insufficient_history",
                "net_weekly_change": 0.0,
                "target_zero_date_p10": None,
                "target_zero_date_p50": None,
                "target_zero_date_p90": None,
                "target_date": targets.get(s),
                "target_status": None,
                "required_fix_rate_per_week": None,
            })
        return {
            "version": 1,
            "generated_at": gen_time,
            "has_enough_history": False,
            "reason_if_insufficient": (
                f"Requires at least {MIN_SNAPSHOTS} snapshots over at least {MIN_SPAN_DAYS} days "
                f"(current: {len(history)} snapshots over {span_days} days)."
            ),
            "history_summary": history_summary,
            "rates": {
                "arrival_rate_per_week": 0.0,
                "fix_rate_per_week": 0.0,
                "net_rate_per_week": 0.0,
            },
            "projections": projections,
            "scenarios": [],
        }

    intervals = calculate_weekly_intervals(history)
    if not intervals:
        intervals = [{
            "open_delta_per_week": 0.0,
            "new_per_week": 0.0,
            "fixed_per_week": 0.0,
            "regressed_per_week": 0.0,
            "sev_deltas": {s: 0.0 for s in SEVERITIES},
        }]

    # Average rates across intervals
    avg_arrival = sum(iv["new_per_week"] + iv["regressed_per_week"] for iv in intervals) / len(intervals)
    avg_fix = sum(iv["fixed_per_week"] for iv in intervals) / len(intervals)
    avg_net = sum(iv["open_delta_per_week"] for iv in intervals) / len(intervals)

    latest_snap = history[-1]
    latest_open = latest_snap.get("open", 0)
    latest_by_sev = latest_snap.get("by_severity", {})

    projections = []
    # Project for critical, high, overall
    project_targets = [
        ("critical", latest_by_sev.get("critical", 0)),
        ("high", latest_by_sev.get("high", 0)),
        ("overall", latest_open),
    ]

    for sev_name, current_open in project_targets:
        if sev_name == "overall":
            delta_series = [iv["open_delta_per_week"] for iv in intervals]
        else:
            delta_series = [iv["sev_deltas"].get(sev_name, 0.0) for iv in intervals]

        p10_delta, p50_delta, p90_delta = compute_rates_and_percentiles(delta_series)
        median_net = p50_delta

        target_date_str = targets.get(sev_name)
        target_date_obj = parse_date(target_date_str) if target_date_str else None

        if current_open == 0:
            status = "converging"
            p10_date = p50_date = p90_date = format_date(current_date)
            target_status = "on_track" if target_date_obj else None
            req_fix_rate = 0.0
        elif median_net < -0.01:
            status = "converging"
            # Net change is negative -> decreasing open count
            # p10_delta is fastest reduction (most negative), p90_delta is slowest reduction
            # If even p90 is negative:
            fastest_rate = -min(p10_delta, p50_delta)
            median_rate = -p50_delta
            slowest_rate = max(-p90_delta, 0.1)

            weeks_p10 = current_open / fastest_rate if fastest_rate > 0 else 0
            weeks_p50 = current_open / median_rate if median_rate > 0 else 0
            weeks_p90 = current_open / slowest_rate if slowest_rate > 0 else 0

            p10_date = format_date(current_date + datetime.timedelta(days=int(weeks_p10 * 7)))
            p50_date = format_date(current_date + datetime.timedelta(days=int(weeks_p50 * 7)))
            p90_date = format_date(current_date + datetime.timedelta(days=int(weeks_p90 * 7)))

            if target_date_obj:
                avail_days = (target_date_obj - current_date).days
                avail_weeks = max(avail_days / 7.0, 0.1)
                req_fix_rate = round(current_open / avail_weeks, 2)
                p90_obj = parse_date(p90_date)
                p50_obj = parse_date(p50_date)
                if p90_obj <= target_date_obj:
                    target_status = "on_track"
                elif p50_obj <= target_date_obj:
                    target_status = "at_risk"
                else:
                    target_status = "off_track"
            else:
                target_status = None
                req_fix_rate = None
        elif abs(median_net) <= 0.01:
            status = "flat"
            p10_date = p50_date = p90_date = None
            target_status = "not_converging" if target_date_obj else None
            if target_date_obj:
                avail_days = (target_date_obj - current_date).days
                avail_weeks = max(avail_days / 7.0, 0.1)
                req_fix_rate = round(current_open / avail_weeks, 2)
            else:
                req_fix_rate = None
        else:
            status = "diverging"
            p10_date = p50_date = p90_date = None
            target_status = "not_converging" if target_date_obj else None
            if target_date_obj:
                avail_days = (target_date_obj - current_date).days
                avail_weeks = max(avail_days / 7.0, 0.1)
                req_fix_rate = round((current_open / avail_weeks) + median_net, 2)
            else:
                req_fix_rate = None

        projections.append({
            "severity": sev_name,
            "current_open": current_open,
            "status": status,
            "net_weekly_change": round(median_net, 2),
            "target_zero_date_p10": p10_date,
            "target_zero_date_p50": p50_date,
            "target_zero_date_p90": p90_date,
            "target_date": target_date_str,
            "target_status": target_status,
            "required_fix_rate_per_week": req_fix_rate,
        })

    # Evaluate What-If scenarios
    scenarios = []
    base_proj = next((p for p in projections if p["severity"] == "overall"), projections[0])
    scenarios.append({
        "scenario_id": "current_pace",
        "description": "Baseline pace using recent 4-week moving average",
        "net_weekly_change": base_proj["net_weekly_change"],
        "projected_date_range": (
            f"{base_proj['target_zero_date_p10']} to {base_proj['target_zero_date_p90']}"
            if base_proj["target_zero_date_p10"] else "Not converging"
        ),
    })

    for mod in what_if_modifiers:
        fix_delta = mod.get("fix_rate_delta", 0.0)
        desc = mod.get("description", f"Velocity change: {fix_delta:+.1f} fixes/week")
        scenario_id = mod.get("id", f"what_if_{fix_delta}")

        sim_net = base_proj["net_weekly_change"] - fix_delta
        if sim_net < -0.01:
            w = latest_open / (-sim_net)
            date_est = format_date(current_date + datetime.timedelta(days=int(w * 7)))
            date_range = f"Estimated ~{date_est}"
        else:
            date_range = "Not converging"

        scenarios.append({
            "scenario_id": scenario_id,
            "description": desc,
            "net_weekly_change": round(sim_net, 2),
            "projected_date_range": date_range,
        })

    return {
        "version": 1,
        "generated_at": gen_time,
        "has_enough_history": True,
        "history_summary": history_summary,
        "rates": {
            "arrival_rate_per_week": round(avg_arrival, 2),
            "fix_rate_per_week": round(avg_fix, 2),
            "net_rate_per_week": round(avg_net, 2),
        },
        "projections": projections,
        "scenarios": scenarios,
    }


def render_forecast_md(forecast_doc: Dict[str, Any], lang: str = "en") -> List[str]:
    """Generate Markdown report section for security debt forecast (EN / JA)."""
    if not forecast_doc.get("has_enough_history"):
        reason = forecast_doc.get("reason_if_insufficient", "Insufficient scan history.")
        if lang == "ja":
            return [
                "## 見通しとセキュリティ負債予測 (Outlook & Debt Forecast)",
                "",
                f"> **注意:** 信頼性の高い予測には最低{MIN_SNAPSHOTS}回のスキャン（期間28日以上）が必要です。現時点では十分な履歴データがありません（{reason}）。",
                "",
            ]
        return [
            "## Outlook & Debt Forecast",
            "",
            f"> **Note:** Reliable forecasting requires at least {MIN_SNAPSHOTS} scans spanning at least {MIN_SPAN_DAYS} days. {reason}",
            "",
        ]

    rates = forecast_doc.get("rates", {})
    projections = forecast_doc.get("projections", [])
    scenarios = forecast_doc.get("scenarios", [])

    if lang == "ja":
        lines = [
            "## 見通しとセキュリティ負債予測 (Outlook & Debt Forecast)",
            "",
            "過去のスキャン履歴から計測した修正速度（Velocity）に基づき、未解決の脆弱性が解消される時期をレンジ（10〜90パーセンタイル）で予測します。",
            "",
            f"- **新規・再発発生率:** {rates.get('arrival_rate_per_week', 0)} 件/週",
            f"- **平均修正消化率:** {rates.get('fix_rate_per_week', 0)} 件/週",
            f"- **週間純増減（Net Velocity）:** {rates.get('net_rate_per_week', 0):+.2f} 件/週",
            "",
            "### 目標達成予測 (Target & burndown projections)",
            "",
            "| 重要度 | 残件数 | 週間純増減 | 予測達成時期 (Range) | 目標期限 | 達成確度 |",
            "|---|---|---|---|---|---|",
        ]
        status_labels = {
            "on_track": "順調 (On Track)",
            "at_risk": "要警戒 (At Risk)",
            "off_track": "遅延 (Off Track)",
            "not_converging": "収束せず (Not Converging)",
        }
        for p in projections:
            sev = p["severity"].capitalize()
            cur = p["current_open"]
            net = f"{p.get('net_weekly_change', 0):+.2f}/週"
            if p["status"] == "converging":
                rng = f"{p['target_zero_date_p10']} 〜 {p['target_zero_date_p90']}"
            else:
                rng = "現状ペースでは収束せず"
            tgt = p.get("target_date") or "-"
            t_status = status_labels.get(p.get("target_status"), "-")
            lines.append(f"| {sev} | {cur} | {net} | {rng} | {tgt} | {t_status} |")

        if len(scenarios) > 1:
            lines += ["", "### What-If シナリオ分析", "", "| シナリオ | 週間増減 | 予測完了時期 |", "|---|---|---|"]
            for sc in scenarios:
                lines.append(f"| {sc['description']} | {sc['net_weekly_change']:+.2f}/週 | {sc['projected_date_range']} |")
        lines.append("")
    else:
        lines = [
            "## Outlook & Debt Forecast",
            "",
            "Projects target completion dates based on historical fix velocity, showing uncertainty ranges honestly.",
            "",
            f"- **Arrival Rate:** {rates.get('arrival_rate_per_week', 0)} findings/week",
            f"- **Fix Rate:** {rates.get('fix_rate_per_week', 0)} findings/week",
            f"- **Net Velocity:** {rates.get('net_rate_per_week', 0):+.2f} findings/week",
            "",
            "### Burndown Projections",
            "",
            "| Scope | Open | Net Change | Projected Date (P10 - P90) | Target Date | Target Status |",
            "|---|---|---|---|---|---|",
        ]
        status_labels = {
            "on_track": "On Track",
            "at_risk": "At Risk",
            "off_track": "Off Track",
            "not_converging": "Not Converging",
        }
        for p in projections:
            sev = p["severity"].capitalize()
            cur = p["current_open"]
            net = f"{p.get('net_weekly_change', 0):+.2f}/wk"
            if p["status"] == "converging":
                rng = f"{p['target_zero_date_p10']} to {p['target_zero_date_p90']}"
            else:
                rng = "Not converging"
            tgt = p.get("target_date") or "-"
            t_status = status_labels.get(p.get("target_status"), "-")
            lines.append(f"| {sev} | {cur} | {net} | {rng} | {tgt} | {t_status} |")

        if len(scenarios) > 1:
            lines += ["", "### What-If Scenarios", "", "| Scenario | Net Velocity | Projected Completion |", "|---|---|---|"]
            for sc in scenarios:
                lines.append(f"| {sc['description']} | {sc['net_weekly_change']:+.2f}/wk | {sc['projected_date_range']} |")
        lines.append("")

    return lines


def render_forecast_html(forecast_doc: Dict[str, Any]) -> str:
    """Generate self-contained bilingual HTML card for security debt forecast."""
    if not forecast_doc.get("has_enough_history"):
        reason = html.escape(forecast_doc.get("reason_if_insufficient", "Insufficient scan history."))
        return (
            '<section class="card" aria-label="Outlook &amp; Debt Forecast">'
            '<h2 class="card-title" data-en="Outlook &amp; Debt Forecast" data-ja="見通しとセキュリティ負債予測 (Outlook)">Outlook &amp; Debt Forecast</h2>'
            f'<div class="forecast-alert"><span class="badge badge-info">INFO</span> '
            f'<span data-en="Requires at least 6 scans over 28 days for reliable projections. ({reason})" '
            f'data-ja="信頼性の高い予測には最低6回・28日以上の履歴が必要です。({reason})">'
            f'Requires at least 6 scans over 28 days for reliable projections. ({reason})</span></div>'
            '</section>'
        )

    rates = forecast_doc.get("rates", {})
    projections = forecast_doc.get("projections", [])
    scenarios = forecast_doc.get("scenarios", [])

    rows = []
    for p in projections:
        sev = html.escape(p["severity"].capitalize())
        cur = p["current_open"]
        net = f"{p.get('net_weekly_change', 0):+.2f}"
        if p["status"] == "converging":
            rng = f"{p['target_zero_date_p10']} &rarr; {p['target_zero_date_p90']}"
        else:
            rng = '<span class="badge badge-critical">Not converging</span>'
        tgt = html.escape(p.get("target_date") or "-")
        t_stat = p.get("target_status")
        badge_cls = "badge-ok" if t_stat == "on_track" else ("badge-high" if t_stat == "at_risk" else "badge-critical")
        stat_html = f'<span class="badge {badge_cls}">{html.escape(str(t_stat or "-"))}</span>'
        rows.append(f"<tr><td><strong>{sev}</strong></td><td>{cur}</td><td>{net}/wk</td><td>{rng}</td><td>{tgt}</td><td>{stat_html}</td></tr>")

    scenario_rows = "".join(
        f"<tr><td>{html.escape(sc['description'])}</td><td>{sc['net_weekly_change']:+.2f}/wk</td><td><strong>{html.escape(sc['projected_date_range'] or '')}</strong></td></tr>"
        for sc in scenarios
    )

    return (
        '<section class="card" aria-label="Outlook &amp; Debt Forecast">'
        '<h2 class="card-title" data-en="Outlook &amp; Debt Forecast" data-ja="見通しとセキュリティ負債予測 (Outlook)">Outlook &amp; Debt Forecast</h2>'
        '<div class="forecast-stats-grid">'
        f'<div class="forecast-stat-box"><div class="stat-lbl" data-en="Arrival Rate" data-ja="新規・再発率">Arrival Rate</div><div class="stat-val">{rates.get("arrival_rate_per_week", 0)}/wk</div></div>'
        f'<div class="forecast-stat-box"><div class="stat-lbl" data-en="Fix Velocity" data-ja="修正消化速度">Fix Velocity</div><div class="stat-val" style="color:var(--ok);">{rates.get("fix_rate_per_week", 0)}/wk</div></div>'
        f'<div class="forecast-stat-box"><div class="stat-lbl" data-en="Net Velocity" data-ja="純増減速度">Net Velocity</div><div class="stat-val">{rates.get("net_rate_per_week", 0):+.2f}/wk</div></div>'
        '</div>'
        '<table><thead><tr>'
        '<th data-en="Scope" data-ja="対象">Scope</th>'
        '<th data-en="Open" data-ja="残件">Open</th>'
        '<th data-en="Velocity" data-ja="純増減">Velocity</th>'
        '<th data-en="Projected Zero Date (P10 - P90)" data-ja="完了予測レンジ (P10 - P90)">Projected Zero Date</th>'
        '<th data-en="Target Date" data-ja="目標期限">Target Date</th>'
        '<th data-en="Target Status" data-ja="進捗状況">Target Status</th>'
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table>'
        + (
            '<h3>What-If Scenarios</h3>'
            f'<table><thead><tr><th>Scenario</th><th>Net Velocity</th><th>Projected Date</th></tr></thead><tbody>{scenario_rows}</tbody></table>'
            if len(scenarios) > 1 else ''
        ) +
        '</section>'
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Forecast security debt from scan history.")
    parser.add_argument("out_dir", type=Path, help="Path to audit OUT directory.")
    parser.add_argument("--baseline", type=Path, default=None, help="Path to baseline.json (defaults to OUT/baseline.json).")
    parser.add_argument("--output", type=Path, default=None, help="Output forecast.json path.")
    parser.add_argument("--target", action="append", help="Target deadline as scope=YYYY-MM-DD (e.g. critical=2027-04-01).")
    parser.add_argument("--what-if", action="append", dest="what_ifs", help="What-if as fix-rate=+N (e.g. fix-rate=+2).")
    args = parser.parse_args()

    baseline_file = args.baseline or (args.out_dir / "baseline.json")
    history = []
    if baseline_file.is_file():
        with open(baseline_file, encoding="utf-8") as fh:
            b_doc = json.load(fh)
            history = b_doc.get("history", [])

    targets = {}
    if args.target:
        for t in args.target:
            if "=" in t:
                k, v = t.split("=", 1)
                targets[k.strip()] = v.strip()

    what_if_list = []
    if args.what_ifs:
        for w in args.what_ifs:
            if "fix-rate=" in w:
                val = float(w.split("fix-rate=")[1])
                what_if_list.append({
                    "id": f"what_if_fix_rate_{val:+g}",
                    "fix_rate_delta": val,
                    "description": f"Remediation acceleration: {val:+g} fixes/week",
                })

    forecast_doc = project_debt(history, targets, what_if_list)

    out_file = args.output or (args.out_dir / "forecast.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(forecast_doc, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    print(f"✔ Security debt forecast written to {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
