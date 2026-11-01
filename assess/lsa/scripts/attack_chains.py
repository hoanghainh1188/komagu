#!/usr/bin/env python3
"""Build explainable multi-step attack chains from linked security findings.

Standard-library-only (Python 3.8+).

A chain links individual findings into realistic end-to-end exploit flows:
  e.g., Mass Assignment (gain role) -> BFLA (admin access) -> BOLA (cross-tenant leak).
"""
from __future__ import annotations

import argparse
import datetime
import html
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Severity weights for sorting chains
SEVERITY_WEIGHT = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

CONFIDENCE_RANK = {
    "confirmed": 3,
    "likely": 2,
    "needs_review": 1,
}

# Regex patterns to detect privilege-granting or tenant-switching fields
ADMIN_FIELD_PATTERNS = re.compile(
    r"(?i)\b(role|roles|is_?admin|admin|is_?staff|is_?superuser|group|groups|permission|permissions|privilege)\b"
)
TENANT_FIELD_PATTERNS = re.compile(
    r"(?i)\b(tenant_?id|org_?id|company_?id|account_?id|workspace_?id)\b"
)
ADMIN_ROUTE_PATTERNS = re.compile(
    r"(?i)(/admin/|/manage/|/internal/|/settings/|/system/|/users?/admin)"
)


def extract_entity_name(endpoint: str, location: str) -> str:
    """Extract a representative resource entity name from an endpoint or file path."""
    text = endpoint or location or ""
    # Try route segments: e.g. /api/customers/{id} -> customers
    segments = [s.strip("/") for s in text.split("/") if s and not s.startswith("{") and not s.startswith(":")]
    ignored = {"api", "v1", "v2", "v3", "rest", "internal", "admin", "app"}
    for seg in reversed(segments):
        clean = re.sub(r"\.[a-zA-Z0-9]+$", "", seg)  # strip extension (.php, .json, etc.)
        if clean.lower() not in ignored and len(clean) > 2:
            return clean.lower()
    return "records"


def profile_finding(finding: Dict[str, Any], route_map: Optional[Dict[str, Dict]] = None) -> Dict[str, Any]:
    """Assign entry requirements, role in chain, and capabilities gained for a finding."""
    cat = (finding.get("category") or "").lower()
    endpoint = finding.get("endpoint") or ""
    loc = finding.get("location") or ""
    attack_vec = finding.get("attack_vector") or {}
    fields = attack_vec.get("fields") or {}

    requires = "authenticated_user"
    gains: List[str] = []
    role_in_chain = "access"
    entity = extract_entity_name(endpoint, loc)

    # Check associated route if provided
    route_id = finding.get("route_id") or finding.get("candidate_id")
    route_priv = None
    if route_map and route_id and route_id in route_map:
        route_priv = route_map[route_id].get("privilege")

    is_admin_endpoint = bool(ADMIN_ROUTE_PATTERNS.search(endpoint) or ADMIN_ROUTE_PATTERNS.search(loc))

    if cat == "mass_assignment":
        # Check if registration/signup endpoint (anonymous entry)
        if any(w in endpoint.lower() or w in loc.lower() for w in ("register", "signup", "join", "onboard")):
            requires = "anonymous"
            role_in_chain = "entry_point"
        else:
            requires = "authenticated_user"
            role_in_chain = "privilege_gain"

        # Check fields targeted
        field_names = " ".join(fields.keys()) if isinstance(fields, dict) else str(fields)
        if not field_names:
            field_names = finding.get("evidence") or loc

        if ADMIN_FIELD_PATTERNS.search(field_names):
            gains.append("privilege:admin")
        elif TENANT_FIELD_PATTERNS.search(field_names):
            gains.append("scope:other_tenant")
        else:
            gains.append("state:tamper")

    elif cat == "bfla":
        role_in_chain = "privilege_gain" if not is_admin_endpoint else "access"
        if route_priv == "anonymous":
            requires = "anonymous"
        else:
            requires = "authenticated_user"

        # BFLA allows caller to perform administrative tasks
        gains.append("privilege:admin")
        gains.append(f"access:{entity}")

    elif cat in ("bola", "idor"):
        role_in_chain = "impact"
        if is_admin_endpoint:
            requires = "privilege:admin"
        else:
            requires = "authenticated_user"

        gains.append(f"impact:leak:{entity}")
        gains.append("impact:data_leak")

    elif cat in ("sql_injection", "nosql_injection"):
        role_in_chain = "impact"
        if any(w in endpoint.lower() or w in loc.lower() for w in ("login", "auth", "register", "search", "public")):
            requires = "anonymous"
        elif is_admin_endpoint:
            requires = "privilege:admin"
        else:
            requires = "authenticated_user"

        gains.append("impact:db_read")
        gains.append("impact:data_leak")
    else:
        # Fallback profile
        requires = "authenticated_user"
        gains.append(f"access:{cat}")

    return {
        "finding_id": finding.get("finding_id") or finding.get("fingerprint"),
        "category": cat,
        "subtype": finding.get("subtype", ""),
        "location": loc,
        "endpoint": endpoint,
        "severity": finding.get("severity", "medium").lower(),
        "confidence": finding.get("confidence", "likely").lower(),
        "status": finding.get("status", "likely").lower(),
        "requires": requires,
        "gains": gains,
        "role_in_chain": role_in_chain,
        "entity": entity,
        "raw": finding,
    }


def _min_confidence(confidences: List[str]) -> str:
    """Return the lowest confidence among a list of confidences."""
    if not confidences:
        return "likely"
    ranked = sorted(confidences, key=lambda c: CONFIDENCE_RANK.get(c, 1))
    return ranked[0]


def _max_severity(severities: List[str]) -> str:
    """Return the highest severity among a list of severities."""
    if not severities:
        return "medium"
    ranked = sorted(severities, key=lambda s: SEVERITY_WEIGHT.get(s, 0), reverse=True)
    return ranked[0]


def build_attack_chains(
    findings: List[Dict[str, Any]],
    routes: Optional[List[Dict[str, Any]]] = None,
    max_chains: int = 10,
    max_length: int = 4,
) -> Dict[str, Any]:
    """Analyze findings and build explainable multi-step attack chains.

    Returns a dictionary conforming to contracts/schemas/attack-chain.schema.json.
    """
    # Exclude rejected findings or suppressions
    active_findings = [
        f for f in findings
        if f.get("status") != "rejected" and not f.get("suppression")
    ]

    # Map routes by id
    route_map: Dict[str, Dict] = {}
    if routes:
        for r in routes:
            rid = r.get("route_id")
            if rid:
                route_map[rid] = r

    # Profile each finding
    profiles = [profile_finding(f, route_map) for f in active_findings]
    # Filter out profiles without a valid finding_id
    profiles = [p for p in profiles if p["finding_id"]]

    # Graph Traversal: search for chains from entry to impact
    chains_found: List[Dict[str, Any]] = []

    # Separate candidates by role
    entry_candidates = [p for p in profiles if p["requires"] in ("anonymous", "authenticated_user")]
    impact_candidates = [p for p in profiles if p["role_in_chain"] == "impact"]

    if not impact_candidates or len(profiles) < 2:
        # Not enough findings to form any multi-step chain
        return _empty_chain_doc()

    visited_paths: Set[Tuple[str, ...]] = set()

    def search_chain(current_path: List[Dict[str, Any]], active_capabilities: Set[str]):
        if len(current_path) > max_length:
            return

        last_step = current_path[-1]

        # Check if the last step is an impact finding and path length >= 2
        if len(current_path) >= 2 and last_step["role_in_chain"] == "impact":
            path_ids = tuple(p["finding_id"] for p in current_path)
            if path_ids not in visited_paths:
                visited_paths.add(path_ids)
                chains_found.append(_assemble_chain(current_path))
            return

        # Attempt to extend path with next finding
        current_ids = {p["finding_id"] for p in current_path}
        for candidate in profiles:
            if candidate["finding_id"] in current_ids:
                continue

            # Check if candidate requirements are satisfied by active capabilities or caller
            req = candidate["requires"]
            if req in active_capabilities or req in ("anonymous", "authenticated_user"):
                new_caps = set(active_capabilities) | set(candidate["gains"])
                search_chain(current_path + [candidate], new_caps)

    # Start DFS from each entry candidate
    for entry in entry_candidates:
        initial_caps = {"anonymous", "authenticated_user"} | set(entry["gains"])
        search_chain([entry], initial_caps)

    # Deduplicate and sort chains: critical first, then confirmed, then shorter length
    sorted_chains = sorted(
        chains_found,
        key=lambda c: (
            SEVERITY_WEIGHT.get(c["severity"], 0),
            CONFIDENCE_RANK.get(c["confidence"], 0),
            -len(c["steps"]),
        ),
        reverse=True,
    )

    # Keep top N unique chains
    selected_chains = sorted_chains[:max_chains]

    # Re-number chain IDs
    for idx, chain in enumerate(selected_chains, start=1):
        chain["chain_id"] = f"chain-{idx:03d}"

    # Calculate Top Breaking Fixes
    breaking_fix_counts: Dict[str, Dict[str, Any]] = {}
    for chain in selected_chains:
        for fid in chain["breaking_fixes"]:
            if fid not in breaking_fix_counts:
                # Find profile
                prof = next((p for p in profiles if p["finding_id"] == fid), None)
                breaking_fix_counts[fid] = {
                    "finding_id": fid,
                    "category": prof["category"] if prof else "unknown",
                    "location": prof["location"] if prof else "unknown",
                    "chains_broken": 0,
                }
            breaking_fix_counts[fid]["chains_broken"] += 1

    top_breaking_fixes = sorted(
        breaking_fix_counts.values(),
        key=lambda b: b["chains_broken"],
        reverse=True,
    )

    by_severity = {
        s: sum(1 for c in selected_chains if c["severity"] == s)
        for s in ("critical", "high", "medium", "low")
    }

    return {
        "version": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "chains": selected_chains,
        "summary": {
            "total_chains": len(selected_chains),
            "by_severity": by_severity,
            "top_breaking_fixes": top_breaking_fixes[:5],
        },
    }


def _assemble_chain(path: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Assemble a formatted attack chain from a sequence of finding profiles."""
    steps: List[Dict[str, Any]] = []
    severities: List[str] = []
    confidences: List[str] = []
    breaking_fixes: List[str] = []

    for idx, p in enumerate(path, start=1):
        steps.append({
            "step_index": idx,
            "finding_id": p["finding_id"],
            "category": p["category"],
            "subtype": p["subtype"],
            "location": p["location"],
            "endpoint": p["endpoint"],
            "role_in_chain": p["role_in_chain"],
            "requires": p["requires"],
            "gains": p["gains"],
            "explanation": f"Exploits {p['category']} at {p['endpoint'] or p['location']} to gain {', '.join(p['gains'])}.",
        })
        severities.append(p["severity"])
        confidences.append(p["confidence"])
        breaking_fixes.append(p["finding_id"])

    entry_step = path[0]
    final_step = path[-1]

    # Generate a descriptive title
    cats = [p["category"].replace("_", " ").title() for p in path]
    title = " → ".join(cats) + f" targeting {final_step['entity']}"

    outcome = f"Unauthorized access and data exfiltration of {final_step['entity']} records."
    business_impact = (
        f"Attackers can leverage initial {entry_step['category']} on {entry_step['endpoint'] or entry_step['location']} "
        f"to achieve full compromise and data leakage of {final_step['entity']} records, causing regulatory breach and customer trust loss."
    )

    # Overall chain severity is at least high if it reaches impact, critical if it reaches admin/leak
    chain_sev = _max_severity(severities)
    if any("impact:data_leak" in p["gains"] for p in path) and any("privilege:admin" in p["gains"] for p in path):
        chain_sev = "critical"

    return {
        "chain_id": "chain-000",
        "title": title,
        "entry": entry_step["requires"],
        "steps": steps,
        "outcome": outcome,
        "business_impact": business_impact,
        "severity": chain_sev,
        "confidence": _min_confidence(confidences),
        "breaking_fixes": breaking_fixes,
    }


def _empty_chain_doc() -> Dict[str, Any]:
    return {
        "version": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "chains": [],
        "summary": {
            "total_chains": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "top_breaking_fixes": [],
        },
    }


def render_attack_chains_md(chains_doc: Dict[str, Any], lang: str = "en") -> List[str]:
    """Generate Markdown report section for attack chains in English or Japanese."""
    chains = chains_doc.get("chains", [])
    if not chains:
        return []

    top_fixes = chains_doc.get("summary", {}).get("top_breaking_fixes", [])

    if lang == "ja":
        lines = [
            "## 攻撃チェーン（複合攻撃シナリオ）",
            "",
            "単独では重大度が「中」または「高」にとどまる脆弱性であっても、攻撃者はそれらを組み合わせて権限昇格や大規模な情報漏洩を達成します。"
            "以下の**最優先対策（Breaking Fixes）**を適用することで、最小限の修正工数で最も多くの攻撃シナリオを無力化できます。",
            "",
            "### 最優先対策（Breaking Fixes）",
            "",
            "| 検出ID | 脆弱性分類 | 該当箇所 | 遮断されるシナリオ数 |",
            "|---|---|---|---|",
        ]
        for tf in top_fixes:
            lines.append(f"| `{tf['finding_id']}` | {tf['category']} | `{tf['location']}` | **{tf['chains_broken']}** |")

        lines += ["", "### 特定された攻撃シナリオ一覧", ""]
        for c in chains:
            lines += [
                f"#### {c['chain_id']} — {c['title']}",
                "",
                f"- **開始権限:** `{c['entry']}`",
                f"- **重要度 / 確信度:** {c['severity']} / {c['confidence']}",
                f"- **結果 / 影響:** {c['outcome']}",
                f"- **ビジネス影響:** {c['business_impact']}",
                "- **攻撃ステップ:**",
            ]
            for s in c["steps"]:
                lines.append(f"  {s['step_index']}. `{s['finding_id']}` ({s['role_in_chain']}): {s['explanation']}")
            lines.append(f"- **遮断に必要な対策:** {', '.join(f'`{f}`' for f in c['breaking_fixes'])}")
            lines.append("")
    else:
        lines = [
            "## Attack Chains (Chained Attack Scenarios)",
            "",
            "Real-world attacks combine multiple vulnerabilities into end-to-end exploit flows. "
            "Fixing the bottleneck findings below breaks the most attack chains with minimum engineering effort.",
            "",
            "### Top Breaking Fixes",
            "",
            "| Finding ID | Category | Location | Chains Broken |",
            "|---|---|---|---|",
        ]
        for tf in top_fixes:
            lines.append(f"| `{tf['finding_id']}` | {tf['category']} | `{tf['location']}` | **{tf['chains_broken']}** |")

        lines += ["", "### Identified Attack Scenarios", ""]
        for c in chains:
            lines += [
                f"#### {c['chain_id']} — {c['title']}",
                "",
                f"- **Starting Privilege:** `{c['entry']}`",
                f"- **Severity / Confidence:** {c['severity']} / {c['confidence']}",
                f"- **Outcome:** {c['outcome']}",
                f"- **Business Impact:** {c['business_impact']}",
                "- **Attack Steps:**",
            ]
            for s in c["steps"]:
                lines.append(f"  {s['step_index']}. `{s['finding_id']}` ({s['role_in_chain']}): {s['explanation']}")
            lines.append(f"- **Breaking Fixes:** {', '.join(f'`{f}`' for f in c['breaking_fixes'])}")
            lines.append("")

    return lines


def render_attack_chains_html(chains_doc: Dict[str, Any]) -> str:
    """Generate self-contained bilingual HTML card visualizing attack chains."""
    chains = chains_doc.get("chains", [])
    if not chains:
        return ""

    top_fixes = chains_doc.get("summary", {}).get("top_breaking_fixes", [])

    fix_rows = "".join(
        f"<tr><td><code>{html.escape(tf['finding_id'])}</code></td>"
        f"<td>{html.escape(tf['category'])}</td>"
        f"<td><code>{html.escape(tf['location'])}</code></td>"
        f"<td><span class=\"badge badge-critical\">{tf['chains_broken']}</span></td></tr>"
        for tf in top_fixes
    ) or "<tr><td colspan=\"4\">No breaking fixes identified.</td></tr>"

    chain_cards: List[str] = []
    for c in chains:
        sev = c.get("severity", "high")
        steps_html = []
        for s in c.get("steps", []):
            role_label = html.escape(s.get("role_in_chain", "step"))
            cat = html.escape(s.get("category", ""))
            fid = html.escape(s.get("finding_id", ""))
            loc = html.escape(s.get("location", ""))
            steps_html.append(
                f'<div class="chain-step-node">'
                f'<div class="chain-step-badge">Step {s.get("step_index", 1)}: {role_label}</div>'
                f'<div class="chain-step-id"><strong>{fid}</strong> ({cat})</div>'
                f'<div class="chain-step-loc">{loc}</div>'
                f'</div>'
            )
        flow_html = ' <span class="chain-arrow">&rarr;</span> '.join(steps_html)

        chain_cards.append(
            f'<div class="chain-item-card">'
            f'<div class="chain-item-header">'
            f'<span class="badge badge-{sev}">{sev.upper()}</span> '
            f'<strong>{html.escape(c.get("chain_id", ""))}</strong>: {html.escape(c.get("title", ""))}'
            f'</div>'
            f'<div class="chain-flow-diagram">{flow_html}</div>'
            f'<div class="chain-impact-desc"><strong>Impact:</strong> {html.escape(c.get("business_impact", ""))}</div>'
            f'</div>'
        )

    all_chains_html = "".join(chain_cards)

    return (
        '<section class="card" aria-label="Chained Attack Scenarios">'
        '<h2 class="card-title" data-en="Chained Attack Scenarios &amp; Breaking Fixes" data-ja="複合攻撃シナリオ・最優先対策 (Attack Chains)">Chained Attack Scenarios &amp; Breaking Fixes</h2>'
        '<p class="card-desc" data-en="Real-world attacks combine multiple vulnerabilities. Prioritize fixing the bottleneck findings below to neutralize the most attack chains with minimum engineering effort." '
        'data-ja="実際の攻撃は複数の脆弱性を組み合わせます。以下の最優先対策（Bottleneck）を実施することで、最小の工数で最大の防御効果が得られます。">'
        'Real-world attacks combine multiple vulnerabilities. Prioritize fixing the bottleneck findings below to neutralize the most attack chains with minimum engineering effort.</p>'
        '<h3 data-en="Top Breaking Fixes (Max Impact)" data-ja="最優先対策（最大防御効果）">Top Breaking Fixes (Max Impact)</h3>'
        '<table><thead><tr>'
        '<th data-en="Finding ID" data-ja="検出ID">Finding ID</th>'
        '<th data-en="Category" data-ja="脆弱性分類">Category</th>'
        '<th data-en="Location" data-ja="該当箇所">Location</th>'
        '<th data-en="Chains Broken" data-ja="遮断シナリオ数">Chains Broken</th>'
        f'</tr></thead><tbody>{fix_rows}</tbody></table>'
        '<h3 data-en="Identified Attack Flows" data-ja="特定された攻撃フロー">Identified Attack Flows</h3>'
        f'<div class="chain-list-container">{all_chains_html}</div>'
        '</section>'
    )


def attach_chains_to_sarif(sarif_data: Dict[str, Any], chains_doc: Dict[str, Any]) -> Dict[str, Any]:
    """Annotate SARIF results with attack chain memberships in properties.attackChains."""
    if not chains_doc.get("chains") or not sarif_data.get("runs"):
        return sarif_data

    # Map finding_id to chain IDs
    finding_to_chains: Dict[str, List[str]] = {}
    for chain in chains_doc["chains"]:
        cid = chain["chain_id"]
        for step in chain["steps"]:
            fid = step["finding_id"]
            finding_to_chains.setdefault(fid, []).append(cid)

    for run in sarif_data.get("runs", []):
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "")
            fingerprints = res.get("partialFingerprints", {})
            kfp = fingerprints.get("komagu/v1") or fingerprints.get("komainu/v1")

            matched_chains = set()
            if rule_id in finding_to_chains:
                matched_chains.update(finding_to_chains[rule_id])
            if kfp and kfp in finding_to_chains:
                matched_chains.update(finding_to_chains[kfp])

            if matched_chains:
                props = res.setdefault("properties", {})
                props["attackChains"] = sorted(matched_chains)

    return sarif_data


def main() -> int:
    parser = argparse.ArgumentParser(description="Build attack chains from findings.json.")
    parser.add_argument("out_dir", type=Path, help="Path to audit OUT directory.")
    parser.add_argument("--routes", type=Path, default=None, help="Path to routes.json (optional).")
    parser.add_argument("--output", type=Path, default=None, help="Output attack-chains.json path.")
    args = parser.parse_args()

    findings_file = args.out_dir / "findings.json"
    if not findings_file.exists():
        print(f"Error: {findings_file} not found.", file=sys.stderr)
        return 1

    with open(findings_file, encoding="utf-8") as fh:
        findings = json.load(fh)

    routes = None
    routes_file = args.routes or (args.out_dir / "routes.json")
    if routes_file.exists():
        with open(routes_file, encoding="utf-8") as fh:
            routes = json.load(fh)

    chain_doc = build_attack_chains(findings, routes)

    out_file = args.output or (args.out_dir / "attack-chains.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(chain_doc, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    print(f"✔ Generated {chain_doc['summary']['total_chains']} attack chains -> {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
