#!/usr/bin/env python3
"""API Inventory & Shadow/Zombie API Detection Engine.

Standard-library-only (Python 3.8+).

Compares three sources:
1. Routes extracted from source code (routes.json / routes.candidates.json from LSA),
2. OpenAPI / Swagger specification published by the team,
3. Live traffic logs captured at the API gateway (Kong HTTP-Log / NGINX access log).

Detects:
- Shadow APIs: Endpoints in code or active traffic missing from OpenAPI spec.
- Zombie APIs: Endpoints marked deprecated in OpenAPI spec but still receiving traffic.
- Documented Missing in Code: Declared in spec but not implemented.
- Dormant Code: Documented code endpoints receiving zero traffic.
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

# Path parameter patterns for normalization (shared semantics with fingerprint.py)
_PATH_PARAM_RES = (
    re.compile(r"\{[^/}]*\}"),  # /orders/{id}
    re.compile(r"<[^/>]*>"),  # Flask /orders/<int:id>
    re.compile(r"(?<=/):[A-Za-z_][A-Za-z0-9_]*"),  # Express /orders/:orderId
    re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),  # UUIDs
    re.compile(r"(?<=/)[0-9a-fA-F]{24,}(?=/|$)"),  # MongoDB ObjectId / hex hashes
    re.compile(r"(?<=/)[0-9]+(?=/|$)"),  # Concrete integer IDs /orders/123
)

# Combined / Common Log Format (Nginx / Kong standard)
_COMBINED_LOG_RE = re.compile(
    r'^[^\s]+\s+[^\s]+\s+[^\s]+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>[^\s\?]+)(?:\?[^\s"]*)?\s+HTTP/[0-9\.]+"\s+(?P<status>\d{3})'
)

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}


def normalize_path(path: str) -> str:
    """Strip query params and replace variable route parameters with {}."""
    if not path:
        return "/"
    p = path.split("?")[0].strip()
    if not p.startswith("/"):
        p = "/" + p
    # Remove trailing slash except for root
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1]

    for pat in _PATH_PARAM_RES:
        p = pat.sub("{}", p)
    return p


def normalize_route_key(method: str, path: str) -> str:
    """Format canonical uppercase method and normalized path: 'GET /api/orders/{}'."""
    return f"{method.upper().strip()} {normalize_path(path)}"


def route_pattern_to_regex(normalized_key: str) -> re.Pattern:
    """Convert a normalized route key (e.g. 'GET /api/orders/{}') into a matching regex."""
    parts = normalized_key.split(" ", 1)
    if len(parts) != 2:
        return re.compile(r"^$")
    method, path_templ = parts
    # Escape regex specials except {}
    escaped = re.escape(path_templ).replace(r"\{\}", r"[^/]+")
    return re.compile(f"^{re.escape(method)}\\s+{escaped}$")


def load_code_routes(routes_path: Path) -> List[Dict[str, Any]]:
    """Parse routes from LSA routes.json or routes.candidates.json."""
    if not routes_path.is_file():
        return []
    with open(routes_path, encoding="utf-8") as fh:
        doc = json.load(fh)

    raw_list = doc.get("routes", []) if isinstance(doc, dict) else (doc if isinstance(doc, list) else [])
    parsed = []
    for r in raw_list:
        if not isinstance(r, dict):
            continue
        m = (r.get("method") or "GET").upper()
        p = r.get("path") or "/"
        loc = r.get("location") or r.get("file") or ""
        norm = normalize_route_key(m, p)
        parsed.append({
            "method": m,
            "path": p,
            "normalized": norm,
            "location": loc,
            "route_id": r.get("route_id", ""),
            "raw": r,
        })
    return parsed


def load_openapi_spec(spec_path: Path) -> List[Dict[str, Any]]:
    """Parse endpoints and deprecation status from OpenAPI/Swagger JSON or simple YAML."""
    if not spec_path.is_file():
        return []

    content = spec_path.read_text(encoding="utf-8").strip()
    doc = None
    if content.startswith("{"):
        try:
            doc = json.loads(content)
        except json.JSONDecodeError:
            pass

    if doc is None:
        # Fallback basic YAML parser for paths/methods
        doc = _parse_simple_openapi_yaml(content)

    if not isinstance(doc, dict):
        return []

    endpoints = []
    paths_dict = doc.get("paths", {})
    if isinstance(paths_dict, dict):
        for path_key, item in paths_dict.items():
            if not isinstance(item, dict):
                continue
            path_deprecated = bool(item.get("deprecated", False))
            for m_key, op in item.items():
                m_upper = m_key.upper()
                if m_upper in HTTP_METHODS and isinstance(op, dict):
                    is_dep = path_deprecated or bool(op.get("deprecated", False))
                    summary = op.get("summary") or op.get("description") or ""
                    endpoints.append({
                        "method": m_upper,
                        "path": path_key,
                        "normalized": normalize_route_key(m_upper, path_key),
                        "deprecated": is_dep,
                        "summary": summary,
                    })
    return endpoints


def _parse_simple_openapi_yaml(yaml_text: str) -> Dict[str, Any]:
    """Lightweight pure stdlib parser for OpenAPI YAML path structures."""
    # When PyYAML is not in standard library, parse basic indented paths structure
    paths: Dict[str, Any] = {}
    current_path = None
    current_method = None

    for raw_line in yaml_text.splitlines():
        line = raw_line.rstrip()
        if not line or line.strip().startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        # Path level (e.g. "  /api/orders/{id}:")
        if stripped.startswith("/") and stripped.endswith(":"):
            current_path = stripped[:-1].strip()
            paths[current_path] = {}
            current_method = None
        # Method level (e.g. "    get:")
        elif current_path and ":" in stripped and indent >= 4:
            key, val = stripped.split(":", 1)
            key = key.strip().lower()
            if key in {"get", "post", "put", "delete", "patch", "options", "head"}:
                current_method = key
                paths[current_path][current_method] = {}
            elif current_method and key == "deprecated":
                paths[current_path][current_method]["deprecated"] = val.strip().lower() in ("true", "yes")

    return {"paths": paths}


def load_traffic_log(log_path: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    """Parse traffic logs from Kong HTTP-Log (JSON lines) or NGINX Combined Log Format."""
    if not log_path or not log_path.is_file():
        return {}

    traffic: Dict[str, Dict[str, Any]] = {}

    with open(log_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue

            method, uri, timestamp = None, None, None

            # Try JSON (Kong HTTP-Log plugin / NDJSON)
            if line.startswith("{") and line.endswith("}"):
                try:
                    obj = json.loads(line)
                    req = obj.get("request", {}) if isinstance(obj.get("request"), dict) else obj
                    method = (req.get("method") or "").upper()
                    uri = req.get("uri") or req.get("url") or req.get("path") or ""
                    # strip scheme/host if full URL
                    if "://" in uri:
                        uri = "/" + uri.split("://", 1)[1].split("/", 1)[-1]
                    timestamp = str(obj.get("started_at") or obj.get("timestamp") or "")
                except json.JSONDecodeError:
                    pass

            # Try NGINX / Kong Combined Log Format
            if not method or not uri:
                m = _COMBINED_LOG_RE.match(line)
                if m:
                    method = m.group("method").upper()
                    uri = m.group("uri")
                    timestamp = m.group("time")

            if method and uri and method in HTTP_METHODS:
                norm_key = normalize_route_key(method, uri)
                if norm_key not in traffic:
                    traffic[norm_key] = {
                        "method": method,
                        "path": uri,
                        "normalized": norm_key,
                        "traffic_hits": 0,
                        "last_seen": timestamp or "unknown",
                    }
                traffic[norm_key]["traffic_hits"] += 1
                if timestamp:
                    traffic[norm_key]["last_seen"] = timestamp

    return traffic


def match_request_to_templates(req_norm_key: str, template_keys: Set[str]) -> Optional[str]:
    """Match a normalized concrete request against known route templates."""
    if req_norm_key in template_keys:
        return req_norm_key

    # Check parameter wildcards
    req_parts = req_norm_key.split(" ", 1)
    if len(req_parts) != 2:
        return None
    req_m, req_p = req_parts

    for tpl in template_keys:
        tpl_parts = tpl.split(" ", 1)
        if len(tpl_parts) != 2:
            continue
        tpl_m, tpl_p = tpl_parts
        if req_m != tpl_m:
            continue
        # Compare segment lengths
        r_segs = [s for s in req_p.split("/") if s]
        t_segs = [s for s in tpl_p.split("/") if s]
        if len(r_segs) != len(t_segs):
            continue
        matched = True
        for rs, ts in zip(r_segs, t_segs):
            if ts == "{}":
                continue
            if rs != ts:
                matched = False
                break
        if matched:
            return tpl
    return None


def diff_api_inventory(
    code_routes: List[Dict[str, Any]],
    spec_endpoints: List[Dict[str, Any]],
    traffic_data: Dict[str, Dict[str, Any]],
    routes_file_name: Optional[str] = None,
    openapi_file_name: Optional[str] = None,
    traffic_file_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute 3-way reconciliation to discover Shadow, Zombie, Dead, and Dormant APIs."""
    gen_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Normalize code routes if not pre-normalized
    norm_code_routes = []
    for r in code_routes:
        if "normalized" not in r:
            m = (r.get("method") or "GET").upper()
            p = r.get("path") or "/"
            norm_code_routes.append({**r, "method": m, "path": p, "normalized": normalize_route_key(m, p)})
        else:
            norm_code_routes.append(r)

    # Normalize spec endpoints if not pre-normalized
    norm_spec_endpoints = []
    for s in spec_endpoints:
        if "normalized" not in s:
            m = (s.get("method") or "GET").upper()
            p = s.get("path") or "/"
            norm_spec_endpoints.append({**s, "method": m, "path": p, "normalized": normalize_route_key(m, p)})
        else:
            norm_spec_endpoints.append(s)

    # Map specs by normalized key
    spec_map: Dict[str, Dict[str, Any]] = {e["normalized"]: e for e in norm_spec_endpoints}
    # Map code routes by normalized key
    code_map: Dict[str, Dict[str, Any]] = {r["normalized"]: r for r in norm_code_routes}

    spec_keys = set(spec_map.keys())
    code_keys = set(code_map.keys())

    # Map traffic hits to code and spec templates
    traffic_matched_spec: Dict[str, int] = {}
    traffic_matched_code: Dict[str, int] = {}
    unmatched_traffic: List[Dict[str, Any]] = []

    for req_key, t_info in traffic_data.items():
        matched_spec_key = match_request_to_templates(req_key, spec_keys)
        if matched_spec_key:
            traffic_matched_spec[matched_spec_key] = traffic_matched_spec.get(matched_spec_key, 0) + t_info["traffic_hits"]

        matched_code_key = match_request_to_templates(req_key, code_keys)
        if matched_code_key:
            traffic_matched_code[matched_code_key] = traffic_matched_code.get(matched_code_key, 0) + t_info["traffic_hits"]

        if not matched_spec_key:
            unmatched_traffic.append({
                **t_info,
                "matched_code": matched_code_key,
            })

    # 1. Shadow APIs: Present in code or traffic, but absent from OpenAPI spec
    shadow_apis: List[Dict[str, Any]] = []
    seen_shadow_keys: Set[str] = set()

    for r_key, r_info in code_map.items():
        if not match_request_to_templates(r_key, spec_keys):
            seen_shadow_keys.add(r_key)
            t_hits = traffic_matched_code.get(r_key, 0)
            discovered = "code_and_traffic" if t_hits > 0 else "code_only"
            shadow_apis.append({
                "method": r_info["method"],
                "path": r_info["path"],
                "normalized": r_key,
                "discovered_in": discovered,
                "location": r_info.get("location", ""),
                "traffic_hits": t_hits,
            })

    # Traffic requests never documented and not matched by code routes
    for u_req in unmatched_traffic:
        u_key = u_req["normalized"]
        if u_key not in seen_shadow_keys and not u_req.get("matched_code"):
            seen_shadow_keys.add(u_key)
            shadow_apis.append({
                "method": u_req["method"],
                "path": u_req["path"],
                "normalized": u_key,
                "discovered_in": "traffic_only",
                "location": "Gateway Traffic",
                "traffic_hits": u_req["traffic_hits"],
            })

    # 2. Zombie APIs: Deprecated in OpenAPI spec, but receiving traffic
    zombie_apis: List[Dict[str, Any]] = []
    for s_key, s_info in spec_map.items():
        if s_info.get("deprecated"):
            hits = traffic_matched_spec.get(s_key, 0)
            if hits > 0:
                loc = code_map.get(s_key, {}).get("location", "Documented in Spec")
                zombie_apis.append({
                    "method": s_info["method"],
                    "path": s_info["path"],
                    "normalized": s_key,
                    "location": loc,
                    "traffic_hits": hits,
                    "last_seen": gen_time,
                })

    # 3. Documented Missing in Code: Declared in spec, not in code
    missing_code: List[Dict[str, Any]] = []
    for s_key, s_info in spec_map.items():
        if not match_request_to_templates(s_key, code_keys):
            missing_code.append({
                "method": s_info["method"],
                "path": s_info["path"],
                "normalized": s_key,
                "summary": s_info.get("summary", ""),
            })

    # 4. Dormant Code: In code & spec, but 0 traffic (only if traffic log was supplied)
    dormant_code: List[Dict[str, Any]] = []
    if traffic_data:
        for r_key, r_info in code_map.items():
            if match_request_to_templates(r_key, spec_keys):
                hits = traffic_matched_code.get(r_key, 0)
                if hits == 0:
                    dormant_code.append({
                        "method": r_info["method"],
                        "path": r_info["path"],
                        "normalized": r_key,
                        "location": r_info.get("location", ""),
                    })

    # Sort outputs
    shadow_apis.sort(key=lambda x: (-x.get("traffic_hits", 0), x["normalized"]))
    zombie_apis.sort(key=lambda x: (-x.get("traffic_hits", 0), x["normalized"]))
    missing_code.sort(key=lambda x: x["normalized"])
    dormant_code.sort(key=lambda x: x["normalized"])

    return {
        "version": 1,
        "generated_at": gen_time,
        "sources": {
            "routes_file": routes_file_name,
            "openapi_file": openapi_file_name,
            "traffic_log_file": traffic_file_name,
        },
        "summary": {
            "total_code_routes": len(code_routes),
            "total_spec_endpoints": len(spec_endpoints),
            "total_traffic_endpoints": len(traffic_data),
            "shadow_count": len(shadow_apis),
            "zombie_count": len(zombie_apis),
            "missing_code_count": len(missing_code),
            "dormant_count": len(dormant_code),
        },
        "shadow_apis": shadow_apis,
        "zombie_apis": zombie_apis,
        "documented_missing_code": missing_code,
        "dormant_code": dormant_code,
    }


def render_inventory_md(diff_doc: Dict[str, Any], lang: str = "en") -> List[str]:
    """Generate Markdown report section for API inventory diff (EN / JA)."""
    s = diff_doc.get("summary", {})
    shadows = diff_doc.get("shadow_apis", [])
    zombies = diff_doc.get("zombie_apis", [])
    missing = diff_doc.get("documented_missing_code", [])

    if lang == "ja":
        lines = [
            "## APIインベントリ照合・Shadow / Zombie API検出 (API Inventory Diff)",
            "",
            "ソースコード (`routes.json`)、公開OpenAPI仕様、およびゲートウェイの通信ログを3者照合し、仕様外エンドポイントや放置APIを特定しました。",
            "",
            "| 項目 | 件数 | 評価 |",
            "|---|---|---|",
            f"| 実装コードAPI数 | {s.get('total_code_routes', 0)} | コードベース内の有効ルート |",
            f"| OpenAPI仕様API数 | {s.get('total_spec_endpoints', 0)} | 公開ドキュメント定義 |",
            f"| 通信確認エンドポイント数 | {s.get('total_traffic_endpoints', 0)} | ゲートウェイ実測トラフィック |",
            f"| **Shadow API (仕様未記載)** | **{s.get('shadow_count', 0)}** | **要確認（認可不備・情報漏洩リスク）** |",
            f"| **Zombie API (非推奨だが稼働中)** | **{s.get('zombie_count', 0)}** | **要廃止（ゾンビAPIトラフィック検知）** |",
            f"| 仕様記載・未実装 (Ghost) | {s.get('missing_code_count', 0)} | 実装欠落または仕様陳腐化 |",
            "",
        ]
        if shadows:
            lines += [
                "### Shadow APIs（ドキュメント未記載・隠しエンドポイント）",
                "",
                "| メソッド & パス | 発見元 | 該当箇所 / 状況 | トラフィック実績 |",
                "|---|---|---|---|",
            ]
            for sh in shadows[:15]:
                lines.append(f"| `{sh['normalized']}` | {sh['discovered_in']} | `{sh.get('location', '-')}` | {sh.get('traffic_hits', 0)} hits |")
            lines.append("")

        if zombies:
            lines += [
                "### Zombie APIs（非推奨指定にも関わらずトラフィックを受信中のAPI）",
                "",
                "| メソッド & パス | 該当コード箇所 | トラフィック実績 | 最終確認日時 |",
                "|---|---|---|---|",
            ]
            for z in zombies[:10]:
                lines.append(f"| `{z['normalized']}` | `{z.get('location', '-')}` | **{z.get('traffic_hits', 0)} hits** | {z.get('last_seen', '-')} |")
            lines.append("")
    else:
        lines = [
            "## API Inventory Reconciliation & Shadow/Zombie API Detection",
            "",
            "Reconciles three independent sources: implementation routes from code, published OpenAPI specification, and live API gateway traffic.",
            "",
            "| Metric | Count | Description |",
            "|---|---|---|",
            f"| Code Routes | {s.get('total_code_routes', 0)} | Endpoints discovered in source code |",
            f"| OpenAPI Endpoints | {s.get('total_spec_endpoints', 0)} | Formally documented endpoints |",
            f"| Traffic Endpoints | {s.get('total_traffic_endpoints', 0)} | Active endpoints observed in gateway traffic |",
            f"| **Shadow APIs (Undocumented)** | **{s.get('shadow_count', 0)}** | **Action required: undocumented attack surface** |",
            f"| **Zombie APIs (Deprecated Active)** | **{s.get('zombie_count', 0)}** | **Action required: deprecated route still receiving traffic** |",
            f"| Documented but Missing in Code | {s.get('missing_code_count', 0)} | Outdated spec or dead documentation |",
            "",
        ]
        if shadows:
            lines += [
                "### Shadow APIs (Undocumented Endpoints)",
                "",
                "| Method & Path | Discovered In | Code Location | Gateway Hits |",
                "|---|---|---|---|",
            ]
            for sh in shadows[:15]:
                lines.append(f"| `{sh['normalized']}` | {sh['discovered_in']} | `{sh.get('location', '-')}` | {sh.get('traffic_hits', 0)} hits |")
            lines.append("")

        if zombies:
            lines += [
                "### Zombie APIs (Deprecated Endpoints Receiving Traffic)",
                "",
                "| Method & Path | Code Location | Gateway Hits | Last Seen |",
                "|---|---|---|---|",
            ]
            for z in zombies[:10]:
                lines.append(f"| `{z['normalized']}` | `{z.get('location', '-')}` | **{z.get('traffic_hits', 0)} hits** | {z.get('last_seen', '-')} |")
            lines.append("")

    return lines


def render_inventory_html(diff_doc: Dict[str, Any]) -> str:
    """Generate self-contained bilingual HTML card for API inventory diff."""
    s = diff_doc.get("summary", {})
    shadows = diff_doc.get("shadow_apis", [])
    zombies = diff_doc.get("zombie_apis", [])

    shadow_rows = "".join(
        f"<tr><td><code>{html.escape(sh['normalized'])}</code></td>"
        f"<td><span class=\"badge badge-high\">{html.escape(sh['discovered_in'])}</span></td>"
        f"<td><code>{html.escape(sh.get('location', '-'))}</code></td>"
        f"<td><strong>{sh.get('traffic_hits', 0)}</strong></td></tr>"
        for sh in shadows[:15]
    ) or "<tr><td colspan=\"4\">No shadow APIs detected.</td></tr>"

    zombie_rows = "".join(
        f"<tr><td><code>{html.escape(z['normalized'])}</code></td>"
        f"<td><code>{html.escape(z.get('location', '-'))}</code></td>"
        f"<td><span class=\"badge badge-critical\">{z.get('traffic_hits', 0)} hits</span></td>"
        f"<td>{html.escape(z.get('last_seen', '-'))}</td></tr>"
        for z in zombies[:10]
    ) or "<tr><td colspan=\"4\">No zombie APIs detected.</td></tr>"

    return (
        '<section class="card" aria-label="API Inventory &amp; Shadow/Zombie Detection">'
        '<h2 class="card-title" data-en="API Inventory &amp; Shadow / Zombie API Detection" '
        'data-ja="APIインベントリ照合・Shadow / Zombie API検出 (Inventory Diff)">API Inventory &amp; Shadow / Zombie API Detection</h2>'
        '<div class="forecast-stats-grid">'
        f'<div class="forecast-stat-box"><div class="stat-lbl" data-en="Code Routes" data-ja="実装コードAPI">Code Routes</div><div class="stat-val">{s.get("total_code_routes", 0)}</div></div>'
        f'<div class="forecast-stat-box"><div class="stat-lbl" data-en="OpenAPI Spec" data-ja="OpenAPI仕様">OpenAPI Spec</div><div class="stat-val">{s.get("total_spec_endpoints", 0)}</div></div>'
        f'<div class="forecast-stat-box"><div class="stat-lbl" data-en="Shadow APIs" data-ja="Shadow API (未記載)">Shadow APIs</div><div class="stat-val" style="color:var(--high);">{s.get("shadow_count", 0)}</div></div>'
        f'<div class="forecast-stat-box"><div class="stat-lbl" data-en="Zombie APIs" data-ja="Zombie API (非推奨稼働)">Zombie APIs</div><div class="stat-val" style="color:var(--crit);">{s.get("zombie_count", 0)}</div></div>'
        '</div>'
        '<h3 data-en="Shadow APIs (Undocumented Endpoints)" data-ja="Shadow APIs（ドキュメント未記載エンドポイント）">Shadow APIs</h3>'
        '<table><thead><tr>'
        '<th data-en="Endpoint" data-ja="エンドポイント">Endpoint</th>'
        '<th data-en="Discovered In" data-ja="発見元">Discovered In</th>'
        '<th data-en="Location" data-ja="該当箇所">Location</th>'
        '<th data-en="Traffic Hits" data-ja="トラフィック数">Traffic Hits</th>'
        f'</tr></thead><tbody>{shadow_rows}</tbody></table>'
        + (
            '<h3 data-en="Zombie APIs (Deprecated but Active Traffic)" data-ja="Zombie APIs（非推奨だがトラフィックを受信中）">Zombie APIs</h3>'
            '<table><thead><tr>'
            '<th data-en="Endpoint" data-ja="エンドポイント">Endpoint</th>'
            '<th data-en="Location" data-ja="該当箇所">Location</th>'
            '<th data-en="Traffic Hits" data-ja="トラフィック数">Traffic Hits</th>'
            '<th data-en="Last Seen" data-ja="最終確認">Last Seen</th>'
            f'</tr></thead><tbody>{zombie_rows}</tbody></table>'
            if zombies else ''
        ) +
        '</section>'
    )
