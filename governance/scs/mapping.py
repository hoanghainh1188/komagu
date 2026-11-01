#!/usr/bin/env python3
"""METI Supply Chain Security (SCS ★3/★4) & NIST CSF 2.0 Mapping Knowledge Base.

Maps Komagu technical audit outputs (SARIF, SBOM, BAS evidence, API inventory diffs,
Coraza WAF rules, Cross-user test reports) into official METI Supply Chain Security
evaluation requirements and NIST Cybersecurity Framework 2.0 subcategories.

Standard library only (Python 3.8+) per ADR-0006.
"""

from __future__ import annotations

from typing import Any, Dict, List

LEGAL_DISCLAIMER_JA = (
    "【重要事項・法的免責事項】本エビデンスパックおよびギャップ分析レポートは、"
    "Komagu Modernization Platformが自律生成した技術的監査成果物をMETIサプライチェーン・"
    "サイバーセキュリティ評価制度（SCS ★3/★4）およびNIST CSF 2.0の統制項目に機械的に照合した技術支援資料です。"
    "本資料は経産省公認の認証機関による正式な適合性評価または認証を代替するものではありません。"
)

LEGAL_DISCLAIMER_EN = (
    "IMPORTANT DISCLAIMER: This evidence pack and gap analysis report represents technical mapping "
    "of automated Komagu audit artifacts against METI Supply Chain Security (SCS ★3/★4) and NIST CSF 2.0 controls. "
    "This pack supports, but does not replace or constitute, a formal accredited assessment by a certified evaluation authority."
)

SCS_CONTROLS: List[Dict[str, Any]] = [
    {
        "control_id": "SCS-AM-01",
        "category": "Asset & Surface Management",
        "name_en": "Comprehensive Software & API Inventory",
        "name_ja": "ソフトウェア資産およびAPIエンドポイント台帳の網羅的把握",
        "tier": "★3",
        "nist_csf_v2": ["ID.AM-01", "ID.AM-02"],
        "expected_artifacts": ["api-inventory-diff.json", "routes.json", "route-inventory.json"],
        "description_en": "Complete visibility of implemented routes, published API contracts, and active gateway traffic to eliminate undocumented shadow and zombie APIs.",
        "description_ja": "ソースコード実装ルート、OpenAPI公開仕様、ゲートウェイ実トラフィックを突き合わせ、未管理のShadow APIおよび非推奨Zombie APIを網羅的に特定・管理する。",
        "action_required_en": "Review detected Shadow APIs and register them in OpenAPI specification, or decommission Zombie APIs.",
        "action_required_ja": "未記載のShadow APIをOpenAPI仕様書に登録するか、稼働中のZombie APIを廃止してください。",
    },
    {
        "control_id": "SCS-AM-02",
        "category": "Supply Chain Integrity",
        "name_en": "Software Bill of Materials (SBOM) & Component Provenance",
        "name_ja": "ソフトウェア部品表 (SBOM) の生成および依存関係リスク管理",
        "tier": "★3",
        "nist_csf_v2": ["ID.AM-05"],
        "expected_artifacts": ["sbom-cyclonedx.json", "sbom-spdx.json", "sbom.json"],
        "description_en": "Generation and tracking of standard CycloneDX 1.5 or SPDX 2.3 SBOM for all direct and transitive third-party dependencies.",
        "description_ja": "すべての直接・推移的サードパーティライブラリについて、標準規格（CycloneDX 1.5 / SPDX 2.3）に準拠したSBOMを作成・追跡する。",
        "action_required_en": "Update third-party dependencies with identified High/Critical CVEs or unmaintained licenses.",
        "action_required_ja": "重大な脆弱性（CVE）または非推奨ライセンスが検出されたサードパーティ依存関係を更新・パッチ適用してください。",
    },
    {
        "control_id": "SCS-AA-01",
        "category": "Identity & Access Control",
        "name_en": "Object-Level Access Control & BOLA/BFLA Defenses",
        "name_ja": "オブジェクトレベル認可制御およびBOLA/IDOR侵害の防止",
        "tier": "★3",
        "nist_csf_v2": ["PR.AA-01", "PR.AA-05"],
        "expected_artifacts": ["findings.sarif", "findings.json", "cross-user-test.json"],
        "description_en": "Enforcement of strict object ownership checks maintaining the HTTP 404 invariant across tenant boundaries.",
        "description_ja": "他テナント・他ユーザーのリソースへのアクセス試行に対し、厳格なHTTP 404 Not Found不変性を維持しデータ漏洩を防止する。",
        "action_required_en": "Apply @RequireOwnership decorators or in-place parameter checks on unprotected endpoints.",
        "action_required_ja": "未保護エンドポイントに対し、所有権検証デコレータまたはKomagu Boilerplate 1認可制御を実装してください。",
    },
    {
        "control_id": "SCS-PS-01",
        "category": "Platform & Perimeter Security",
        "name_en": "Perimeter Virtual Patching & Edge Defense",
        "name_ja": "境界防御ゲートウェイおよび脆弱性バーチャルパッチの適用",
        "tier": "★3",
        "nist_csf_v2": ["PR.PS-01", "PR.PS-02"],
        "expected_artifacts": ["coraza.conf", "kong.yml", "waf-rules.conf"],
        "description_en": "Deployment of zero-code perimeter virtual patches (OWASP Core Rule Set / Coraza WAF) intercepting zero-day probes and injection attacks.",
        "description_ja": "エッジゲートウェイ（Kong / Coraza WAF）によるゼロコード・バーチャルパッチを配備し、既知・未知のインジェクション攻撃を遮断する。",
        "action_required_en": "Ensure edge gateway Coraza WAF plugin is enabled with blocking mode on public endpoints.",
        "action_required_ja": "公開エンドポイントに対し、Coraza WAFのブロッキングモードおよびカスタムSecRuleが有効化されていることを確認してください。",
    },
    {
        "control_id": "SCS-CM-01",
        "category": "Continuous Monitoring & Testing",
        "name_en": "Automated Code Auditing & CI/CD Security Gating",
        "name_ja": "継続的静的コード監査およびCI/CDセキュリティゲートウェイ運用",
        "tier": "★3",
        "nist_csf_v2": ["DE.CM-01"],
        "expected_artifacts": ["findings.sarif", "baseline.json", "audit.sarif"],
        "description_en": "Automated security scanning integrated into CI pipelines with baseline regression tracking and strict break-glass suppression governance.",
        "description_ja": "CI/CDパイプラインと統合された自動セキュリティスキャン、ベースライン回帰検出、および監査ログ付き例外管理を実施する。",
        "action_required_en": "Resolve unresolved Critical/High security findings prior to production deployment.",
        "action_required_ja": "本番リリース前に、未解決のCritical/High脆弱性を解消するか、正式な例外申請（suppressions.json）を記録してください。",
    },
    {
        "control_id": "SCS-IR-01",
        "category": "Active Defense & Incident Response",
        "name_en": "Empirical Breach & Attack Simulation (BAS)",
        "name_ja": "実戦的サイバー攻撃シミュレーション（能動的サイバー防御訓練）",
        "tier": "★4",
        "nist_csf_v2": ["RS.MI-01", "RS.MI-02"],
        "expected_artifacts": ["bas-evidence.json", "bas-report.md"],
        "description_en": "Rehearsal of landmark real-world enterprise cyber attacks (Times Car BOLA, Metabase zero-day SQLi, ransomware disasters) to measure empirical resilience.",
        "description_ja": "著名な実事故（Times Car大規模BOLA、MetabaseゼロデイSQLi、ランサムウェア破壊）に基づくシミュレーションを実施し、組織の能動的防御力を実証する。",
        "action_required_en": "Run BAS simulations quarterly and maintain an overall Platform Resilience Index of >= 90%.",
        "action_required_ja": "四半期ごとにBASシミュレーションを実行し、プラットフォーム耐性スコア（Resilience Index）90%以上を維持してください。",
    },
    {
        "control_id": "SCS-DS-01",
        "category": "Data Security & Resilience",
        "name_en": "Ransomware-Resilient Immutable Storage (WORM Backup)",
        "name_ja": "ランサムウェア耐性不変バックアップ（WORMストレージ保護）",
        "tier": "★4",
        "nist_csf_v2": ["PR.DS-11"],
        "expected_artifacts": ["bas-evidence.json"],
        "description_en": "Verification of Write-Once-Read-Many (WORM) storage locks and S3 Object Lock in COMPLIANCE mode preventing backup truncation and tampering.",
        "description_ja": "Write-Once-Read-Many（WORM）ストレージ保護およびS3 Object Lock（コンプライアンスモード）の検証により、バックアップの改ざん・消去を防止する。",
        "action_required_en": "Configure cloud storage archives with COMPLIANCE mode object lock and cross-region replication.",
        "action_required_ja": "バックアップ保管先に対してコンプライアンスモードのオブジェクトロックおよびクロスリージョンレプリケーションを有効化してください。",
    },
    {
        "control_id": "SCS-OG-01",
        "category": "Organizational Governance",
        "name_en": "CSIRT Incident Reporting & Vendor Notification Protocol",
        "name_ja": "CSIRTインシデント報告体制およびサプライチェーン連絡網の整備",
        "tier": "★3",
        "nist_csf_v2": ["GV.OC-01", "GV.PO-01"],
        "expected_artifacts": ["usage-policy.md", "auth-model.md"],
        "description_en": "Establishment of formal incident communication channels and designated reporting protocols complying with the Active Cyber Defense Act 2025.",
        "description_ja": "能動的サイバー防御法（2025年制定）に基づく重要インフラ・サプライチェーンインシデント通報手順およびCSIRT連携体制を整備・文書化する。",
        "action_required_en": "Document CSIRT contact escalation matrix and prime contractor emergency notification workflow.",
        "action_required_ja": "CSIRT連絡エスカレーションマトリクスおよび元請事業者・所管官庁への緊急通報手順書を策定・保管してください。",
    },
]
