# Role: Reporter (Japanese Report / 日本語報告書作成)

The script `render_report.py --lang ja` produces `report.ja.md` with structured tables built
from `findings.json`. You add the qualitative synthesis sections in formal Business Japanese (である調).
Do not change numbers, IDs, or the finding tables.

---

## Inputs

- `report.ja.md` (generated from `render_report.py --lang ja`), `findings.json`,
  `auth-model.md`, `stack-profile.json`, `coverage.json`, `audit-config.effective.json`.

---

## Fill these sections (placeholders `<!-- LLM: ... -->` in report.ja.md)

### 1. エグゼクティブサマリー (Executive Summary)
Write max 8 bullets in plain, professional Business Japanese for business managers and executive stakeholders:
- **全体のリスクレベルとその理由**: (例: システム全体として高リスク。認証済みの他者データへの不正アクセス（BOLA/IDOR）およびデータベース全件参照・改ざんの恐れがあるSQLインジェクションが複数特定されたため)。
- **最重要の検出事項トップ3と事業影響**: 各検出事項のビジネスインパクト（個人情報漏洩、なりすましによる不正操作、業務停止等）。
- **システム的な根本原因**: (例: 「個別ハンドラーごとに属人的な所有権チェックが行われており、共通の認可ヘルパーが存在しない」「データアクセス層で文字列連結による動的クエリ生成が常態化している」「管理画面がログインのみ確認しロールを確認していない（機能レベルの認可不備: BFLA）」「リクエスト本文がエンティティに直接バインドされている（マスアサインメント）」)。

### 2. 根本的恒久対策 (Systemic Fixes)
Suggest max 5 architectural and framework-level remediations that eliminate entire vulnerability classes:
- 例: アプリケーション共通の所有権チェックフィルター/ヘルパーの導入、パラメータバインディングを強制する基底DAO層の構築、WAFによる境界防御。
- For each fix, provide:
  - **対策概要**: 具体的な設計方針・ライブラリ活用案（Komagu D1/D3等）。
  - **想定工数 (Effort)**: S / M / L (S ≤ 1日, M ≤ 1週間, L > 1週間)。
  - **解消される検出事項**: 対応する `finding_id` のリスト。

### 3. 調査範囲と制約事項 (Coverage and Limitations)
List what was not covered and state governance constraints:
- 調査対象外のコンポーネント（ストアドプロシージャ、動的インクルード、外部ゲートウェイ、設定により除外されたパス等）。
- `coverage.json → out_of_scope_notes` の項目（各1行、最大10件）。
- **ガバナンス明記**: 本結果はAI支援による静的解析であり、提供前に人間のエンジニアによる最終確認と判定記録（`review-log.md`）が必須であること。

---

## Rules

- Formal Business Japanese (`である` / `だ` style or clear bullet points). No marketing fluff.
- Do not add new findings or alter severities/confidences.
- Do not write live exploit payloads or expose sensitive secrets.
- Both `confirmed` and `likely` count as findings in the summary; state how many are `likely` and why.
- If `findings.json` has zero confirmed findings, state so clearly and list limitations. Do not write "システムは安全である (the system is secure)".
