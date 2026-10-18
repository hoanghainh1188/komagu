---
title: npx一発で動く！レガシーWeb APIの認可不備（BOLA）とSQLiを自動監査するCLIツール「komainu-guard」を作った
tags:
  - Node.js
  - Security
  - API
  - OpenSource
  - AI
private: false
updated_at: '2026-10-18T13:33:12+09:00'
id: da60f64f937b78440af0
organization_url_name: null
slide: false
ignorePublish: false
posting_campaign_uuid: null
agreed_posting_campaign_term: false
---

こんにちは！エンジニアの Harry です。

Web API のセキュリティ診断を行う際、最も厄介で深刻な脆弱性のひとつが **BOLA（Broken Object Level Authorization / オブジェクトレベルの認可不備、別名 IDOR）** です。OWASP API Security Top 10 でも常にトップ（API1:2023）に君臨し続けています。

しかし、長年稼働している **レガシーシステム（PHP、古いJava、ASP.NET等）** において、SonarQube などの従来の SAST（静的解析ツール）を使っても、BOLA はほとんど検出できません。認可ロジックは「ユーザーAがユーザーBのデータにアクセスできるか」という**業務コンテキスト**に依存するため、単なる構文解析では見逃されてしまうためです。

そこで今回、**「AST（抽象構文木）による静的解析」×「マルチエージェントAI（監査役と懐疑派レビュアー）」** を融合させ、インストール不要でローカルから即座に実行できる CLI ツール **「komainu-guard」** を開発し、npm に OSS として公開しました！

:::note info
**npm パッケージ:** [`komainu-guard`](https://www.npmjs.com/package/komainu-guard)  
**実行コマンド:** `npx komainu-guard --help`
:::

---

## 1. 30秒で体験：インストール不要の Quickstart

Node.js 環境があれば、事前インストールなしで `npx` コマンド一発で動かせます。

### バージョン確認
```bash
npx --yes komainu-guard --version
# Output: komainu-guard 0.2.1
```

### ステップ 1：静的プリスキャン（オフライン・ミリ秒で完了）
リポジトリの言語スタック検出、エンドポイントの洗い出し、SQLi・BOLA の潜在候補箇所を AST で高速スキャンします。

```bash
npx --yes komainu-guard pre-scan ./path/to/legacy-repo
```

**実行結果の例：**
```text
Loaded 10 target stacks.
Targets found: 1
Target: ./path/to/legacy-repo
  Stacks: php (confirmed)
  Routes for BOLA: 6 routes
  Injection candidates: 8 locations
  Pre-scan completed in 0.12s.
```

### ステップ 2：AIによる深層監査（Audit）
プリスキャンで絞り込んだエンドポイントに対して、認可ロジックの欠落や文字列結合による SQL インジェクションを AI エージェントが精密に監査します。

```bash
npx --yes komainu-guard audit ./path/to/legacy-repo --out ./audit-result
```

### ステップ 3：インタラクティブな HTML レポートの閲覧
診断結果は SARIF 形式だけでなく、モダンなスタンドアロン HTML レポートとしても出力されます。ブラウザでそのまま開いてチームに共有可能です。

```bash
npx --yes komainu-guard report ./audit-result
```

---

## 2. なぜ作ったのか？（開発背景）

日本のエンタープライズや受託開発（AMS / 保守案件）の現場では、10〜20年以上前に作られた PHP や Java Struts、Classic ASP などのシステムが今なお現役で動いています。

これらのシステムをモダン化するにあたり、以下のような壁にぶつかりました：

1. **従来の SAST ツール（SonarQube、Fortify 等）の限界:**  
   SQL インジェクションのような明確なシンク（Sink）は検出できても、「このコントローラーでテナントIDの検証が抜けている」といった **認可の論理バグ（BOLA）は見落とす**。
2. **単なる LLM プロンプト監査の限界:**  
   「ソースコード全体を LLM に投げて脆弱性を探す」アプローチは、リポジトリが大きくなるとトークン制限・コストが跳ね上がり、何より **ハルシネーション（誤検知・嘘の指摘）** が多すぎて実務で使えない。
3. **セキュリティと機密保持の懸念:**  
   顧客のソースコードをクラウドのパブリック AI に送信して学習されるリスクを絶対に避けたい。

これらを解決するために設計したのが **Komainu LSA（Legacy Security Assessment）** アーキテクチャです。

---

## 3. 「静的解析 × 敵対的マルチエージェント」のアーキテクチャ

komainu-guard の中核は、以下の多層パイプラインで構成されています：

```
+-------------------------------------------------------------------------+
|                        komainu-guard パイプライン                       |
+-------------------------------------------------------------------------+
|                                                                         |
|  [Phase 1] AST 決定論的プリスキャン (完全ローカル・シークレット自動除外)  |
|            -> ルート定義とSQL/クエリ呼び出し箇所を正規表現&ASTで抽出       |
|                                                                         |
|  [Phase 2 & 3] スタック特定 & ルートインベントリ生成                    |
|            -> 認証モデル(auth-model.md)と認可境界を構造化               |
|                                                                         |
|  [Phase 4] 監査役エージェント (Auditor)                                 |
|            -> 絞り込まれたコンテキストのみを読み、BOLA/SQLiを指摘        |
|                                                                         |
|  [Phase 5] 懐疑派レビュアーエージェント (Skeptic Verifier)              |
|            -> 「この指摘は誤検知ではないか？」と反論・検証し誤検知を排除  |
|                                                                         |
|  [Phase 6] 人間（Person B）による最終署名 & マルチフォーマット出力       |
|            -> Markdown, SARIF (GitHub Code Scanning連携), HTML Report    |
+-------------------------------------------------------------------------+
```

### 特徴 1：誤検知を潰す「Skeptic Verifier（懐疑派検証役）」
AI に脆弱性を探させると、存在しない欠陥を過剰に報告しがちです。komainu-guard では、監査役（Auditor）が見つけた指摘に対して、**「その指摘を論破しようとする」独立した検証エージェント（Skeptic Verifier）** を走らせます。
両者が合意した確度の高い脆弱性のみをレポートに採用することで、高い Precision（適合率）を実現しています。

### 特徴 2：10種類の主要レガシースタックに対応
- **PHP** (Plain PHP, CodeIgniter)
- **Java** (Servlet, JSP, Struts 1, Spring MVC, MyBatis, Hibernate)
- **.NET** (ASP.NET WebForms, HTTP Handlers, ASP.NET MVC)
- **Classic ASP** (VBScript)
- **ColdFusion**
- **Node.js** (Express)
- **Python** (Flask)
- **Perl** (CGI)
- **SQL** (Stored Procedures / Functions)

### 特徴 3：エンタープライズに配慮したデータ保護設計
- **Target Read-Only:** 診断対象のソースコードディレクトリには 1 バイトも書き込みを行いません。出力はすべて独立した `OUT` ディレクトリに隔離されます。
- **No Training / Zero Retention:** 機密情報（APIキーやパスワード）は事前スキャンで自動マスキング。ローカル GPU（Qwen 2.5 Coder 等）での完全閉域実行にも対応しています。

---

## 4. ベンチマーク結果

多様な言語スタックを含むテスト用リポジトリ群に対して実施した網羅評価（Evaluation Run 3）において、以下の精度を達成しています：

- **再現率（Recall）:** **100.0%**（植え込まれた脆弱性を 1 件も見落とさず検出）
- **適合率（Precision）:** **1.000**（懐疑派検証役により誤検知ゼロを達成）

---

## 5. まとめと今後の展望

レガシーシステムをセキュアにモダン化する第一歩は、**「客観的かつ正確な現状把握」** から始まります。

`komainu-guard` を使えば、お手元のターミナルで `npx komainu-guard` を実行するだけで、わずか数分で既存コードベースの認可リスクを可視化できます。

今後は、脆弱性の検出（Assess）にとどまらず、OWASP Coraza WAF を統合した API Gateway（Kong）による境界防御や、.NET / Spring Boot 向けの認可修復ライブラリ（Remediate）の連携も順次強化していく予定です。

まずはぜひ、お手元のレガシープロジェクトやサンプルコードで試してみてください！

- **npm:** [https://www.npmjs.com/package/komainu-guard](https://www.npmjs.com/package/komainu-guard)
- **GitHub:** [https://github.com/hoanghainh1188/komainu](https://github.com/hoanghainh1188/komainu)

フィードバックや Issue、スターをいただけると大変励みになります！
