# データ削除報告書 / Data Deletion Report

> テンプレート: コピーして機密フォルダで記入します。記入済みの報告書をこのリポジトリにコミットしないでください。
> *Template: copy and fill in within the secure pilot directory. Never commit a completed report to this repository.*
> 根拠 / Basis: AI利用承諾申請書 §3-6 ([`docs/pilot-client-ai-approval-consent.md`](../../docs/pilot-client-ai-approval-consent.md))、実施手順書 W12-3 ([`docs/pilot-execution-runbook.md`](../../docs/pilot-execution-runbook.md))

## 1. 対象 / Engagement

| 項目 / Item | 記入 / Entry |
|---|---|
| 対象システム / System | `<system name from the signed approval>` |
| 承諾書の日付 / Approval date | `<YYYY-MM-DD>` |
| 実行方式 / Hosting option | `<A: on-premises / B: Japan-region cloud>` |
| 成果物の納品日 / Deliverables handed over | `<YYYY-MM-DD>` |
| 作業端末 / Workstation | `<asset ID or host name>` |
| ディスク暗号化 / Disk encryption | `<method, or none>` |

## 2. 削除記録 / Deletion Record

作業環境上のソースコード複製、解析データ、ログを削除し、1行ごとに記録します。該当しない行は「該当なし / N/A」と理由を記入します。
*Record one row for each location of the source copy, analysis data and logs. For a row that does not apply, enter N/A and the reason.*

| # | 区分 / Category | パス / Path | 削除方法 / Method | 削除日時 / Deleted at (JST) | 実施者 / Operator | 確認者 / Verifier | 確認結果 / Verified absent |
|---|---|---|---|---|---|---|---|
| 1 | ソース複製 / Filtered source copy | `~/pilot/src` | | | | | ☐ |
| 2 | 修正用複製 / Working copy for fixes | `~/pilot/src-fixed` | | | | | ☐ |
| 3 | 解析データ / Analysis output, including `ai-raw/` and `.cache/` | `~/pilot/out*` | | | | | ☐ |
| 4 | パッチ等 / Patches and rules | `~/pilot/fix.patch`, `~/pilot/virtual-patches.conf` | | | | | ☐ |
| 5 | 設定・一覧 / Pilot config, exclude list, file list | `~/pilot/pilot-config.json`, `~/pilot/ams-exclude.txt`, `~/pilot/src-file-list.txt` | | | | | ☐ |
| 6 | カナリア文字列 / Canary strings | `~/pilot/canaries.txt` | | | | | ☐ |
| 7 | モデルサーバーログ / Model server logs (option A) | `<log path, for example ~/.ollama/logs>` | | | | | ☐ |
| 8 | クラウド・プロキシのログ / Cloud or proxy logs (option B) | `<service, region, log location>` | | | | | ☐ |
| 9 | 一時ディレクトリ / Temporary directories | `$TMPDIR`, `/tmp`, `/var/tmp` | | | | | ☐ |
| 10 | シェル履歴等 / Shell history, editor swap files | `<paths checked>` | | | | | ☐ |
| 11 | バックアップ・スナップショット / Backups and snapshots | `<paths or services checked>` | | | | | ☐ |

## 3. 確認方法 / Verification

確認者は実施者とは別の担当者とします。実行したコマンドと結果を記録します。結果にはファイルの内容を含めないでください。
*The verifier must be a different person from the operator. Record the commands run and their results, without any file contents.*

| 確認項目 / Check | コマンド等 / Command or method | 結果 / Result |
|---|---|---|
| 削除対象パスが存在しない / Listed paths no longer exist | `ls -d ~/pilot/src ~/pilot/src-fixed ~/pilot/out*` | |
| ソース由来のファイルが一時領域に残っていない / No source-derived files remain in temporary locations | `<command>` | |
| 第三者への送信がなかった範囲の確認 / Model endpoint matched the approved option | `<ai-run-stats.json or logs reviewed before deletion>` | |
| 最終の漏えいチェック / Final leak check before deletion | `komagu leak-check` 終了コード / exit code: `<0, 1 or 2>`、実施日 / date: `<YYYY-MM-DD>` | |

## 4. 削除しなかったもの / Retained Items

| 項目 / Item | 保管者 / Held by | 理由 / Reason | 保管期限 / Until |
|---|---|---|---|
| 納品済み報告書・パッチ / Delivered reports and patches | 貴社 / Client | 納品物 / Deliverable | 貴社規程による / Per client policy |
| 署名済み承諾書、本報告書 / Signed approval and this report | `<holder>` | 契約記録 / Contract record | `<date>` |
| `<other item, or none>` | | | |

## 5. 例外・制約 / Exceptions and Limitations

削除できなかったデータ、外部サービス側の保持、バックアップの消去予定などを記入します。ファイルシステム上の削除は、SSD上の物理的な完全消去を保証するものではありません。上書き消去や暗号鍵の破棄を行った場合は、その方法を §2 に記入します。
*Record any data that could not be deleted, retention on the service side and scheduled backup expiry. Deleting a file does not guarantee physical erasure on an SSD. If overwriting or key destruction was used, state it in §2.*

`<none, or details>`

## 6. 署名 / Sign-off

上記のとおり削除を実施し、確認したことを報告します。
*We report that the deletion above was carried out and verified.*

| 役割 / Role | 氏名 / Name | 所属 / Organization | 日付 / Date | 署名 / Signature |
|---|---|---|---|---|
| 実施者 / Operator | | | | |
| 確認者 / Verifier | | | | |
