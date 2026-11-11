# Pilot: Client AI Processing Approval & Data Governance Protocol (AMS Project)
## パイロット案件におけるAIコード解析利用許諾およびデータガバナンス規程

**Version:** 1.1  
**Effective Date:** 2026-11-03  
**Project Lead & Sign-off Authority:** Harry (Principal Architect / PM / Person B)  
**Classification:** Confidential — Internal & Client Governance (`docs/`)  
**Related Issues:** [hoanghainh1188/komagu#5](https://github.com/hoanghainh1188/komagu/issues/5), [hoanghainh1188/komagu#350](https://github.com/hoanghainh1188/komagu/issues/350)  
**Runbook:** [Pilot Execution Runbook (AMS, Java)](pilot-execution-runbook.md)  
**Parent Plan:** [Boilerplate 1 — Secure API & IAM Delivery Plan (Pilot Section)](boilerplate-1-delivery-plan.md)

---

## 1. Executive Summary & Purpose (概要と目的)

### 1.1 Purpose (目的)
Nhằm chuẩn bị cho giai đoạn **Thử nghiệm thực tế (Pilot: Tuần 9–12)** của dự án Komagu trên hệ thống đang bảo trì (**AMS - Application Maintenance Service**), tài liệu này thiết lập:
1. **Khung quản trị dữ liệu và an toàn thông tin (Data Governance & Security Protocol)** khi áp dụng công nghệ Trí tuệ Nhân tạo (AI/LLM) để rà soát mã nguồn tự động (LSA - Legacy Security Assessment) và hỗ trợ hiện đại hóa API bảo mật.
2. **Mẫu văn bản xin phê duyệt chính thức (Formal AI Processing Consent Letter / 稟議・利用許諾申請書)** song ngữ Nhật - Anh chuẩn mực, sẵn sàng trình ký Ban lãnh đạo và Bộ phận An toàn Thông tin của khách hàng AMS.
3. **Kế hoạch dự phòng (Fallback Plan)** trong trường hợp khách hàng chưa kịp hoàn tất thủ tục phê duyệt trước hạn chót Tuần 6 (Week 6 deadline).

### 1.2 Target System Criteria (Tiêu chí hệ thống áp dụng)
Theo kế hoạch tại [Delivery Plan §Pilot](boilerplate-1-delivery-plan.md#pilot-assess-then-fix-with-the-boilerplate):
- Hệ thống thuộc phạm vi hợp đồng bảo trì AMS hiện hữu.
- Quy mô kiến trúc: Web API xử lý dữ liệu định danh người dùng (per-user/multi-tenant data) với quy mô từ **30 đến 150 endpoints**.
- Ngăn xếp công nghệ ưu tiên: Các ngôn ngữ legacy được bộ công cụ Komagu LSA hỗ trợ đầy đủ (PHP, Java/Spring, ASP.NET Core/.NET Framework).
- **Hệ thống AMS dự kiến (2026-11-03):** Java legacy (JSP / Struts / Spring). Tier 1 của LSA nhận diện Servlet, JSP, Struts 1/2, Spring MVC, MyBatis/iBATIS và Hibernate/JPA (đã chạy thử trên `assess/lsa/tests/fixtures/java-legacy`).

---

## 2. Core Security & Data Governance Guarantees (セキュリティおよびデータガバナンス誓約)

Doanh nghiệp Nhật Bản đặc biệt coi trọng an toàn thông tin, bảo vệ tài sản sở hữu trí tuệ (IP) và tuân thủ Đạo luật bảo vệ thông tin cá nhân (APPI - 個人情報保護法) cũng như Tiêu chuẩn Quản lý An toàn Thông tin (JIS Q 27001 / ISO/IEC 27001). Komagu đưa ra 6 cam kết kỹ thuật bất biến sau:

```
+---------------------------------------------------------------------------------------+
|                       KOMAGU AI DATA GOVERNANCE FRAMEWORK                             |
+---------------------------------------------------------------------------------------+
|  [1] Zero Model Training     -> Tuyệt đối KHÔNG dùng code khách hàng để huấn luyện AI |
|  [2] Zero Data Retention     -> Xóa bộ nhớ đệm ngay sau khi phân tích (No Persistence)|
|  [3] Read-Only Code Scans    -> Quét tĩnh cục bộ, KHÔNG ghi đè lên kho mã nguồn gốc  |
|  [4] No Production DB Access -> KHÔNG chạm CSDL vận hành, KHÔNG truy cập dữ liệu PII  |
|  [5] Secret Pre-Redaction    -> Bộ lọc tự động loại bỏ Token/Pass/Key trước khi gửi   |
|  [6] Person B Human Sign-off -> Con người (Harry) thẩm định 100% trước khi công bố    |
+---------------------------------------------------------------------------------------+
```

### 2.1 Không sử dụng dữ liệu huấn luyện (No Model Training Guarantee)
- **Cam kết:** Mã nguồn, tài liệu cấu trúc, sơ đồ lớp và mọi dữ liệu liên quan của khách hàng **TUYỆT ĐỐI KHÔNG** được sử dụng để tái huấn luyện (retrain), tinh chỉnh (fine-tune) hoặc cải thiện bất kỳ mô hình AI thương mại hay công cộng nào.
- **Cơ sở pháp lý & kỹ thuật:** Thỏa thuận cấp độ dịch vụ doanh nghiệp (Enterprise SLA / Data Processing Addendum) với nhà cung cấp hạ tầng AI, hoặc chạy hoàn toàn trên mô hình cục bộ (Local Model).

### 2.2 Không lưu trữ dữ liệu vĩnh viễn (Zero Data Retention - ZDR)
- Khi gọi qua Private Enterprise API (Azure OpenAI / AWS Bedrock), hợp đồng áp dụng chính sách **Zero Data Retention** (Customer Data is not stored at rest, prompt logging disabled).
- Dữ liệu prompt chỉ tồn tại trong bộ nhớ RAM trong thời gian tính toán của tiến trình (In-flight transient processing).

### 2.3 Nguyên tắc cách ly và chỉ đọc (Read-Only Target & Out-of-tree Output)
- Theo đúng quy tắc an toàn [`assess/lsa/prompts/_shared-rules.md`](../assess/lsa/prompts/_shared-rules.md):
  - Thư mục mã nguồn `TARGET` được gắn cờ **Read-Only** tuyệt đối.
  - Bộ công cụ LSA và các subagent AI **không bao giờ** ghi, sửa đổi hay tạo file tạm bên trong thư mục mã nguồn của khách hàng.
  - Toàn bộ kết quả phân tích, log và báo cáo chỉ được ghi ra thư mục chỉ định riêng biệt (`OUT/`), nằm ngoài cây thư mục dự án.

### 2.4 Không tiếp cận CSDL và dữ liệu người dùng (Zero Database & PII Access)
- Komagu chỉ phân tích cấu trúc mã nguồn tĩnh (Static AST & Source Structure: định nghĩa route, controller, truy vấn SQL, logic kiểm tra quyền).
- **Không yêu cầu và không bao giờ kết nối** tới CSDL Production/Staging của khách hàng.
- Không thu thập, không truyền tải bất kỳ thông tin cá nhân (PII) nào của người dùng cuối.

### 2.5 Tiền lọc và ẩn danh hóa mã nguồn (Secret Redaction & Local Pre-filtering)
- Tier 1 (pre-scan, route mapping, candidate discovery) chạy cục bộ hoàn toàn trên máy trạm của kỹ sư dự án, không gọi AI.
- Ở chế độ **headless** (`komagu scan --headless-ai`), mọi đoạn code gửi tới AI đều đi qua một hàm duy nhất (`operate/ai/context.py` → `_read_snippet`) và được che bí mật trước khi gửi bằng [`assess/lsa/scripts/redaction.py`](../assess/lsa/scripts/redaction.py) (#350):
  - giá trị có khoá dạng `password` / `pass` / `pw` / `passphrase` / `secret` / `credential` / `api_key` / `token` trong code, JSON, PHP và file cấu hình (`.properties`, YAML, `.env`, có hoặc không có dấu nháy, kể cả trong comment JSP);
  - dạng Java legacy: `setPassword("x")`, `DriverManager.getConnection(url, user, "x")`, `PasswordAuthentication`, Spring XML `<property name="password" value="x"/>`, `web.xml` `<param-name>` / `<param-value>` (kể cả khi tách dòng), `keystorePass` của Tomcat;
  - mật khẩu trong connection string (`jdbc:...;password=`, `?pwd=`, `jdbc:oracle:thin:user/pass@`) và URI có thông tin đăng nhập (`mongodb://user:pass@host`);
  - header `Basic` / `Bearer`, token dạng AWS `AKIA…`, GitHub `ghp_…`, `sk-…`, Google `AIza…`;
  - toàn bộ nội dung khối `-----BEGIN ... PRIVATE KEY-----`; dòng dài hơn 4.000 ký tự (minified) bị bỏ hẳn.
- Chỉ gửi các đoạn code quanh route, candidate và finding (cửa sổ khoảng 30–60 dòng), không gửi cả repository. Có test kiểm tra rằng không secret nào cài sẵn đến được model (`operate/tests/test_headless_ai.py`, `test_ai_redaction.py`).
- **Giới hạn (phải nói rõ với khách hàng):** bộ che dựa trên mẫu (pattern), không bảo đảm bắt được mọi dạng bí mật. Ví dụ: hằng số có tên không gợi ý bí mật (`String X = "..."`), passphrase có khoảng trắng, giá trị mã hoá `ENC(...)`. Ở chế độ agent runtime (Claude Code, Codex, Cursor), agent tự mở file nên bộ che này **không áp dụng**. Vì vậy pilot AMS **chỉ chạy ở chế độ headless**, và các file nhạy cảm được loại khỏi bản sao source ngay từ đầu (runbook W9-2).

### 2.6 Cơ chế kiểm soát con người độc lập (Human-in-the-Loop: Person B Protocol)
- AI chỉ đóng vai trò trợ lý đề xuất (Auditor & Remediation Assistant).
- **100% phát hiện an ninh (Security Findings)** và **100% mã nguồn khắc phục (Remediation Patches)** bắt buộc phải được thẩm định, xác nhận và ký duyệt bởi chuyên gia con người (Person B - Harry) thông qua biên bản `review-log.md` trước khi gửi tới khách hàng hoặc tích hợp vào hệ thống.
- Tuyệt đối không tự động triển khai (Auto-deploy) mã do AI sinh ra lên môi trường chạy thực tế.

---

## 3. Model Hosting & Execution Options (モデル稼働環境の選択肢)

Nhằm đáp ứng linh hoạt theo chính sách bảo mật nội bộ của từng khách hàng Nhật Bản, Komagu cung cấp 2 phương án hạ tầng:

| Đặc tính kỹ thuật | **Phương án A: On-Premises / Air-Gapped (Khuyên dùng cho khối tài chính/y tế)** | **Phương án B: Private Enterprise Cloud (Khuyên dùng cho khối thương mại/dịch vụ)** |
|---|---|---|
| **Mô hình AI** | Open-weight model chạy qua endpoint tương thích OpenAI (Ollama / vLLM). Đã đo: `gpt-oss:20b` trên Apple M4 Pro 24 GB (Run 6, v2.5.0 có che secret, [EVAL-RESULTS](../assess/lsa/tests/EVAL-RESULTS.md)): 40–56 phút cho repo eval. Máy chủ GPU của khách hàng có thể chạy model lớn hơn | Model enterprise do khách hàng chấp thuận (ví dụ Claude trên AWS Bedrock Tokyo, GPT trên Azure OpenAI Japan East). **Chưa đo ở chế độ headless**: phải đo trên repo eval trước khi chạy pilot (runbook bước P4) |
| **Hạ tầng máy chủ** | Chạy trên Private GPU Server nội bộ của khách hàng hoặc Máy trạm cô lập (Offshore Dedicated Workstation) không kết nối Internet | Chạy qua Microsoft Azure OpenAI (Japan East/West) hoặc AWS Bedrock (Tokyo Region) |
| **Kết nối mạng** | Hoàn toàn Offline / Air-Gapped (Mạng nội bộ cách ly) | Kết nối bảo mật TLS 1.3 qua Private Endpoint / VPC Peering |
| **Chính sách lưu vết** | Dữ liệu không bao giờ rời khỏi hạ tầng chỉ định | Hợp đồng Enterprise Zero Data Retention (ZDR), không lưu trữ prompt. **Cần kiểm tra điều khoản hiện hành của nhà cung cấp trước khi cam kết**, ví dụ chế độ lưu prompt để giám sát lạm dụng (abuse monitoring) của Azure OpenAI và thủ tục xin miễn |
| **Phù hợp chính sách** | Khách hàng cấm tuyệt đối truyền mã nguồn ra ngoài mạng nội bộ | Khách hàng cho phép dùng Cloud có bảo chứng Enterprise Compliance |
| **Đánh đổi** | Không có rủi ro truyền dữ liệu; model nhỏ cho độ chính xác thấp hơn (Run 6, 2 lần chạy: BOLA 26/29, injection 34/34, BFLA 10/10, mass assignment 14/15, precision 0,79–0,81, 1 báo sai trên code an toàn mỗi lần) | Độ chính xác dự kiến cao hơn; phụ thuộc hợp đồng và vùng dữ liệu |

Cả hai phương án dùng chung một lệnh (`komagu scan --headless-ai <endpoint> --model <model>`), chỉ khác endpoint. Có thể chuẩn bị song song và chốt khi khách hàng chọn.

---

## 4. Formal AI Processing Consent Template (AI利用承諾申請書 — 日英併記)

Dưới đây là mẫu văn bản thỏa thuận chính thức được chuẩn bị theo thể thức văn bản doanh nghiệp Nhật Bản (稟議書・同意書). Kỹ sư trưởng (Harry) sẽ điền các thông tin trong ngoặc vuông `[...]` trước khi trình gửi khách hàng.

***

### ソフトウェア保守・モダナイゼーションにおけるAIコード解析利用に関する承諾申請書
### Request for Approval: Utilization of AI-Assisted Code Analysis in Software Maintenance & Modernization

**申請日 (Date of Application):** 2026年 [MM] 月 [DD] 日  
**申請者 (Applicant):** [Công ty thực hiện dự án AMS / Tên nhóm kỹ thuật]  
**責任者 (Lead Architect / Person B):** Harry Nguyen ([Chức danh / Email liên hệ])  
**提出先 (Submitted to):** [Tên công ty khách hàng / Quý khách hàng]  
**ご担当者様 (Attention):** [Tên người đại diện / Bộ phận CNTT / CISO]  

---

#### 1. 申請の趣旨および目的 (Purpose of Application)
貴社より受託しておりますソフトウェア保守・運用業務（AMS）におきまして、潜在的なセキュリティ脆弱性（オブジェクトレベル認可不備／BOLA、SQLインジェクション等）を迅速に特定し、安全なAPIモダナイゼーションを推進するため、専用のAIコード解析支援ツール「Komagu LSA」のパイロット適用をご承認いただきたく申請いたします。

*We hereby request your approval to conduct a pilot engagement utilizing the "Komagu LSA" AI-assisted code analysis kit for the ongoing Application Maintenance Services (AMS). This initiative aims to rapidly identify latent security vulnerabilities (such as Broken Object Level Authorization/BOLA and SQL Injection) and support secure API modernization.*

#### 2. 対象システムおよび範囲 (Target System & Scope)
- **対象システム名 (System Name):** [Tên hệ thống khách hàng AMS chỉ định]
- **解析対象 (Scope of Analysis):** 静的ソースコード（ルーティング定義、コントローラー、クエリ処理ロジック）。※最大 [30〜150] エンドポイント相当。
- **除外対象 (Exclusions):** 本番環境データベース、実データ、個人情報（PII）、認証シークレット（APIキー、接続文字列等）。

#### 3. セキュリティおよびデータ保護誓約 (Security & Data Governance Commitments)
弊社は、本業務の遂行にあたり、以下の事項を厳格に遵守・誓約いたします。

1. **学習利用の完全禁止 (No Model Training):** 貴社のソースコードおよび解析結果は、AIモデルの再学習・改善・微調整等に一切利用されません。
2. **データの不保持 (Zero Data Retention):** 解析プロセスの完了後、外部サーバー上に貴社のソースコードが永続的に保管されることは一切ありません。
3. **機密情報の事前マスキング (Automatic Secret Redaction):** AIへ送信するのは、ローカル環境で抽出した解析対象のコード断片のみです。AIがリポジトリ全体に直接アクセスすることはありません。送信前に、パスワード、APIキー、接続文字列内の認証情報、秘密鍵は自動的にマスキングされます。
   *Only code excerpts selected locally are sent to the AI; the AI never accesses the repository directly. Passwords, API keys, credentials in connection strings and private keys are masked automatically before sending.*
4. **本番環境・実データ非接続 (No DB/PII Access):** 静的コードのみを対象とし、本番データベースへの接続や実顧客データの取得は行いません。
5. **人間による100%監査および責任 (Human-in-the-Loop Governance):** AIによる出力結果は確定情報として扱わず、弊社のセキュリティ責任者（Person B: Harry）が全件を精査・署名した上でご報告いたします。勝手な自動修正・本番適用は行いません。
6. **作業データの削除 (Deletion at Pilot Close):** パイロット終了時、解析結果を貴社へ納品した後、弊社作業環境上のソースコード複製および解析データを削除し、削除報告書を提出いたします。
   *At pilot close, after the results are delivered, we delete the source copy and analysis data from our working environment and submit a deletion report.*

#### 4. AI稼働環境の選択 (Selection of Execution Environment)
貴社のセキュリティポリシーに基づき、以下の稼働環境のいずれかを選択して適用いたします（ご希望の方式にチェックをお願い申し上げます）：

- [ ] **方式A (推奨・完全閉域): オンプレミス / 専用GPU環境 (Local / Air-Gapped Mode)**  
  *(貴社指定の専用環境または完全閉域ローカルGPU環境上で「gpt-oss」等のオープンウェイトモデルを稼働させます。外部通信は一切発生しません。)*
- [ ] **方式B (高精度クラウド): エンタープライズ専用クラウドAPI (Private Enterprise API Mode)**  
  *(日本国内リージョン[東日本/西日本]のAzure OpenAIまたはAWS Bedrockを利用し、エンタープライズゼロデータ保持[ZDR]契約のもとで通信を暗号化して実行します。)*

#### 5. 承諾・署名欄 (Approval & Sign-off Section)

上記の内容およびセキュリティ誓約事項を確認の上、対象システムにおけるAIコード解析の実施を承諾します。

**貴社名 (Client Company Name):** ________________________________________________  
**ご所属・役職 (Department / Title):** ________________________________________________  
**ご芳名・ご署名 (Authorized Signer Name / Signature or Hanko):** ________________________________________________  
**承諾日 (Approval Date):** 2026年 ______ 月 ______ 日  

***

---

## 5. Fallback System & Procedure (代替方針・フォールバック計画)

Nhằm đảm bảo tiến độ bàn giao của [Delivery Plan §Pilot](boilerplate-1-delivery-plan.md) không bị đình trệ nếu quy trình phê duyệt của khách hàng gặp vướng mắc, quy trình dự phòng được kích hoạt theo các quy tắc sau:

```
[Tuần 1: Khởi động] --> Gửi Thỏa thuận xin phê duyệt cho khách hàng AMS
                              |
                     [Cuối Tuần 6 (Deadline)]
                              |
        +---------------------+---------------------+
        |                                           |
 [Khách hàng ký duyệt]                      [Chưa có văn bản phê duyệt]
        |                                           |
 [Kế hoạch chính thức]                      [KÍCH HOẠT FALLBACK]
 Chạy Pilot trên hệ thống AMS              Chạy Pilot trên Hệ thống Nội bộ:
 Đo lường số liệu thực tế                   Demo Member Portal (D6) + Internal Tool
 Báo cáo case study khách hàng              Báo cáo số liệu với nhãn "Internal Only"
```

### 5.1 Thời hạn phê duyệt chốt (Approval Deadline)
- **Hạn chót:** **Cuối Tuần 6 (End of Week 6)** theo mốc kế hoạch M3.
- Nếu đến hết ngày làm việc cuối cùng của Tuần 6, khách hàng chưa cung cấp văn bản phê duyệt có chữ ký/dấu mộc (Written Approval), Trưởng dự án (Harry) sẽ ra quyết định chuyển đổi ngay sang Hệ thống Thay thế mà không chờ đợi thêm.

### 5.2 Đặc tả hệ thống thay thế (Fallback System Specification)
1. **Ứng dụng Member Portal (Deliverable D6)**:
   - Kiến trúc: ASP.NET Core (.NET 8) và Spring Boot 3 (Kotlin) có backend cơ sở dữ liệu PostgreSQL.
   - Quy mô: Đầy đủ các phân hệ quản lý người dùng, hồ sơ, giao dịch với tổng cộng **24 endpoints** (12 endpoints trên ASP.NET Core và 12 endpoints trên Spring Boot Kotlin).
   - Chứa đầy đủ các kịch bản BOLA/IDOR đa người dùng và lỗi truy vấn SQL truyền thống của các hệ thống legacy.
2. **Quy định công bố số liệu (Reporting Disclosure):**
   - Mọi số liệu đo lường về thời gian rà soát, tỷ lệ phát hiện (recall/precision) và person-days tiết kiệm được sẽ ghi rõ trong báo cáo tuần 12 là **"Số liệu kiểm chuẩn nội bộ" (Internal System Reference Metrics)** thay vì số liệu môi trường khách hàng bên ngoài.

---

## 6. Security Q&A for the Client (想定質問と回答 — 日英併記)

Bộ câu hỏi bộ phận An toàn Thông tin phía khách hàng thường hỏi. Gửi kèm Đơn xin phê duyệt ở bước 2 của checklist. Mỗi câu trả lời phải khớp với code hiện tại. Khi thay đổi code, cập nhật lại phần này.

**Q1. ソースコードはどこに送られますか？ / Where does our code go?**
解析用のソースコード複製は、弊社の専用作業端末（方式A）または貴社承認済みのクラウド環境（方式B）にのみ置かれます。方式Aでは外部への通信は発生しません。方式Bでは、ローカルで抽出したコード断片のみが日本リージョンのAPIに送信されます。
*The source copy stays on our dedicated workstation (A) or in a cloud environment you approve (B). With A nothing leaves the machine; with B only locally selected excerpts go to a Japan-region API.*

**Q2. AIに何が送信されますか？ / What exactly is sent to the AI?**
ルート定義、コントローラー、クエリ処理の周辺コード（1件あたり約30〜60行）、および解析ルール（プロンプト）です。送信前に認証情報はマスキングされます（§2.5）。データベース、実データ、ログ、個人情報は送信しません。
*Code around routes, controllers and query logic (about 30–60 lines per item) plus the audit rules. Credentials are masked first (§2.5). No database content, real data, logs or personal data.*

**Q3. マスキングで全ての機密情報を除去できますか？ / Does redaction catch every secret?**
いいえ。パターンに基づくため、全形式の保証はできません。そのため、解析用のソース複製を作成する段階で、環境別設定ファイル・鍵ファイル・証明書・テストデータを除外することを事前に貴社と合意し、除外後のファイル一覧をご確認いただきます。方式Aでは、マスキング漏れがあっても外部へ送信されません。
*No. It is pattern-based, so we cannot guarantee every format. We therefore agree with you up front to leave environment config, key, certificate and test-data files out of the source copy, and you can check the file list of the copy. With option A, a missed secret still never leaves the machine.*

**Q4. AIがソースコードを変更することはありますか？ / Can the AI change our code?**
ありません。解析対象ディレクトリは読み取り専用で、出力は別ディレクトリにのみ書き込まれます。修正案は提案として納品し、適用は貴社の通常の変更管理手続きに従います。
*No. The target directory is read-only and output goes to a separate directory. Fixes are delivered as proposals and applied through your normal change process.*

**Q5. AIの判定はそのまま報告されますか？ / Are AI findings reported as-is?**
いいえ。AIの指摘は別のAI検証役が反証を試みた上で、弊社のセキュリティ責任者が全件を確認・署名します（`review-log.md`）。署名のない指摘は報告しません。
*No. A separate verifier agent tries to refute each finding, then our security lead reviews and signs every one (`review-log.md`). Unsigned findings are not reported.*

**Q6. 解析データはいつ削除されますか？ / When is the data deleted?**
パイロット終了時（第12週）、成果物納品後に作業端末上のソース複製・中間データ・ログを削除し、削除報告書を提出します（申請書 §3-6）。
*At pilot close (week 12), after delivery, we delete the source copy, intermediate data and logs, and submit a deletion report (letter §3-6).*

**Q7. 本番環境への影響はありますか？ / Any impact on production?**
ありません。静的解析のみで、本番・ステージング環境への接続や負荷試験は行いません。認可テスト（クロスユーザーテスト）を実施する場合は、貴社が用意するテスト環境とテスト用アカウントのみを使用し、別途ご承認をいただきます。
*None. Static analysis only; no connection to or load on production or staging. Any cross-user authorization test uses only a test environment and test accounts you provide, with separate approval.*

---

## 7. Action Checklist for Project Lead (Harry)

| STT | Nhiệm vụ | Thời hạn | Người thực hiện | Trạng thái |
|:---:|---|:---:|:---:|:---:|
| 1 | Hoàn thiện thông tin hệ thống AMS cụ thể vào Mục 4 của Đơn xin phê duyệt | Tuần 2 | Harry | [ ] Chờ điền |
| 2 | Họp giải trình sơ bộ và gửi bản thảo Đơn xin phê duyệt (kèm Security Q&A ở §6) cho Quản lý dự án phía khách hàng | Tuần 3 | Harry / BrSE | [ ] Chờ gửi |
| 3 | Trả lời giải trình bổ sung về bảo mật (nếu bộ phận Security khách hàng yêu cầu) | Tuần 4–5 | Harry | [ ] Dự phòng |
| 4 | Thu thập văn bản phê duyệt chính thức đã ký kết và lưu trữ vào thư mục bảo mật | Cuối Tuần 6 | Harry | [ ] Milestone M3 |
| 5 | *Nếu chưa có phê duyệt:* Ra quyết định kích hoạt chính thức Fallback System | Cuối Tuần 6 | Harry (BOD) | [ ] Dự phòng |

---

## 8. Version History

| Phiên bản | Ngày | Tác giả | Tóm tắt thay đổi |
|---|---|---|---|
| **1.0** | 2026-10-18 | Harry & Komagu Lead Agent | Khởi tạo tài liệu quy chế quản trị dữ liệu AI, cam kết bảo mật và mẫu đơn xin phê duyệt song ngữ Nhật - Anh phục vụ Issue #5. |
| **1.1** | 2026-11-03 | Harry & Claude | #350: §2.5 mô tả đúng phạm vi che bí mật và giới hạn (chỉ chế độ headless); bảng hạ tầng dùng model đã đo; thêm cam kết xóa dữ liệu (§3-6 của đơn); thêm Security Q&A (§6); ghi stack Java của hệ thống AMS. |
