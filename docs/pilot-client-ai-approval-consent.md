# Pilot: Client AI Processing Approval & Data Governance Protocol (AMS Project)
## パイロット案件におけるAIコード解析利用許諾およびデータガバナンス規程

**Version:** 1.0  
**Effective Date:** 2026-10-18  
**Project Lead & Sign-off Authority:** Harry (Principal Architect / PM / Person B)  
**Classification:** Confidential — Internal & Client Governance (`docs/`)  
**Related Issue:** [hoanghainh1188/komainu#5](https://github.com/hoanghainh1188/komainu/issues/5)  
**Parent Plan:** [Boilerplate 1 — Secure API & IAM Delivery Plan (Pilot Section)](boilerplate-1-delivery-plan.md)

---

## 1. Executive Summary & Purpose (概要と目的)

### 1.1 Purpose (目的)
Nhằm chuẩn bị cho giai đoạn **Thử nghiệm thực tế (Pilot: Tuần 9–12)** của dự án Komainu trên hệ thống đang bảo trì (**AMS - Application Maintenance Service**), tài liệu này thiết lập:
1. **Khung quản trị dữ liệu và an toàn thông tin (Data Governance & Security Protocol)** khi áp dụng công nghệ Trí tuệ Nhân tạo (AI/LLM) để rà soát mã nguồn tự động (LSA - Legacy Security Assessment) và hỗ trợ hiện đại hóa API bảo mật.
2. **Mẫu văn bản xin phê duyệt chính thức (Formal AI Processing Consent Letter / 稟議・利用許諾申請書)** song ngữ Nhật - Anh chuẩn mực, sẵn sàng trình ký Ban lãnh đạo và Bộ phận An toàn Thông tin của khách hàng AMS.
3. **Kế hoạch dự phòng (Fallback Plan)** trong trường hợp khách hàng chưa kịp hoàn tất thủ tục phê duyệt trước hạn chót Tuần 6 (Week 6 deadline).

### 1.2 Target System Criteria (Tiêu chí hệ thống áp dụng)
Theo kế hoạch tại [Delivery Plan §Pilot](boilerplate-1-delivery-plan.md#pilot-assess-then-fix-with-the-boilerplate):
- Hệ thống thuộc phạm vi hợp đồng bảo trì AMS hiện hữu.
- Quy mô kiến trúc: Web API xử lý dữ liệu định danh người dùng (per-user/multi-tenant data) với quy mô từ **30 đến 150 endpoints**.
- Ngăn xếp công nghệ ưu tiên: Các ngôn ngữ legacy được bộ công cụ Komainu LSA hỗ trợ đầy đủ (PHP, Java/Spring, ASP.NET Core/.NET Framework).

---

## 2. Core Security & Data Governance Guarantees (セキュリティおよびデータガバナンス誓約)

Doanh nghiệp Nhật Bản đặc biệt coi trọng an toàn thông tin, bảo vệ tài sản sở hữu trí tuệ (IP) và tuân thủ Đạo luật bảo vệ thông tin cá nhân (APPI - 個人情報保護法) cũng như Tiêu chuẩn Quản lý An toàn Thông tin (JIS Q 27001 / ISO/IEC 27001). Komainu đưa ra 6 cam kết kỹ thuật bất biến sau:

```
+---------------------------------------------------------------------------------------+
|                       KOMAINU AI DATA GOVERNANCE FRAMEWORK                             |
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
- Komainu chỉ phân tích cấu trúc mã nguồn tĩnh (Static AST & Source Structure: định nghĩa route, controller, truy vấn SQL, logic kiểm tra quyền).
- **Không yêu cầu và không bao giờ kết nối** tới CSDL Production/Staging của khách hàng.
- Không thu thập, không truyền tải bất kỳ thông tin cá nhân (PII) nào của người dùng cuối.

### 2.5 Tiền lọc và ẩn danh hóa mã nguồn (Secret Redaction & Local Pre-filtering)
- Giai đoạn 1 (Phase 1) và Giai đoạn 3 (Route Mapping) chạy bộ quét AST regex cục bộ hoàn toàn trên máy trạm của kỹ sư dự án:
  - Tự động nhận diện và ẩn danh chuỗi bí mật (API keys, connection strings, private certificates, JWT secrets) trước khi đóng gói context gửi tới AI.
  - Chỉ gửi các đoạn code logic định tuyến và controller liên quan trực tiếp đến bề mặt tấn công BOLA hoặc Injection.

### 2.6 Cơ chế kiểm soát con người độc lập (Human-in-the-Loop: Person B Protocol)
- AI chỉ đóng vai trò trợ lý đề xuất (Auditor & Remediation Assistant).
- **100% phát hiện an ninh (Security Findings)** và **100% mã nguồn khắc phục (Remediation Patches)** bắt buộc phải được thẩm định, xác nhận và ký duyệt bởi chuyên gia con người (Person B - Harry) thông qua biên bản `review-log.md` trước khi gửi tới khách hàng hoặc tích hợp vào hệ thống.
- Tuyệt đối không tự động triển khai (Auto-deploy) mã do AI sinh ra lên môi trường chạy thực tế.

---

## 3. Model Hosting & Execution Options (モデル稼働環境の選択肢)

Nhằm đáp ứng linh hoạt theo chính sách bảo mật nội bộ của từng khách hàng Nhật Bản, Komainu cung cấp 2 phương án hạ tầng:

| Đặc tính kỹ thuật | **Phương án A: On-Premises / Air-Gapped (Khuyên dùng cho khối tài chính/y tế)** | **Phương án B: Private Enterprise Cloud (Khuyên dùng cho khối thương mại/dịch vụ)** |
|---|---|---|
| **Mô hình AI** | `Qwen 2.5 Coder 32B/7B Instruct` (Local Open Weights) | `Claude 3.5 Sonnet` / `GPT-4o` qua Private Enterprise API |
| **Hạ tầng máy chủ** | Chạy trên Private GPU Server nội bộ của khách hàng hoặc Máy trạm cô lập (Offshore Dedicated Workstation) không kết nối Internet | Chạy qua Microsoft Azure OpenAI (Japan East/West) hoặc AWS Bedrock (Tokyo Region) |
| **Kết nối mạng** | Hoàn toàn Offline / Air-Gapped (Mạng nội bộ cách ly) | Kết nối bảo mật TLS 1.3 qua Private Endpoint / VPC Peering |
| **Chính sách lưu vết** | Dữ liệu không bao giờ rời khỏi hạ tầng chỉ định | Hợp đồng Enterprise Zero Data Retention (ZDR), không lưu trữ prompt |
| **Phù hợp chính sách** | Khách hàng cấm tuyệt đối truyền mã nguồn ra ngoài mạng nội bộ | Khách hàng cho phép dùng Cloud có bảo chứng Enterprise Compliance |

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
貴社より受託しておりますソフトウェア保守・運用業務（AMS）におきまして、潜在的なセキュリティ脆弱性（オブジェクトレベル認可不備／BOLA、SQLインジェクション等）を迅速に特定し、安全なAPIモダナイゼーションを推進するため、専用のAIコード解析支援ツール「Komainu LSA」のパイロット適用をご承認いただきたく申請いたします。

*We hereby request your approval to conduct a pilot engagement utilizing the "Komainu LSA" AI-assisted code analysis kit for the ongoing Application Maintenance Services (AMS). This initiative aims to rapidly identify latent security vulnerabilities (such as Broken Object Level Authorization/BOLA and SQL Injection) and support secure API modernization.*

#### 2. 対象システムおよび範囲 (Target System & Scope)
- **対象システム名 (System Name):** [Tên hệ thống khách hàng AMS chỉ định]
- **解析対象 (Scope of Analysis):** 静的ソースコード（ルーティング定義、コントローラー、クエリ処理ロジック）。※最大 [30〜150] エンドポイント相当。
- **除外対象 (Exclusions):** 本番環境データベース、実データ、個人情報（PII）、認証シークレット（APIキー、接続文字列等）。

#### 3. セキュリティおよびデータ保護誓約 (Security & Data Governance Commitments)
弊社は、本業務の遂行にあたり、以下の事項を厳格に遵守・誓約いたします。

1. **学習利用の完全禁止 (No Model Training):** 貴社のソースコードおよび解析結果は、AIモデルの再学習・改善・微調整等に一切利用されません。
2. **データの不保持 (Zero Data Retention):** 解析プロセスの完了後、外部サーバー上に貴社のソースコードが永続的に保管されることは一切ありません。
3. **機密情報の事前マスキング (Automatic Secret Redaction):** コード解析に先立ち、ローカル環境においてAPIキーやパスワード等の認証情報は自動的に検知・除外されます。
4. **本番環境・実データ非接続 (No DB/PII Access):** 静的コードのみを対象とし、本番データベースへの接続や実顧客データの取得は行いません。
5. **人間による100%監査および責任 (Human-in-the-Loop Governance):** AIによる出力結果は確定情報として扱わず、弊社のセキュリティ責任者（Person B: Harry）が全件を精査・署名した上でご報告いたします。勝手な自動修正・本番適用は行いません。

#### 4. AI稼働環境の選択 (Selection of Execution Environment)
貴社のセキュリティポリシーに基づき、以下の稼働環境のいずれかを選択して適用いたします（ご希望の方式にチェックをお願い申し上げます）：

- [ ] **方式A (推奨・完全閉域): オンプレミス / 専用GPU環境 (Local / Air-Gapped Mode)**  
  *(貴社指定の専用環境または完全閉域ローカルGPU環境上で「Qwen 2.5 Coder」等のオープンウェイトモデルを稼働させます。外部通信は一切発生しません。)*
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
1. **Ứng dụng Member Portal (Deliverable D6)** kết hợp cùng **Công cụ Quản lý Nội bộ (Internal Web API)**:
   - Kiến trúc: ASP.NET Core (.NET 8) và Spring Boot 3 (Kotlin) có backend cơ sở dữ liệu PostgreSQL.
   - Quy mô: Đầy đủ các phân hệ quản lý người dùng, hồ sơ, giao dịch với tổng cộng **42 endpoints**.
   - Chứa đầy đủ các kịch bản BOLA/IDOR đa người dùng và lỗi truy vấn SQL truyền thống của các hệ thống legacy.
2. **Quy định công bố số liệu (Reporting Disclosure):**
   - Mọi số liệu đo lường về thời gian rà soát, tỷ lệ phát hiện (recall/precision) và person-days tiết kiệm được sẽ ghi rõ trong báo cáo tuần 12 là **"Số liệu kiểm chuẩn nội bộ" (Internal System Reference Metrics)** thay vì số liệu môi trường khách hàng bên ngoài.

---

## 6. Action Checklist for Project Lead (Harry)

| STT | Nhiệm vụ | Thời hạn | Người thực hiện | Trạng thái |
|:---:|---|:---:|:---:|:---:|
| 1 | Hoàn thiện thông tin hệ thống AMS cụ thể vào Mục 4 của Đơn xin phê duyệt | Tuần 2 | Harry | [ ] Chờ điền |
| 2 | Họp giải trình sơ bộ và gửi bản thảo Đơn xin phê duyệt cho Quản lý dự án phía khách hàng | Tuần 3 | Harry / BrSE | [ ] Chờ gửi |
| 3 | Trả lời giải trình bổ sung về bảo mật (nếu bộ phận Security khách hàng yêu cầu) | Tuần 4–5 | Harry | [ ] Dự phòng |
| 4 | Thu thập văn bản phê duyệt chính thức đã ký kết và lưu trữ vào thư mục bảo mật | Cuối Tuần 6 | Harry | [ ] Milestone M3 |
| 5 | *Nếu chưa có phê duyệt:* Ra quyết định kích hoạt chính thức Fallback System | Cuối Tuần 6 | Harry (BOD) | [ ] Dự phòng |

---

## 7. Version History

| Phiên bản | Ngày | Tác giả | Tóm tắt thay đổi |
|---|---|---|---|
| **1.0** | 2026-10-18 | Harry & Komainu Lead Agent | Khởi tạo tài liệu quy chế quản trị dữ liệu AI, cam kết bảo mật và mẫu đơn xin phê duyệt song ngữ Nhật - Anh phục vụ Issue #5. |
