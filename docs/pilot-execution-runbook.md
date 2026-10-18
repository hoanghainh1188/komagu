# Pilot Execution Runbook: 4-Week Operational Playbook (Weeks 9–12)
## パイロット運用実施手順書

**Version:** 1.0  
**Effective Date:** 2026-10-18  
**Project Lead & Sign-off Authority:** Harry (Principal Architect / PM / Person B)  
**Parent Delivery Plan:** [Boilerplate 1 Delivery Plan (§Pilot)](boilerplate-1-delivery-plan.md)  
**Related Documents:** [ADR-0005: Effort Baseline](adr/0005-effort-baseline-and-roi-measurement.md), [AI Data Governance Protocol](pilot-client-ai-approval-consent.md)  
**Related Issue:** [hoanghainh1188/komainu#75](https://github.com/hoanghainh1188/komainu/issues/75)

---

## 1. Overview & 4-Week Flight Path (概要と全体スケジュール)

Sổ tay này định nghĩa toàn bộ quy trình vận hành thực tế cho **Giai đoạn Thử nghiệm Pilot (Tuần 9–12)** của dự án Komainu trên hệ thống đang bảo trì (**AMS** hoặc **Hệ thống Thay thế Nội bộ D6**).

```
+-------------------------------------------------------------------------------------------------+
|                                 KOMAINU PILOT 4-WEEK TIMELINE                                    |
+-------------------------------------------------------------------------------------------------+
|  [Tuần 9]      -> KICKOFF & GOVERNANCE: Kiểm tra phê duyệt AI / Quyết định Fallback            |
|                   Hạ tầng AI (Local GPU/Cloud ZDR), Thiết lập Timesheet 4 tags (ADR-0005)       |
|                                                                                                 |
|  [Tuần 9-10]   -> ASSESS & SIGN-OFF: Chạy LSA (100% endpoints), Harry thẩm định Person B        |
|                   Ký review-log.md, Xuất báo cáo HTML/SARIF cho khách hàng                      |
|                                                                                                 |
|  [Tuần 10]     -> PROTECT EDGE: Dựng Kong Gateway + Coraza WAF sidecar (CRS v4)                 |
|                   Phòng thủ ngay lập tức (Rate Limit + SQLi block) trước khi sửa code           |
|                                                                                                 |
|  [Tuần 10-12]  -> REMEDIATE & CI: Áp dụng thư viện phân quyền D1/D2, refactor Safe Query D3     |
|                   Thiết lập pipeline kiểm thử tự động D5 Schemathesis chặn BOLA                 |
|                                                                                                 |
|  [Tuần 12]     -> RE-TEST & ROI MEASURE: Quét lại 100% sạch lỗi, đối chiếu Baseline ADR-0005   |
|                   Đo lường % Person-days tiết kiệm, Họp BOD duyệt Go/No-go Stage 2              |
+-------------------------------------------------------------------------------------------------+
```

---

## 2. Phase 1: Tuần 9 — Khởi động, Pháp trị & Thiết lập Hạ tầng

### Bước 1.1: Kiểm tra Văn bản Phê duyệt Xử lý AI (Consent Verification)
- **Người thực hiện:** Harry (Lead Oversight).
- **Hành động kiểm tra:**
  1. Kiểm tra văn bản [AI Processing Approval Consent Form](pilot-client-ai-approval-consent.md) gửi khách hàng AMS.
  2. **Quy tắc cổng chặn Tuần 6 (Week 6 Hard Gate):**
     - **Nếu ĐÃ CÓ văn bản ký kết (Approved):** Chạy Pilot chính thức trên mã nguồn hệ thống AMS.
     - **Nếu CHƯA CÓ văn bản ký kết trước hạn chót Tuần 6:** Kích hoạt ngay lập tức **Fallback System** (Ứng dụng Member Portal D6 24 endpoints). Gắn nhãn kết quả đo lường là *"Internal System Reference Metrics"*.
  3. Cập nhật trạng thái `fallbackActive` trong file cấu hình `delivery/pilot/pilot-config.json` (dựa trên mẫu `delivery/pilot/pilot-config.sample.json`).

### Bước 1.2: Thiết lập Hạ tầng Tính toán AI (Model Hosting Setup)
- **Phương án A (On-Premises / Air-Gapped):**
  - Khởi động cụm suy luận `Qwen 2.5 Coder 32B Instruct` trên máy chủ GPU nội bộ / máy trạm cô lập:
    ```bash
    # Khởi động vLLM hoặc Ollama cục bộ
    ollama run qwen2.5-coder:32b
    # Kiểm tra endpoint
    curl http://127.0.0.1:8000/v1/models
    ```
- **Phương án B (Private Enterprise Cloud):**
  - Cấu hình Azure OpenAI Service (Japan East/West) với hợp đồng Enterprise Zero Data Retention (ZDR).
  - Khai báo API Key và Endpoint vào biến môi trường:
    ```bash
    export AZURE_OPENAI_ENDPOINT="https://komainu-pilot.openai.azure.com/"
    export AZURE_OPENAI_API_KEY="<secure-secret>"
    ```

### Bước 1.3: Cách ly Kho Mã nguồn Mục tiêu (Read-Only Target Enforcement)
- Thư mục mã nguồn `TARGET` phải được gắn quyền **Chỉ đọc (Read-Only)** để đảm bảo an toàn tuyệt đối:
  ```bash
  chmod -R 555 /path/to/target-repo
  ```
- Khởi tạo thư mục xuất kết quả riêng biệt ngoài cây thư mục dự án (`OUT/`):
  ```bash
  mkdir -p ./pilot-out
  ```

### Bước 1.4: Khởi tạo Bảng Chấm công Timesheet Tracking
- Sao chép biểu mẫu chấm công từ [`delivery/pilot/timesheet-template.csv`](../delivery/pilot/timesheet-template.csv) sang `delivery/pilot/timesheet-pilot.csv`.
- Phổ biến cho toàn bộ kỹ sư dự án quy chuẩn chấm công bắt buộc sử dụng 4 tag chuẩn theo [ADR-0005](adr/0005-effort-baseline-and-roi-measurement.md):
  - `[PILOT-LSA]`: Công sức cấu hình, quét tĩnh, kiểm chứng và thẩm định Person B.
  - `[PILOT-GATEWAY]`: Công sức dựng Kong Gateway, cấu hình Coraza WAF và test abuse.
  - `[PILOT-REMEDIATE]`: Công sức tích hợp thư viện D1/D2 và sửa đổi query SQL D3.
  - `[PILOT-TEST-CI]`: Công sức viết pipeline Schemathesis và chạy cross-user tests.

---

## 3. Phase 2: Tuần 9–10 — Rà soát An ninh & Thẩm định Person B

### Bước 2.1: Chạy Rà soát Cú pháp Tĩnh & Sinh Báo cáo Ban đầu (Scan)
Sử dụng gói `komainu-guard` đã phát hành để quét tự động toàn bộ mã nguồn mục tiêu:
```bash
# Thực hiện quét tĩnh, trích xuất route candidates và sinh báo cáo song ngữ
npx --yes komainu-guard scan /path/to/target-repo --out ./pilot-out --lang all --format all
```
- **Kiểm tra đầu ra trong `./pilot-out`:**
  - `stack-profile.json`: Xác nhận đúng ngôn ngữ/framework (PHP, Java, .NET...).
  - `routes.candidates.json`: Đạt độ phủ 100% các endpoint của hệ thống (từ 30 đến 150 endpoints).
  - `injection.candidates.json`: Các điểm nghi vấn SQL/query interpolation.
  - Tự động lọc sạch các chuỗi bí mật (Secret Redaction).
  - `report.html` & `report.md`: Báo cáo sơ bộ trực quan.

### Bước 2.2: Chạy Kiểm toán Sâu bằng Multi-Agent (Deep Audit Workflow)
Sử dụng các prompt template LSA runtime neutral (`assess/lsa/prompts/`) đưa vào agent context với dữ liệu đầu vào là thư mục `./pilot-out`:
1. **Phase 2 & 3:** Chạy `10-stack-detector` và `20-route-mapper` để hoàn thiện `auth-model.md` và `route-inventory.json`.
2. **Phase 4:** Chạy `30-bola-auditor` và `40-injection-auditor` để tìm kiếm BOLA/IDOR và SQLi trên từng batch endpoints.
3. **Phase 5:** Chạy `50-finding-verifier` (Skeptic Verifier) phản biện và loại trừ triệt để False Positives để hoàn thiện `findings.json`.

### Bước 2.3: Thẩm định Con người Độc lập (Person B Protocol)
- **Người thực hiện:** Harry (Security Reviewer / Person B).
- **Hành động:**
  1. Mở file `./pilot-out/findings.json` và đối chiếu từng dòng mã nguồn mục tiêu.
  2. Xác nhận hoặc bác bỏ từng phát hiện vào biên bản thẩm định `./pilot-out/review-log.md`.
  3. **Tiêu chuẩn nghiệm thu:** Tỷ lệ chấp thuận đạt $\ge 70\%$ tổng số phát hiện của AI.
  4. Harry ký tên và ghi ngày tháng vào cuối file `review-log.md`.

### Bước 2.4: Xuất Bản Báo cáo Hoàn chỉnh
Chạy cập nhật lại báo cáo sau thẩm định Person B:
```bash
python3 assess/lsa/scripts/render_report.py ./pilot-out --lang all
```
- Cung cấp trọn bộ báo cáo cho khách hàng / BOD:
  - Báo cáo Markdown tóm tắt điều hành (`report.md`, `report.ja.md`).
  - File SARIF (`findings.sarif`) để import vào GitHub Security Tab / SonarQube.
  - Báo cáo HTML tương tác standalone (`report.html`) để xem trực tiếp trên trình duyệt.

---

## 4. Phase 3: Tuần 10 — Phòng thủ Bề mặt bằng Edge Gateway & WAF

Trước khi chỉnh sửa bất kỳ dòng mã nguồn nào, triển khai ngay cổng Kong Gateway và OWASP Coraza WAF (theo Deliverable D4 & [ADR-0003](adr/0003-waf-engine-coraza.md)) phía trước hệ thống mục tiêu:

```bash
cd operate/gateway
docker compose up -d
deck gateway sync --konnect-token <token> deck.yaml
```

- **Quy tắc bảo vệ kích hoạt:**
  1. **Rate Limiting:** Giới hạn 100 requests/phút theo IP và 500 requests/phút theo User Token nhằm ngăn chặn tấn công vét cạn (credential stuffing) và quét BOLA diện rộng.
  2. **OWASP Coraza WAF (CRS v4):** Kích hoạt bộ luật chặn đứng các mẫu chuỗi SQL Injection và Path Traversal.
- **Kiểm thử nghiệm thu:** Chạy kịch bản tấn công giả lập để xác nhận Kong & WAF trả về `429 Too Many Requests` hoặc `403 Forbidden`.

---

## 5. Phase 4: Tuần 10–12 — Khắc phục Lỗ hổng & Tự động hóa CI

### Bước 5.1: Tích hợp Thư viện Phân quyền D1 & Định danh D2
- Với các endpoint thuộc ngăn xếp .NET 8:
  - Nhúng gói NuGet `Komainu.Authorization`.
  - Khai báo middleware kiểm tra quyền sở hữu đối tượng:
    ```csharp
    [AuthorizeOwner(ResourceParam = "orderId", OwnerClaim = "sub")]
    public async Task<IActionResult> GetOrder(string orderId) { ... }
    ```
- Với các endpoint thuộc ngăn xếp Kotlin / Spring Boot 3:
  - Nhúng dependency `komainu-spring-boot-starter`.
  - Sử dụng annotation `@PreAuthorize("@ownerCheck.isOwner(#orderId, authentication)")`.

### Bước 5.2: Khắc phục Truy vấn SQL An toàn (D3)
- Thay thế toàn bộ chuỗi nối SQL thô bằng truy vấn có tham số (Parameterized Queries).
- Áp dụng bộ phân tích tĩnh Roslyn analyzer (C#) và detekt rule (Kotlin) để ngăn chặn việc commit mã nguồn nối chuỗi SQL mới.

### Bước 5.3: Triển khai Pipeline Kiểm thử Tự động D5
- Cấu hình workflow GitHub Actions (`.github/workflows/authz-cross-user.yml`) sử dụng công cụ Schemathesis.
- **Kiểm chứng tính nghiêm ngặt (Plant-and-verify):**
  - Cố ý tạo một lỗ hổng BOLA giả lập -> Pipeline phải chuyển sang màu ĐỎ (`FAILURE`).
  - Gỡ bỏ lỗ hổng -> Pipeline chuyển sang màu XANH (`SUCCESS`).

---

## 6. Phase 5: Tuần 12 — Kiểm thử Lại, Đo lường ROI & Nghiệm thu

### Bước 6.1: Quét Kiểm chứng Tái phát (Re-test Verification)
- Chạy lại toàn bộ LSA pipeline trên mã nguồn đã sửa.
- **Tiêu chuẩn đạt:** 100% các lỗ hổng BOLA và SQLi đã chấp thuận trước đó đều được khắc phục triệt để (Zero accepted open findings).

### Bước 6.2: Tổng kết Timesheet & Tính toán Tỷ lệ Tiết kiệm Công sức (ROI)
- Tổng hợp toàn bộ số giờ làm việc thực tế từ `delivery/pilot/timesheet-pilot.csv`:
  $$\text{Tổng Person-Days Thực tế} = \sum (\text{HoursSpent}) / 8$$
- Đối chiếu với **Baseline 46.0 person-days** theo chuẩn [ADR-0005](adr/0005-effort-baseline-and-roi-measurement.md):
  $$\text{Tỷ lệ Tiết kiệm Công sức (\%)} = \frac{46.0 - \text{Person-Days Thực tế}}{46.0} \times 100\%$$
- **Ngưỡng nghiệm thu thành công:** Tỷ lệ tiết kiệm đạt **$\ge 50\%$** (Mục tiêu kỳ vọng: **$65\% - 75\%$**).

### Bước 6.3: Báo cáo Tổng kết & Họp Ban Lãnh đạo (BOD Gate Review)
- Lập tài liệu báo cáo tổng kết Pilot: `docs/pilot-final-report.md`.
- Trình bày kết quả trước BOD:
  1. Số lượng endpoints và lỗ hổng đã được khắc phục 100%.
  2. Bằng chứng kiểm thử tự động ngăn ngừa BOLA trong CI.
  3. Tỷ lệ tiết kiệm chi phí và công sức thực tế có số liệu chứng minh.
  4. Tình trạng chấp thuận trích dẫn làm Case Study (Client Reference) của khách hàng.
  5. Đề xuất quyết định **Go / No-go** để cấp ngân sách cho **Stage 2 (Boilerplate 5: DevSecOps & SBOM)** và **Stage 3 (Boilerplate 2: eKYC / 犯収法)**.
