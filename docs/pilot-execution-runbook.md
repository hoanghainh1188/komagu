# Pilot Execution Runbook: AMS Pilot on a Java Legacy System (Weeks 1–12)
## パイロット運用実施手順書（AMS・Java レガシー）

**Version:** 2.1  
**Effective Date:** 2026-11-03  
**Project Lead & Sign-off Authority:** Harry (Principal Architect / PM / Person B)  
**Parent Delivery Plan:** [Boilerplate 1 Delivery Plan (§Pilot)](boilerplate-1-delivery-plan.md)  
**Related Documents:** [ADR-0005: Effort Baseline](adr/0005-effort-baseline-and-roi-measurement.md), [AI Data Governance Protocol & Consent Letter](pilot-client-ai-approval-consent.md), [AMS pilot profile](../delivery/pilot/pilot-config.sample.json)  
**Related Issues:** [hoanghainh1188/komagu#75](https://github.com/hoanghainh1188/komagu/issues/75), [hoanghainh1188/komagu#350](https://github.com/hoanghainh1188/komagu/issues/350)

Mọi lệnh trong sổ tay này đã được chạy thử trên `assess/lsa/tests/fixtures/java-legacy` (kit 0.3.1, CLI 2.4.0), trừ các lệnh cần model thật hoặc môi trường của khách hàng. Các lệnh đó được ghi chú *(chưa chạy thử)*.

---

## 0. Trạng thái hiện tại (2026-11-03)

| Mục | Trạng thái |
|---|---|
| Hệ thống AMS | Java legacy (JSP / Struts / Spring), tên và phạm vi chưa điền |
| Đơn xin phê duyệt AI | **Chưa gửi** ([checklist §7](pilot-client-ai-approval-consent.md#7-action-checklist-for-project-lead-harry)) |
| Phương án hạ tầng | **Chưa chọn**: chuẩn bị cả A (on-prem) và B (cloud Nhật) |
| Pilot nội bộ (fallback D6) | Đã xong: [pilot-final-report.md](../delivery/pilot/pilot-final-report.md), số liệu nội bộ |

## 1. Quy tắc bất biến

1. **Chỉ chạy headless** (`komagu scan --headless-ai`). Ở chế độ này, mọi đoạn code gửi tới AI đều được che bí mật (`operate/ai/context.py`). Agent runtime (Claude Code, Codex, Cursor) tự mở file, nên **không dùng** trên code của khách hàng.
2. **Không quét code của khách hàng trước khi có văn bản phê duyệt đã ký.** Tier 1 không gọi AI, nhưng vẫn là xử lý mã nguồn của khách hàng.
3. Chỉ quét **bản sao đã lọc** (bước W9-2), không quét repository gốc.
4. Không dùng `komagu fix --osv` trên code của khách hàng: tuỳ chọn này gửi tên và phiên bản thư viện tới OSV.dev. Dùng `--sca` (cơ sở dữ liệu tích hợp, offline).
5. Không có finding nào ra khỏi nhóm khi chưa có chữ ký Person B trong `review-log.md`.

---

## 2. Lịch tổng thể

| Tuần | Việc | Đầu ra | Cổng |
|---|---|---|---|
| 1–2 | P1–P2: điền đơn, chuẩn bị Q&A | Đơn bản nháp | — |
| 3 | Gửi đơn kèm Security Q&A (§6 của đơn) | Email gửi khách hàng | — |
| 3–6 | P3–P4: cài đặt, hiệu chuẩn cả hai phương án trên repo eval | `calib-A/`, `calib-B/` | — |
| **Cuối 6** | Kiểm tra văn bản phê duyệt | Bản ký lưu ở thư mục bảo mật | **Gate M3**: không có thì dùng fallback |
| 9 | W9: bản sao đã lọc, hạ tầng, timesheet | `pilot-config.json`, danh sách file | — |
| 9–10 | W9–W10: Tier 1 + Tier 2, Person B duyệt | `review-log.md` đã ký, báo cáo JA/EN | Accepted ≥ 70%, độ phủ endpoint 100% |
| 10 | W10: edge (Kong + Coraza) trước hệ thống | Rule virtual patch | Abuse script bị chặn |
| 10–12 | W10–W12: sửa và test cross-user | Patch, kết quả `komagu test` | — |
| 12 | W12: quét lại, đo ROI, xoá dữ liệu | Báo cáo cuối, biên bản xoá | **Gate BOD** |

---

## 3. Chuẩn bị trước khi có phê duyệt (tuần 1–6)

### P1. Điền đơn xin phê duyệt
Điền các ô `[...]` ở [§4 của đơn](pilot-client-ai-approval-consent.md#4-formal-ai-processing-consent-template-ai利用承諾申請書--日英併記): tên hệ thống, số endpoint ước tính, người ký. Đánh dấu cả hai phương án A và B để khách hàng chọn.

### P2. Security Q&A
Gửi kèm [§6 Security Q&A](pilot-client-ai-approval-consent.md#6-security-qa-for-the-client-想定質問と回答--日英併記). Nếu khách hàng hỏi câu chưa có trong Q&A, trả lời bằng văn bản rồi bổ sung vào §6.

### P3. Cài đặt máy trạm pilot
Máy trạm phải dùng riêng cho pilot. Với phương án A, máy phải offline khi có code của khách hàng trên đó.
```bash
git clone --branch v2.4.0 https://github.com/hoanghainh1188/komagu.git ~/komagu-pilot
cd ~/komagu-pilot
grep -q _redact_lines operate/ai/context.py && echo "redaction: OK" || echo "redaction: MISSING - STOP"
python3 assess/lsa/tests/run_tests.py
python3 -m unittest discover -s operate/tests -p "test_*.py"
```
Dòng kiểm tra phải in `redaction: OK`. Chỉ dùng `v2.4.0` trở lên: các bản trước gửi code cho model mà không che bí mật, và bộ test vẫn pass trên các bản đó vì chưa có test che bí mật.

Cả hai bộ test phải pass, trong đó có `test_ai_redaction` và `test_no_planted_secret_reaches_the_model`.

### P4. Hiệu chuẩn hạ tầng trên repo eval (không dùng code khách hàng)
Repo eval gồm 10 ứng dụng fixture với ground truth 121 mục. Chạy cùng một lệnh cho từng phương án, chỉ đổi endpoint và model:
```bash
python3 assess/lsa/tests/build_eval_repo.py ~/pilot-calib/eval
export KOMAGU_AI_API_KEY="<key from the secret manager>"   # never pass --api-key on the command line
./bin/komagu scan ~/pilot-calib/eval/repo --out ~/pilot-calib/calib-A --no-cache \
  --headless-ai http://127.0.0.1:11434/v1 --model gpt-oss:20b --ai-timeout 3600
python3 assess/lsa/tests/score_findings.py ~/pilot-calib/eval/ground-truth.json ~/pilot-calib/calib-A
```
- **Phương án A:** đã đo `gpt-oss:20b` (Run 4–5, [EVAL-RESULTS](../assess/lsa/tests/EVAL-RESULTS.md)). Lặp lại trên máy chủ GPU dự kiến để lấy thời gian chạy thực tế.
- **Phương án B** *(chưa chạy thử)*: endpoint phải tương thích OpenAI `/chat/completions` với Bearer token. Nếu dịch vụ cloud không hỗ trợ trực tiếp, đặt một proxy tương thích OpenAI (ví dụ LiteLLM) trong cùng vùng dữ liệu. Ghi lại model, vùng (region) và điều khoản lưu dữ liệu vào `pilot-config.json`.
- Kết quả hiệu chuẩn (recall theo loại, thời gian, `ai-run-stats.json`) dùng để giải thích cho khách hàng khi họ chọn phương án.

---

## 4. Tuần 9 — Khởi động

### W9-1. Kiểm tra phê duyệt
Chỉ tiếp tục khi có văn bản đã ký và phương án hạ tầng đã chọn. Sao chép [`delivery/pilot/pilot-config.sample.json`](../delivery/pilot/pilot-config.sample.json) thành `pilot-config.json` (lưu ở thư mục bảo mật, không commit), điền `approvalDate`, `hosting.selected` và số endpoint.

### W9-2. Tạo bản sao đã lọc
Đây là biện pháp chính cho Q3 trong Q&A: file nhạy cảm không bao giờ có trong bản sao.
```bash
rsync -a --exclude-from=ams-exclude.txt /path/to/client-repo/ ~/pilot/src/
find ~/pilot/src -type f | sort > ~/pilot/src-file-list.txt    # send this list to the client for confirmation
chmod -R a-w ~/pilot/src
```
`ams-exclude.txt` cần được thống nhất với khách hàng. Mẫu khởi đầu cho Java:
```text
.git/
*.jks
*.keystore
*.p12
*.pem
*.key
*.crt
**/src/test/
**/test-data/
**/*-prod.properties
**/*-production.yml
**/context.xml
**/server.xml
**/tomcat-users.xml
```
Kiểm tra lại: `grep -rIliE "password|secret|jdbc:" ~/pilot/src | head` để xem những file còn chứa từ khoá. Bộ che bí mật sẽ xử lý các file đó, nhưng file không cần cho việc audit thì nên loại thêm.

### W9-3. Hạ tầng AI
- **A:** khởi động model trên máy chủ GPU, kiểm tra `curl http://127.0.0.1:11434/v1/models`. Ngắt kết nối Internet của máy trạm.
- **B:** đặt `KOMAGU_AI_API_KEY` từ secret manager; kiểm tra endpoint bằng một request không chứa code.

### W9-4. Timesheet
Sao chép [`timesheet-template.csv`](../delivery/pilot/timesheet-template.csv). Mỗi dòng phải có một trong 4 tag của ADR-0005: `[PILOT-LSA]`, `[PILOT-GATEWAY]`, `[PILOT-REMEDIATE]`, `[PILOT-TEST-CI]`.

---

## 5. Tuần 9–10 — Đánh giá (Assess)

### W9-5. Tier 1 (không dùng AI)
```bash
./bin/komagu scan ~/pilot/src --out ~/pilot/out --project "<AMS system name>" --lang all --format all --update-baseline
```
Kiểm tra trên `~/pilot/out`:
- `stack-profile.json`: phải có `java-jsp`, `java-struts1` hoặc `java-struts2`, `java-spring-mvc` khi áp dụng, cùng `Hibernate/JPA` / `MyBatis/iBATIS`. Nếu thiếu, ghi chú lại; không tự sửa config khi chưa hiểu nguyên nhân.
- `routes.candidates.json`: so số route với số endpoint khách hàng báo. Route khai báo trong `struts-config.xml` / `struts.xml` / `web.xml` được ánh xạ từ XML. Nếu chênh lệch, tìm nguyên nhân trước khi chạy Tier 2 (tiêu chí: độ phủ 100%).
- `injection.candidates.json`, `mass-assignment.candidates.json`: số lượng và mức ưu tiên.

### W9-6. Tier 2 headless *(chưa chạy thử với model thật trên code Java của khách hàng)*
```bash
./bin/komagu scan ~/pilot/src --out ~/pilot/out --project "<AMS system name>" --no-cache \
  --headless-ai <endpoint> --model <model> --ai-timeout 3600
```
- Lưu lại toàn bộ `~/pilot/out` (bao gồm `ai-raw/` và `ai-run-stats.json`). Nếu một batch lỗi (`parse_failures`), chạy lại trước khi duyệt.
- Phase 5 (skeptic verifier) tự động phản biện từng finding. Finding bị bác vẫn được giữ trong `findings.raw.json` để Person B xem.

### W10-1. Person B duyệt
Sao chép [`assess/lsa/templates/review-log.md`](../assess/lsa/templates/review-log.md) vào `~/pilot/out/review-log.md`. Với mỗi finding, đọc code tại vị trí được chỉ ra, rồi ghi accept, reject hoặc đổi severity. Hoàn thành mục "Coverage sign-off", trong đó có mục kiểm tra báo cáo không chứa bí mật hay dữ liệu cá nhân.
- **Tiêu chí:** accepted / reported ≥ 70%.

### W10-2. Báo cáo
```bash
python3 assess/lsa/scripts/render_report.py ~/pilot/out --project "<AMS system name>" --lang all --format all
```
Gửi `report.ja.md` / `report.html` / `findings.sarif` cho khách hàng **sau khi** Person B ký.

---

## 6. Tuần 10 — Bảo vệ lớp biên (Edge)

Đặt Kong + Coraza (OWASP CRS) trước **môi trường test** của khách hàng trước khi sửa code:
```bash
./bin/komagu protect --target http://<client-test-host>:<port> --dry-run
./bin/komagu protect --virtual-patch ~/pilot/out/findings.json --patch-out ~/pilot/virtual-patches.conf --dry-run
./bin/komagu protect --target http://<client-test-host>:<port> --up      # (chưa chạy thử trên môi trường khách hàng)
```
- Proxy công khai chạy ở `:8000`, Kong Admin ở `:8001`, Coraza ở `:8080`. Ứng dụng Java (Tomcat) thường cũng dùng `8080`, nên phải đổi cổng nếu chạy cùng máy.
- Chạy script abuse (rate limit, SQLi) và xác nhận nhận được `429` / `403`. Ghi kết quả vào timesheet với tag `[PILOT-GATEWAY]`.

---

## 7. Tuần 10–12 — Khắc phục (Fix) và test cross-user

### W10-3. Chọn cách sửa theo stack

| Stack trong `stack-profile.json` | Cách sửa | Tài liệu |
|---|---|---|
| Servlet / JSP / Struts 1 / Struts 2 | `OwnershipEnforcer.requireOwnership(...)` trước khi đọc hoặc ghi object; trả 404 khi không khớp owner | [`remediate/legacy_shims/java/OwnershipEnforcer.java`](../remediate/legacy_shims/java/OwnershipEnforcer.java) |
| MyBatis `${...}` (sort / column) | Allow-list với `OwnershipEnforcer.safeOrderBy` / `validateIdentifier`; đổi `${}` sang `#{}` khi là giá trị | [`mybatis-safe-sort-example.xml`](../remediate/legacy_shims/java/mybatis-safe-sort-example.xml) |
| JDBC nối chuỗi | `PreparedStatement` với tham số | [`remediate/query/`](../remediate/query/README.md) |
| Spring Boot 3 (Java 17+) | `@RequireOwnership` / `KomaguSecurityManager` | [`remediate/authz/README.md` §3](../remediate/authz/README.md) |
| Spring MVC cũ (Spring ≤ 5, Java 8) | Module Spring Boot 3 không dùng được: dùng shim như với Servlet | `OwnershipEnforcer.java` |

Gợi ý patch tự động (chỉ là đề xuất, áp dụng theo quy trình change của khách hàng):
```bash
./bin/komagu fix ~/pilot/src --findings ~/pilot/out/findings.json --dry-run --format diff --output-patch ~/pilot/fix.patch
```
Trước khi chạy, phải bỏ cờ chỉ đọc trên một **bản sao làm việc khác**, không phải trên `~/pilot/src`.

### W11-1. Test cross-user *(chưa chạy thử trên môi trường khách hàng)*
Chỉ chạy trên môi trường test, với tài khoản test do khách hàng cấp (Q7) và sau khi khách hàng đồng ý riêng:
```bash
export ATTACKER_TOKEN="<test account B token>"
./bin/komagu test --url http://<client-test-host>:<port> --from-scan ~/pilot/out/findings.json \
  --token "$ATTACKER_TOKEN" --strict --output ~/pilot/out/cross-user-results.json
```
Mỗi finding đã sửa phải có một test case: trước khi sửa thì test fail, sau khi sửa thì pass.

---

## 8. Tuần 12 — Quét lại, đo lường, đóng pilot

### W12-1. Quét lại so với baseline
```bash
./bin/komagu scan ~/pilot/src-fixed --out ~/pilot/out-w12 --baseline ~/pilot/out/baseline.json --fail-on any \
  --headless-ai <endpoint> --model <model> --ai-timeout 3600
```
**Tiêu chí:** 100% finding đã accept trong phạm vi pilot được sửa và test lại (không còn finding accepted nào mở).

### W12-2. ROI theo ADR-0005
- Baseline ngành: `N × (0.25 + 0.35 + 0.20) + 6.0` person-days, với `N` là số endpoint thực tế. Ví dụ: 50 endpoint cho ra 46.0.
- Thực tế: `Σ HoursSpent / 8` từ timesheet, tách theo 4 tag.
- Báo cáo con số đo được, **không đặt mục tiêu** (delivery plan: "Measured and reported, no target").

### W12-3. Bàn giao và xoá dữ liệu
1. Bàn giao báo cáo, patch và kết quả test cho khách hàng.
2. Xoá `~/pilot/src`, `~/pilot/src-fixed`, `~/pilot/out*` và log của model server (phương án A); kiểm tra thư mục tạm.
3. Lập biên bản xoá (thư mục, ngày, người thực hiện, người xác nhận) và gửi khách hàng (cam kết §3-6 của đơn).

---

## 9. Điều kiện dừng

Dừng pilot và báo khách hàng ngay khi:
- Phát hiện bí mật thật trong `ai-raw/` hoặc trong báo cáo: xoá đầu ra liên quan, báo cáo sự cố, bổ sung pattern che và test trước khi chạy lại.
- Có code được gửi ra ngoài phạm vi phương án đã duyệt (sai endpoint, sai vùng).
- Khách hàng rút lại phê duyệt.

---

## 10. Version History

| Phiên bản | Ngày | Tác giả | Tóm tắt thay đổi |
|---|---|---|---|
| 1.0 | 2026-10-18 | Harry & Komagu Lead Agent | Khởi tạo sổ tay 4 tuần (#75). |
| 2.0 | 2026-11-03 | Harry & Claude | #350: viết lại cho pilot AMS Java; chỉ dùng headless; thêm chuẩn bị trước phê duyệt (P1–P4) và bước tạo bản sao đã lọc; sửa lệnh theo CLI 2.3.0 (tên package, `komagu protect` thay cho `operate/gateway` + Konnect, `render_report.py`); bảng sửa lỗi theo stack Java; baseline ROI theo công thức ADR-0005; bước xoá dữ liệu và điều kiện dừng. |
| 2.1 | 2026-11-10 | Harry & Claude | #355: P3 cài `v2.4.0`, bản đầu tiên có che bí mật, và thêm bước kiểm tra che bí mật. |
