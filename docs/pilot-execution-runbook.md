# Pilot Execution Runbook: AMS Pilot on a Java Legacy System (Weeks 1–12)
## パイロット運用実施手順書（AMS・Java レガシー）

**Version:** 2.4  
**Effective Date:** 2026-11-03  
**Project Lead & Sign-off Authority:** Harry (Principal Architect / PM / Person B)  
**Parent Delivery Plan:** [Boilerplate 1 Delivery Plan (§Pilot)](boilerplate-1-delivery-plan.md)  
**Related Documents:** [ADR-0005: Effort Baseline](adr/0005-effort-baseline-and-roi-measurement.md), [AI Data Governance Protocol & Consent Letter](pilot-client-ai-approval-consent.md), [AMS pilot profile](../delivery/pilot/pilot-config.sample.json)  
**Related Issues:** [hoanghainh1188/komagu#75](https://github.com/hoanghainh1188/komagu/issues/75), [hoanghainh1188/komagu#350](https://github.com/hoanghainh1188/komagu/issues/350)

Mọi lệnh trong sổ tay này đã được chạy thử trên `assess/lsa/tests/fixtures/java-legacy` (kit 0.3.1, CLI 2.4.0), trừ các lệnh cần model thật hoặc môi trường của khách hàng. Các lệnh đó được ghi chú *(chưa chạy thử)*.

Các bước W9-2 đến W12-3 đã được diễn tập nối tiếp trên một ứng dụng Struts 1 / JSP đang chạy trên Tomcat ([`examples/legacy-java-rehearsal`](../examples/legacy-java-rehearsal/README.md), #374), với model giả lập cục bộ. Các sửa lỗi của lần diễn tập có từ `v2.5.0`; P3 cài `v2.6.0`.

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
git clone --branch v2.6.0 https://github.com/hoanghainh1188/komagu.git ~/komagu-pilot
cd ~/komagu-pilot
grep -q _redact_lines operate/ai/context.py && echo "redaction: OK" || echo "redaction: MISSING - STOP"
python3 assess/lsa/tests/run_tests.py
python3 -m unittest discover -s operate/tests -p "test_*.py"
```
Dòng kiểm tra phải in `redaction: OK`. Chỉ dùng `v2.6.0` trở lên. `v2.5.0` là bản đầu tiên có test cross-user theo session (W11-1) và `komagu leak-check` (§9). `v2.6.0` thêm `--ai-reasoning-effort` (xem P4), và route không có id đầu vào không còn bị gán một id giả trong path, nên auditor BOLA không còn báo finding trên các route đó (#381). Các bản trước `v2.4.0` còn gửi code cho model mà không che bí mật, và bộ test vẫn pass trên các bản đó vì chưa có test che bí mật.

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
- **Phương án A:** đã đo `gpt-oss:20b` (Run 6, [EVAL-RESULTS](../assess/lsa/tests/EVAL-RESULTS.md)): 40–56 phút trên Apple M4 Pro 24 GB; BOLA 26/29, injection 34/34, BFLA 10/10, mass assignment 14/15, precision 0,79–0,81. Lặp lại trên máy chủ GPU dự kiến để lấy thời gian chạy thực tế, và so với các số này.
- **Phương án B** *(chưa chạy thử)*: endpoint phải tương thích OpenAI `/chat/completions` với Bearer token. Nếu dịch vụ cloud không hỗ trợ trực tiếp, đặt một proxy tương thích OpenAI (ví dụ LiteLLM) trong cùng vùng dữ liệu. Ghi lại model, vùng (region) và điều khoản lưu dữ liệu vào `pilot-config.json`.
- **Model có reasoning** (ví dụ `qwen3.5:9b`): thêm `--ai-reasoning-effort none` khi bộ nhớ hạn chế. Trên máy 24 GB với `num_ctx 16384`, reasoning mặc định làm hai batch BOLA hết `--ai-timeout`; tắt reasoning thì chạy xong mọi phase trong 35 phút (Run 6, [EVAL-RESULTS](../assess/lsa/tests/EVAL-RESULTS.md)). Endpoint phải nhận trường `reasoning_effort` (Ollama `/v1` có nhận). Không đặt cờ thì không gửi gì, như các bản trước.
- Giá trị `--ai-reasoning-effort` (hoặc không đặt) được ghi vào `ai-run-stats.json`. Dùng đúng giá trị đã hiệu chuẩn ở W9-6 và W12-1, để kết quả trước và sau khi sửa so sánh được.
- Kết quả hiệu chuẩn (recall theo loại, thời gian, `ai-run-stats.json`) dùng để giải thích cho khách hàng khi họ chọn phương án.

---

## 4. Tuần 9 — Khởi động

### W9-1. Kiểm tra phê duyệt
Chỉ tiếp tục khi có văn bản đã ký và phương án hạ tầng đã chọn. Sao chép [`delivery/pilot/pilot-config.sample.json`](../delivery/pilot/pilot-config.sample.json) thành `pilot-config.json` (lưu ở thư mục bảo mật, không commit), điền `approvalDate`, `hosting.selected` và số endpoint.

### W9-2. Tạo bản sao đã lọc
Đây là biện pháp chính cho Q3 trong Q&A: file nhạy cảm không bao giờ có trong bản sao.
```bash
cp ~/komagu-pilot/delivery/pilot/ams-exclude.sample.txt ~/pilot/ams-exclude.txt   # agree the final list with the client
rsync -a --exclude-from="$HOME/pilot/ams-exclude.txt" /path/to/client-repo/ ~/pilot/src/
find ~/pilot/src -type f | sort > ~/pilot/src-file-list.txt    # send this list to the client for confirmation
chmod -R a-w ~/pilot/src
```
[`ams-exclude.sample.txt`](../delivery/pilot/ams-exclude.sample.txt) là mẫu khởi đầu cho Java; `ams-exclude.txt` cần được thống nhất với khách hàng và lưu ngoài repository. `operate/tests/test_pilot_safeguards.py` kiểm tra mẫu này bằng `rsync` thật: keystore, cấu hình production và `context.xml` đều bị loại. Khi thêm pattern, không dùng `**/` ở đầu vì rsync không khớp với file ở thư mục gốc của bản sao.

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
./bin/komagu scan ~/pilot/src --out ~/pilot/out --project "<AMS system name>" --no-cache --lang all --format all
```
Dùng `--no-cache`: nếu không, Tier 1 ghi mã nguồn của khách hàng vào `~/pilot/out/.cache/` và `komagu leak-check` sẽ báo file đó.
Kiểm tra trên `~/pilot/out`:
- `stack-profile.json`: phải có `java-jsp`, `java-struts1` hoặc `java-struts2`, `java-spring-mvc` khi áp dụng, cùng `data_access` là `Hibernate/JPA` / `MyBatis/iBATIS` (MyBatis cũng hiện là stack `java-mybatis`). Nếu thiếu, ghi chú lại; không tự sửa config khi chưa hiểu nguyên nhân.
- `routes.candidates.json`: so số route với số endpoint khách hàng báo. Route khai báo trong `struts-config.xml` / `struts.xml` / `web.xml` được ánh xạ từ XML. Dòng `servlet-mapping` kiểu `*.do` cũng được tính là một route, nên số route bằng số action cộng số mapping đó. Nếu chênh lệch, tìm nguyên nhân trước khi chạy Tier 2 (tiêu chí: độ phủ 100%).
- `injection.candidates.json`, `mass-assignment.candidates.json`: số lượng và mức ưu tiên.

### W9-6. Tier 2 headless *(chưa chạy thử với model thật trên code Java của khách hàng)*
```bash
./bin/komagu scan ~/pilot/src --out ~/pilot/out --project "<AMS system name>" --no-cache --update-baseline \
  --headless-ai <endpoint> --model <model> --ai-timeout 3600
```
- Nếu P4 hiệu chuẩn với `--ai-reasoning-effort`, thêm đúng giá trị đó vào lệnh này và lệnh W12-1.
- `--update-baseline` phải đặt ở bước này: Tier 1 không sinh finding nên baseline tạo ở W9-5 sẽ rỗng, và W12-1 không có gì để so sánh.
- Lưu lại toàn bộ `~/pilot/out` (gồm `ai-run-stats.json`; `ai-raw/` chỉ có khi một batch phải sửa lại định dạng). Nếu một batch lỗi (`parse_failures`), chạy lại trước khi duyệt.
- Kiểm tra `validation_errors` trong `coverage.json`: finding sai schema bị loại khỏi `findings.json` dù lệnh vẫn thoát `0`. Nếu danh sách không rỗng, chạy lại trước khi duyệt.
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

Đặt Kong + Coraza (OWASP CRS) trước **môi trường test** của khách hàng trước khi sửa code. Ứng dụng dùng `JSESSIONID` và form phải dùng profile `kong-legacy-session.yaml`: profile mặc định chỉ mở `/api/v1` và bắt buộc JWT.
```bash
./bin/komagu protect --target http://<client-test-host>:<port> --config remediate/edge/kong/kong-legacy-session.yaml --dry-run
./bin/komagu protect --virtual-patch ~/pilot/out/findings.json --patch-out ~/pilot/virtual-patches.conf --dry-run
KOMAGU_EDGE_BIND=127.0.0.1 ./bin/komagu protect --target http://<client-test-host>:<port> \
  --config remediate/edge/kong/kong-legacy-session.yaml --patch-out ~/pilot/virtual-patches.conf --up      # (chưa chạy thử trên môi trường khách hàng)
```
- Proxy chạy ở `:8000`, Kong Admin ở `127.0.0.1:8001`. Coraza nghe `8080` bên trong mạng Docker và không mở ra máy chủ, nên không đụng với Tomcat `8080`. `KOMAGU_EDGE_BIND` mặc định là `0.0.0.0`; bỏ biến này chỉ khi proxy phải nhận request từ máy khác. Khi Tomcat chạy trên chính máy trạm, dùng `--target http://host.docker.internal:<port>`.
- Virtual patch **không** bảo vệ được route dùng session: WAF không biết ai sở hữu object, nên finding BOLA trên route `.do`, `.action`, `.jsp`, `.jspx` không có rule và phải sửa bằng code. Finding SQLi không có route cũng không có rule riêng; các rule SQLi chung vẫn áp dụng. Lệnh in cảnh báo cho từng trường hợp.
- Chạy script abuse và xác nhận kết quả, rồi ghi vào timesheet với tag `[PILOT-GATEWAY]`:
```bash
curl -s -o /dev/null -w '%{http_code}\n' --get --data-urlencode "q=zzz%' OR 1=1 -- " -b "$COOKIE" http://<edge-host>:8000/<route có tham số>   # phải là 403
for i in $(seq 1 25); do curl -s -o /dev/null -w '%{http_code}\n' -b "$COOKIE" http://<edge-host>:8000/<trang sau đăng nhập> & done | sort | uniq -c   # phải có 429
```
Sau đó thử một luồng thật qua `:8000` (đăng nhập, mở form, gửi form có token) để chắc WAF không chặn nhầm. CRS 944130 từng chặn mọi form Struts 1 vì tên trường token giống tên lớp Java; rule `200002` trong `coraza-crs-custom.conf` đã loại trừ đúng trường đó. Giới hạn là 10 request/giây và 120 request/phút theo IP; sửa trong profile nếu luồng thật của khách hàng cần nhiều hơn.

Diễn tập ngày 2026-11-11 trên Tomcat: SQLi trả `403`, 25 request đồng thời có 15 lần `429`, đăng nhập và form có token đi qua bình thường.

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
Trước khi chạy, tạo một **bản sao làm việc khác** và bỏ cờ chỉ đọc trên bản đó, không phải trên `~/pilot/src`:
```bash
cp -R ~/pilot/src ~/pilot/src-fixed && chmod -R u+w ~/pilot/src-fixed
```
Khi toàn bộ finding cần sửa tay, `--format diff` không tạo patch; danh sách vị trí được in ra stderr, và file `--output-patch` không được tạo.

**Với Java legacy, `komagu fix` chưa tạo được patch dùng được.** Kết quả chạy `--dry-run` trên fixture Struts với `findings.json` dựng tay theo dạng Tier 2 (Tier 1 không sinh finding nên không có gì để vá):
- File `.java`: patcher chỉ chèn `@RequireOwnership` của module Spring Boot 3. Annotation này không có tác dụng trên Struts, Servlet hay Spring MVC cũ. `entityClass` lại suy ra từ route (`View.do.class`), nên code không biên dịch được.
- File Java mã hoá Shift_JIS: patcher đọc file như UTF-8, làm hỏng chú thích tiếng Nhật và đổi CRLF thành LF, nên diff thay cả file.
- File `.jsp`: báo `needs manual fix`, không có patch.

Vì vậy **không áp dụng patch này**. Chỉ dùng `--dry-run` để liệt kê vị trí cần sửa, rồi sửa bằng tay theo bảng trên với `OwnershipEnforcer`.

### W11-1. Test cross-user *(chưa chạy thử trên môi trường khách hàng)*
Chỉ chạy trên môi trường test, với tài khoản test do khách hàng cấp (Q7) và sau khi khách hàng đồng ý riêng.

Ứng dụng JSP / Struts / Spring MVC cũ dùng `JSESSIONID` và form, không dùng Bearer token. Làm theo thứ tự:

1. Đăng nhập bằng tài khoản A (chủ object) và B (kẻ tấn công), lấy giá trị cookie. Cookie chỉ đi qua biến môi trường hoặc file, không có cờ nhận trực tiếp giá trị cookie, và không xuất hiện trong output hay báo cáo.
2. Mở thử một trang không có quyền để biết ứng dụng từ chối thế nào: mã `404` / `403`, trang lỗi `200`, hay `302` về trang login. Ghi lại để khai báo bằng `--deny-*`. Trang lỗi Shift_JIS / Windows-31J vẫn so khớp được.
3. Chạy:
```bash
read -rs ATTACKER_COOKIE && export ATTACKER_COOKIE   # nhập JSESSIONID=... của B
read -rs OWNER_COOKIE && export OWNER_COOKIE         # nhập JSESSIONID=... của A
./bin/komagu test --url http://<cổng trực tiếp của ứng dụng> --from-scan ~/pilot/out/findings.json \
  --resource-id <id object của A> --strict \
  --attacker-cookie-env ATTACKER_COOKIE --owner-cookie-env OWNER_COOKIE \
  --session-check /<trang cả A và B đều mở được> --session-marker "<chữ chỉ có khi đã đăng nhập>" \
  --deny-status 404 --deny-redirect /login.do --deny-marker "<chữ trên trang báo lỗi quyền>" \
  --allow-redirect /<trang đích sau khi ghi thành công> \
  --csrf-page /<trang form của B> --csrf-field org.apache.struts.taglib.html.TOKEN \
  --owner-control-writes --owner-csrf-page /<trang form của A> \
  --output ~/pilot/out/cross-user-results.json
```
- Dùng cổng trực tiếp của ứng dụng, không qua `:8000`: rate limit và WAF ở biên sẽ làm kết quả sai.
- Route khai báo trong XML có method `ANY`: tên action có từ như `update`, `save`, `delete` được gửi bằng POST, còn lại bằng GET. Sửa `attack_vector.method` trong `findings.json` nếu đoán sai. `--resource-id` dùng chung cho mọi route, nên order và invoice của A phải có cùng id, hoặc chạy riêng từng nhóm.
- Route `.do`, `.action`, `.jsp`, `.jspx` tự gửi form; id lấy tên tham số từ `attack_vector.target_param` (Tier 2 điền từ Tier 1, mặc định `id`). Tên trường token: Struts 1 như trên, Struts 2 `<s:token>` là `token`, Spring Security là `_csrf`. Không có token thì bỏ hai cờ `--csrf-*`.
- `--strict` với cookie bắt buộc có tín hiệu từ chối, `--session-check` và cookie của A. Thiếu một trong ba thì lệnh dừng với exit 2.
- Exit `0`: mọi request đều bị từ chối. Exit `1`: có `[FAIL]` (lỗ hổng) hoặc `[ERROR]` (không kết luận được, ví dụ redirect chưa khai báo, thiếu token, hoặc A cũng bị từ chối nên id hay route sai). Exit `2`: cấu hình sai hoặc session hết hạn, kể cả khi hết hạn giữa chừng; kết quả lần chạy đó không dùng được.
- Sau khi B bị từ chối, A gửi lại đúng request đó và phải thành công, để chứng minh route và id là đúng. `--owner-control-writes` **thực sự ghi vào dữ liệu của A**, nên phải dùng object test và có sự đồng ý của khách hàng. Không có cờ này thì `--strict` báo `[ERROR]` cho request ghi bị từ chối, không báo PASS. Route `DELETE` sẽ xoá object của A, nên cần object riêng cho từng route.
- Trên route còn lỗ hổng, request ghi của B **thực sự được thực hiện**.

Mỗi finding đã sửa phải có một test case: trước khi sửa thì test fail, sau khi sửa thì pass. Lưu file kết quả của cả hai lần chạy. `komagu test` chỉ kiểm tra lỗi phân quyền: finding SQLi phải được kiểm tra bằng request riêng (payload trước khi sửa trả dữ liệu ngoài phạm vi, sau khi sửa thì không) và ghi lại kết quả.

Đã diễn tập trên Tomcat với Struts token, `JSESSIONID` và ba kiểu từ chối (`404`, trang lỗi `200` Windows-31J, `302`): trước khi sửa 4/4 `[FAIL]`, exit `1`; sau khi sửa 4/4 `[PASS]`, exit `0`, và cookie không xuất hiện trong file kết quả. Chưa chạy trên môi trường khách hàng.

---

## 8. Tuần 12 — Quét lại, đo lường, đóng pilot

### W12-1. Quét lại so với baseline
```bash
./bin/komagu scan ~/pilot/src-fixed --out ~/pilot/out-w12 --no-cache --baseline ~/pilot/out/baseline.json --fail-on any \
  --headless-ai <endpoint> --model <model> --ai-timeout 3600      # (chưa chạy thử với model thật)
```
Sửa MyBatis `${...}` bằng allow-list vẫn giữ `${}` trong XML, và model chỉ thấy file XML nên có thể vẫn báo finding. Khi Person B đã xác nhận allow-list, thêm `fingerprint` của finding đó vào `~/pilot/src-fixed/.komagu/suppressions.json` với `reason`, `approved_by` và `expires`, rồi chạy lại. Diễn tập với model giả lập: exit `1` trước khi thêm, exit `0` sau khi thêm, 5 finding `fixed` và 1 `suppressed`.

**Tiêu chí:** 100% finding đã accept trong phạm vi pilot được sửa và test lại (không còn finding accepted nào mở).

### W12-2. ROI theo ADR-0005
- Baseline ngành: `N × (0.25 + 0.35 + 0.20) + 6.0` person-days, với `N` là số endpoint thực tế. Ví dụ: 50 endpoint cho ra 46.0.
- Thực tế: `Σ HoursSpent / 8` từ timesheet, tách theo 4 tag.
- Báo cáo con số đo được, **không đặt mục tiêu** (delivery plan: "Measured and reported, no target").

### W12-3. Bàn giao và xoá dữ liệu
1. Bàn giao báo cáo, patch và kết quả test cho khách hàng.
2. Dừng stack biên, rồi xoá toàn bộ `~/pilot/`. `~/pilot/src` đã bị `chmod a-w` ở W9-2 nên phải bỏ cờ chỉ đọc trước, nếu không `rm` sẽ báo `Permission denied` và dữ liệu vẫn còn:
   ```bash
   ./bin/komagu protect --down
   chmod -R u+w ~/pilot && rm -rf ~/pilot
   ```
   Xoá log của model server (phương án A); kiểm tra thư mục tạm.
3. Lập biên bản xoá theo mẫu JA/EN [`data-deletion-report.template.md`](../delivery/pilot/data-deletion-report.template.md) (thư mục, ngày, người thực hiện, người xác nhận, log model server, thư mục tạm) và gửi khách hàng (cam kết §3-6 của đơn). Lưu bản đã điền ở thư mục bảo mật, không commit.

---

## 9. Điều kiện dừng

Dừng pilot và báo khách hàng ngay khi:
- Phát hiện bí mật thật trong `ai-raw/` hoặc trong báo cáo: xoá đầu ra liên quan, báo cáo sự cố, bổ sung pattern che và test trước khi chạy lại. `.cache/` chứa mã nguồn của khách hàng, nên W9-5 và W12-1 dùng `--no-cache`. Kiểm tra sau mỗi lần chạy Tier 2 và trước khi gửi báo cáo cho khách hàng:
  ```bash
  ./bin/komagu leak-check ~/pilot/out --canary-file ~/pilot/canaries.txt --format json > ~/pilot/leak-check.json
  ```
  `~/pilot/canaries.txt` chứa các chuỗi khách hàng cung cấp (tên host nội bộ, tên DB, giá trị mồi), mỗi dòng một chuỗi, và nằm ngoài repository. Mã thoát: `0` không phát hiện gì, `1` có nghi vấn, `2` quét chưa đầy đủ (có file không đọc được, file nhị phân, hoặc đầu vào sai). Báo cáo chỉ ghi file, dòng và giá trị đã che. Mã `1` là nghi vấn: Person B mở từng vị trí để xác định có phải bí mật thật không, và chỉ dừng pilot khi đúng là bí mật thật. Mã `2` phải được xử lý rồi quét lại. Mã `0` không chứng minh là không còn bí mật, nên Person B vẫn phải kiểm tra như ở W10-1.
- Có code được gửi ra ngoài phạm vi phương án đã duyệt (sai endpoint, sai vùng).
- Khách hàng rút lại phê duyệt.

---

## 10. Version History

| Phiên bản | Ngày | Tác giả | Tóm tắt thay đổi |
|---|---|---|---|
| 1.0 | 2026-10-18 | Harry & Komagu Lead Agent | Khởi tạo sổ tay 4 tuần (#75). |
| 2.0 | 2026-11-03 | Harry & Claude | #350: viết lại cho pilot AMS Java; chỉ dùng headless; thêm chuẩn bị trước phê duyệt (P1–P4) và bước tạo bản sao đã lọc; sửa lệnh theo CLI 2.3.0 (tên package, `komagu protect` thay cho `operate/gateway` + Konnect, `render_report.py`); bảng sửa lỗi theo stack Java; baseline ROI theo công thức ADR-0005; bước xoá dữ liệu và điều kiện dừng. |
| 2.1 | 2026-11-10 | Harry & Claude | #355: P3 cài `v2.4.0`, bản đầu tiên có che bí mật, và thêm bước kiểm tra che bí mật. |
| 2.2 | 2026-11-11 | Harry & Claude | #374: sửa theo lần diễn tập W9–W12 trên ứng dụng Struts 1 đang chạy: profile Kong cho ứng dụng session, `--update-baseline` chuyển sang W9-6, `--no-cache`, giới hạn của virtual patch, xử lý MyBatis ở W12-1, bỏ cờ chỉ đọc trước khi xoá. |
| 2.3 | 2026-11-11 | Harry & Claude | #376: P3 cài `v2.5.0`, bản đầu tiên có test cross-user theo session, `komagu leak-check` và các sửa lỗi của lần diễn tập. |
| 2.4 | 2026-11-11 | Harry & Claude | #384: P3 cài `v2.6.0`; P4, W9-6 và W12-1 hướng dẫn dùng `--ai-reasoning-effort` cho model có reasoning. |
