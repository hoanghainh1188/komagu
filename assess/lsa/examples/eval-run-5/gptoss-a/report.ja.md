# セキュリティ監査報告書 — repo

> **機密区分: 社外秘 (CONFIDENTIAL)** 本報告書はAI支援による静的コードレビュー結果です。外部共有前に必ず人間のレビュー担当者による確認・承認が必要です（判定結果は `review-log.md` に記録）。

| 項目 | 値 |
|---|---|
| 診断実施日 | 2026-10-31 |
| 監査キットバージョン | 0.3.1 |
| 監査対象スコープ | BOLA/IDOR（オブジェクトレベルの認可不備）、外部入力によるSQL/HQL/NoSQLクエリ構築、BFLA（機能レベルの認可不備）、マスアサインメント |
| 検出技術スタック | php, php-codeigniter, php-laravel, java-servlet, java-jsp, java-struts1, java-spring-mvc, java-mybatis, java-hibernate, dotnet-webforms, dotnet-handlers, dotnet-mvc, classic-asp, perl-cgi, coldfusion, node-express, python-flask, sql-procedures |
| インベントリ登録エンドポイント数 | 74 (候補数: 74) |
| BOLA監査対象エンドポイント数 | 74 |
| レビュー対象インジェクション候補数 | 38 |
| BFLA監査対象の特権エンドポイント数 | 0 |
| レビュー対象マスアサインメント候補数 | 15 |

## 1. エグゼクティブサマリー

<!-- LLM: reporter agent writes max 8 bullets here (日本語で記載: 全体のリスクレベル、事業影響の大きい上位3件の検出事項、根本原因) -->

## 2. 検出事項の概要

| 重要度 | 緊急 (Critical) | 高 (High) | 中 (Medium) | 低 (Low) | 情報 (Info) |
|---|---|---|---|---|---|
| 件数 | 50 | 43 | 6 | 0 | 0 |

| 脆弱性分類 | 件数 |
|---|---|
| オブジェクトレベルの認可不備 (BOLA/IDOR) | 42 |
| SQLインジェクション (SQLi) | 30 |
| NoSQLインジェクション (NoSQLi) | 5 |
| 機能レベルの認可不備 (BFLA) | 12 |
| マスアサインメント (Mass Assignment) | 10 |

ステータス内訳: 未検証 (Unverified)=0, 確認済 (Confirmed)=57, likely=42, 棄却 (Rejected)=2, 要確認 (Needs Review)=0

## 検出推移と平均修正日数 (MTTR)

| 日付 | 未解決 | 新規 | 再発 | 修正済 | 抑制 |
|---|---|---|---|---|---|
| 2026-10-31 | 99 | 99 | 0 | 0 | 0 |

修正済みの検出事項はまだありません。

## 3. 検出事項の詳細

| ID | 重要度 | 確信度 | ステータス | 脆弱性分類 | 対象エンドポイント | 該当箇所 | タイトル |
|---|---|---|---|---|---|---|---|
| BFLA-R-0003-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | 機能レベルの認可不備 (BFLA) |   | `classic-asp/shop/member.asp:9` | Unrestricted member deletion in classic‑ASP |
| BFLA-R-0007-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | 機能レベルの認可不備 (BFLA) |   | `dotnet-legacy/Web/Controllers/AdminController.cs:12` | Unrestricted user deletion in ASP.NET MVC |
| BFLA-R-0009-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | 機能レベルの認可不備 (BFLA) |   | `dotnet-legacy/Web/Controllers/AdminController.cs:30` | Export endpoint controlled by request parameter |
| BFLA-R-0023-1 | 緊急 (Critical) | 中 (Medium) | likely | 機能レベルの認可不備 (BFLA) |   | `java-legacy/src/com/acme/web/AdminUserController.java:13` | Unrestricted user deletion in Spring MVC |
| BFLA-R-0030-1 | 緊急 (Critical) | 中 (Medium) | likely | 機能レベルの認可不備 (BFLA) |   | `node-express/routes/admin.js:8` | Unrestricted user deletion in Express.js |
| BFLA-R-0032-1 | 緊急 (Critical) | 中 (Medium) | likely | 機能レベルの認可不備 (BFLA) |   | `node-express/routes/admin.js:16` | Export endpoint controlled by query parameter in Express.js |
| BFLA-R-0057-1 | 緊急 (Critical) | 中 (Medium) | likely | 機能レベルの認可不備 (BFLA) |   | `php-plain/admin.php:6` | Unrestricted user view in PHP |
| BFLA-R-0058-1 | 緊急 (Critical) | 中 (Medium) | likely | 機能レベルの認可不備 (BFLA) |   | `php-plain/admin.php:10` | Unrestricted user deletion in PHP |
| BFLA-R-0059-1 | 緊急 (Critical) | 中 (Medium) | likely | 機能レベルの認可不備 (BFLA) |   | `php-plain/manage_users.php:1` | Client‑side admin check allows user deletion in PHP |
| BFLA-R-0063-1 | 緊急 (Critical) | 中 (Medium) | likely | 機能レベルの認可不備 (BFLA) |   | `php-plain/profile.php:1` | Privilege escalation via role field in profile update |
| BFLA-R-0066-1 | 緊急 (Critical) | 中 (Medium) | likely | 機能レベルの認可不備 (BFLA) |   | `php-plain/admin/delete_user.php:1` | Unrestricted user deletion in PHP |
| BFLA-R-0067-1 | 緊急 (Critical) | 中 (Medium) | likely | 機能レベルの認可不備 (BFLA) |   | `php-plain/admin/promote.php:1` | Privilege escalation via role promotion in PHP |
| INJ-I-0001 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `classic-asp/shop/member.asp:6` | SQL Injection in classic-asp/shop/member.asp:6 |
| INJ-I-0002 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `classic-asp/shop/member.asp:7` | SQL Injection in classic-asp/shop/member.asp:7 |
| INJ-I-0003 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `classic-asp/shop/member.asp:10` | SQL Injection in classic-asp/shop/member.asp:10 |
| INJ-I-0004 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `classic-asp/shop/order.asp:6` | SQL Injection in classic-asp/shop/order.asp:6 |
| INJ-I-0006 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `coldfusion/app/OrderService.cfc:5` | SQL Injection in coldfusion/app/OrderService.cfc:5 |
| INJ-I-0007 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `coldfusion/app/order.cfm:3` | SQL Injection in coldfusion/app/order.cfm:3 |
| INJ-I-0008-1 | 緊急 (Critical) | 中 (Medium) | likely | SQLインジェクション (SQLi) |   | `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` | SQL Injection in dotnet-legacy/Web/Controllers/InvoiceController.cs:28 |
| INJ-I-0009 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` | SQL Injection in dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7 |
| INJ-I-0010 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` | SQL Injection in dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8 |
| INJ-I-0011-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` | SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13 |
| INJ-I-0011-3 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` | SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20 |
| INJ-I-0012 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19` | SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19 |
| INJ-I-0013 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20` | SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20 |
| INJ-I-0014 | 緊急 (Critical) | 中 (Medium) | likely | SQLインジェクション (SQLi) |   | `java-legacy/WebContent/order/detail.jsp:5` | SQL Injection in java-legacy/WebContent/order/detail.jsp:5 |
| INJ-I-0015-1 | 緊急 (Critical) | 中 (Medium) | likely | SQLインジェクション (SQLi) |   | `java-legacy/src/com/acme/mapper/OrderMapper.xml:9` | SQL Injection in java-legacy/src/com/acme/mapper/OrderMapper.xml:9 |
| INJ-I-0016 | 緊急 (Critical) | 中 (Medium) | likely | SQLインジェクション (SQLi) |   | `java-legacy/src/com/acme/struts/EditUserAction.java:13` | SQL Injection in java-legacy/src/com/acme/struts/EditUserAction.java:13 |
| INJ-I-0017 | 緊急 (Critical) | 中 (Medium) | likely | SQLインジェクション (SQLi) |   | `java-legacy/src/com/acme/web/InvoiceController.java:29` | SQL Injection in java-legacy/src/com/acme/web/InvoiceController.java:29 |
| INJ-I-0018-1 | 緊急 (Critical) | 中 (Medium) | likely | SQLインジェクション (SQLi) |   | `java-legacy/src/com/acme/web/OrderServlet.java:15` | SQL Injection in java-legacy/src/com/acme/web/OrderServlet.java:15 |
| INJ-I-0020-1 | 緊急 (Critical) | 中 (Medium) | likely | SQLインジェクション (SQLi) |   | `node-express/routes/orders.js:17` | SQL Injection in node-express/routes/orders.js:17 |
| INJ-I-0020-3 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | NoSQLインジェクション (NoSQLi) |   | `node-express/routes/orders.js:17` | NoSQL Injection in node-express/routes/orders.js:25 |
| INJ-I-0020-4 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `node-express/routes/orders.js:17` | SQL Injection in node-express/routes/orders.js:29 |
| INJ-I-0021 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `node-express/routes/orders.js:29` | SQL Injection in node-express/routes/orders.js:29 |
| INJ-I-0022 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | NoSQLインジェクション (NoSQLi) |   | `node-express/routes/orders.js:21` | NoSQL Injection in node-express/routes/orders.js:21 |
| INJ-I-0023 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | NoSQLインジェクション (NoSQLi) |   | `node-express/routes/orders.js:25` | NoSQL Injection in node-express/routes/orders.js:25 |
| INJ-I-0024-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `perl-cgi/cgi-bin/order.cgi:13` | SQL Injection in perl-cgi/cgi-bin/order.cgi:13 |
| INJ-I-0025 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `perl-cgi/cgi-bin/order.cgi:19` | SQL Injection in perl-cgi/cgi-bin/order.cgi:19 |
| INJ-I-0026-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `php-codeigniter/application/controllers/Invoice.php:10` | SQL Injection in php-codeigniter/application/controllers/Invoice.php:10 |
| INJ-I-0028 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `php-plain/admin.php:12` | SQL Injection in php-plain/admin.php:12 |
| INJ-I-0029-2 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | NoSQLインジェクション (NoSQLi) |   | `php-plain/mongo_find.php:5` | NoSQL Injection in php-plain/mongo_find.php:6 |
| INJ-I-0030 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | NoSQLインジェクション (NoSQLi) |   | `php-plain/mongo_find.php:6` | NoSQL Injection in php-plain/mongo_find.php:6 |
| INJ-I-0031-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `php-plain/order_detail.php:6` | SQL Injection in php-plain/order_detail.php:6 |
| INJ-I-0032-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `php-plain/search.php:8` | SQL Injection in php-plain/search.php:7 |
| INJ-I-0032-2 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `php-plain/search.php:8` | SQL Injection in php-plain/search.php:12 |
| INJ-I-0036-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `python-flask/app.py:29` | SQL Injection in python-flask/app.py:29 |
| INJ-I-0037-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) |   | `sql-procs/sp_search_orders.sql:5` | SQL Injection in sql-procs/sp_search_orders.sql:5 |
| MASS-M-0003-1 | 緊急 (Critical) | 中 (Medium) | likely | マスアサインメント (Mass Assignment) |   | `java-legacy/src/com/acme/web/AccountController.java:14` | Unrestricted role binding in Spring MVC |
| MASS-M-0004-1 | 緊急 (Critical) | 中 (Medium) | likely | マスアサインメント (Mass Assignment) |   | `java-legacy/src/com/acme/web/AccountController.java:27` | Unrestricted role binding in Spring MVC (duplicate) |
| MASS-M-0005-1 | 緊急 (Critical) | 中 (Medium) | likely | マスアサインメント (Mass Assignment) |   | `java-legacy/src/com/acme/web/ProfileServlet.java:12` | Unrestricted role binding via BeanUtils in Java Servlet |
| BOLA-R-0001 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /user/edit.do | `java-legacy/src/com/acme/struts/EditUserAction.java:10` | BOLA in ANY /user/edit.do: missing owner verification |
| BOLA-R-0002 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /classic-asp/shop/member.asp?mode=edit | `classic-asp/shop/member.asp:6` | BOLA in ANY /classic-asp/shop/member.asp?mode=edit: missing owner verification |
| BOLA-R-0003 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /classic-asp/shop/member.asp?mode=delete | `classic-asp/shop/member.asp:9` | BOLA in ANY /classic-asp/shop/member.asp?mode=delete: missing owner verification |
| BOLA-R-0004 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /classic-asp/shop/order.asp | `classic-asp/shop/order.asp:5` | BOLA in ANY /classic-asp/shop/order.asp: missing owner verification on first query |
| BOLA-R-0005 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /coldfusion/app/OrderService.cfc?method=getOrder | `coldfusion/app/OrderService.cfc:4` | BOLA in ANY /coldfusion/app/OrderService.cfc?method=getOrder: missing owner verification |
| BOLA-R-0006 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /coldfusion/app/order.cfm | `coldfusion/app/order.cfm:2` | BOLA in ANY /coldfusion/app/order.cfm: missing owner verification on first query |
| BOLA-R-0007 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /Admin/DeleteUser | `dotnet-legacy/Web/Controllers/AdminController.cs:12` | BOLA in POST /Admin/DeleteUser: missing owner verification |
| BOLA-R-0009 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /Admin/Export | `dotnet-legacy/Web/Controllers/AdminController.cs:30` | BOLA in POST /Admin/Export: missing role check allows data exposure |
| BOLA-R-0010 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /Customer/Edit | `dotnet-legacy/Web/Controllers/CustomerController.cs:12` | BOLA in POST /Customer/Edit: missing owner verification |
| BOLA-R-0011 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /Customer/EditName | `dotnet-legacy/Web/Controllers/CustomerController.cs:20` | BOLA in POST /Customer/EditName: missing owner verification |
| BOLA-R-0012 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /Customer/Refresh | `dotnet-legacy/Web/Controllers/CustomerController.cs:27` | BOLA in POST /Customer/Refresh: missing owner verification |
| BOLA-R-0013 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /Invoice/Details | `dotnet-legacy/Web/Controllers/InvoiceController.cs:11` | BOLA in GET /Invoice/Details: missing owner verification |
| BOLA-R-0015 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /Invoice/Search | `dotnet-legacy/Web/Controllers/InvoiceController.cs:26` | BOLA in POST /Invoice/Search: missing owner verification |
| BOLA-R-0016 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /dotnet-legacy/Web/Handlers/GetFile.ashx | `dotnet-legacy/Web/Handlers/GetFile.ashx:8` | BOLA in ANY /dotnet-legacy/Web/Handlers/GetFile.ashx: missing owner verification |
| BOLA-R-0017 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /dotnet-legacy/Web/Orders/EditOrder.aspx | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` | BOLA in ANY /dotnet-legacy/Web/Orders/EditOrder.aspx.vb: missing owner verification |
| BOLA-R-0018 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /dotnet-legacy/Web/Orders/OrderDetail.aspx | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10` | BOLA in ANY /dotnet-legacy/Web/Orders/OrderDetail.aspx.cs: missing owner verification |
| BOLA-R-0019 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /java-legacy/WebContent/order/detail.jsp | `java-legacy/WebContent/order/detail.jsp:3` | BOLA in ANY /java-legacy/WebContent/order/detail.jsp: missing owner verification |
| BOLA-R-0020 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /account/save | `java-legacy/src/com/acme/web/AccountController.java:14` | BOLA in POST /account/save: missing owner verification |
| BOLA-R-0021 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /account/rename | `java-legacy/src/com/acme/web/AccountController.java:20` | BOLA in POST /account/rename: missing owner verification |
| BOLA-R-0022 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | PUT /account/api | `java-legacy/src/com/acme/web/AccountController.java:27` | BOLA in PUT /account/api: missing owner verification |
| BOLA-R-0023 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /admin/users/{id}/delete | `java-legacy/src/com/acme/web/AdminUserController.java:13` | BOLA in POST /admin/users/{id}/delete: missing owner verification |
| BOLA-R-0025 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /invoices/{id} | `java-legacy/src/com/acme/web/InvoiceController.java:15` | BOLA in GET /invoices/{id}: missing owner verification |
| BOLA-R-0027 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /invoices/search | `java-legacy/src/com/acme/web/InvoiceController.java:27` | BOLA in GET /invoices/search: missing owner verification |
| BOLA-R-0028 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /order/view | `java-legacy/src/com/acme/web/OrderServlet.java:11` | BOLA in GET /order/view: missing owner verification |
| BOLA-R-0029 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST <see web.xml servlet-mapping> | `java-legacy/src/com/acme/web/ProfileServlet.java:9` | BOLA in POST /ProfileServlet: missing owner verification |
| BOLA-R-0030 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /admin/users/:id/delete | `node-express/routes/admin.js:8` | BOLA in POST /admin/users/:id/delete: missing owner verification |
| BOLA-R-0033 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /orders/:id | `node-express/routes/orders.js:8` | BOLA in GET /orders/:id: missing owner verification |
| BOLA-R-0038 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /stats | `node-express/routes/orders.js:28` | BOLA in GET /stats: missing owner verification |
| BOLA-R-0043 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /perl-cgi/cgi-bin/order.cgi | `perl-cgi/cgi-bin/order.cgi:13` | BOLA in ANY /perl-cgi/cgi-bin/order.cgi: missing owner verification |
| BOLA-R-0044 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /invoice/view/{id} | `php-codeigniter/application/controllers/Invoice.php:10` | BOLA in ANY /invoice/view/{id}: missing owner verification |
| BOLA-R-0046 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /invoice/update | `php-codeigniter/application/controllers/Invoice.php:23` | BOLA in ANY /invoice/update: missing owner verification |
| BOLA-R-0057-1 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /php-plain/admin.php?action=view | `php-plain/admin.php:8` | BOLA in GET /php-plain/admin.php?action=view: missing admin authorization |
| BOLA-R-0057-2 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /php-plain/admin.php?action=delete | `php-plain/admin.php:6` | BOLA in POST /php-plain/admin.php?action=delete: missing admin authorization |
| BOLA-R-0058-1 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /php-plain/admin.php?action=view | `php-plain/admin.php:10` | BOLA in GET /php-plain/admin.php?action=view: missing admin authorization |
| BOLA-R-0058-2 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /php-plain/admin.php?action=delete | `php-plain/admin.php:12` | BOLA in POST /php-plain/admin.php?action=delete: missing admin authorization |
| BOLA-R-0059-1 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /php-plain/manage_users.php | `php-plain/manage_users.php:6` | BOLA in POST /php-plain/manage_users.php: missing admin authorization |
| BOLA-R-0061-1 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /php-plain/order_detail.php | `php-plain/order_detail.php:6` | BOLA in GET /php-plain/order_detail.php: missing ownership verification |
| BOLA-R-0066-1 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /php-plain/admin/delete_user.php | `php-plain/admin/delete_user.php:6` | BOLA in POST /php-plain/admin/delete_user.php: missing admin authorization |
| BOLA-R-0067-1 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /php-plain/admin/promote.php | `php-plain/admin/promote.php:6` | BOLA in POST /php-plain/admin/promote.php: missing admin authorization |
| BOLA-R-0069-1 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /orders/<int:order_id> | `python-flask/app.py:12` | BOLA in GET /orders/<int:order_id>: missing ownership verification |
| BOLA-R-0073 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /users/<int:uid>/name | `python-flask/profile.py:16` | BOLA in POST /users/<uid>/name: missing owner verification |
| BOLA-R-0074 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | PATCH /users/<int:uid> | `python-flask/profile.py:24` | BOLA in PATCH /users/<uid>: missing owner verification |
| MASS-M-0009-1 | 高 (High) | 中 (Medium) | likely | マスアサインメント (Mass Assignment) |   | `php-laravel/app/Http/Controllers/AccountController.php:23` | Team creation allows owner_id to be set by any user |
| MASS-M-0006-1 | 中 (Medium) | 中 (Medium) | likely | マスアサインメント (Mass Assignment) |   | `node-express/routes/profile.js:8` | Profile update binds entire request body to User model |
| MASS-M-0007-1 | 中 (Medium) | 中 (Medium) | likely | マスアサインメント (Mass Assignment) |   | `node-express/routes/profile.js:16` | Profile update binds entire request body to User model |
| MASS-M-0008-1 | 中 (Medium) | 中 (Medium) | likely | マスアサインメント (Mass Assignment) |   | `php-laravel/app/Http/Controllers/AccountController.php:13` | User registration binds entire request body to User model |
| MASS-M-0010-1 | 中 (Medium) | 中 (Medium) | likely | マスアサインメント (Mass Assignment) |   | `php-laravel/app/Http/Controllers/AccountController.php:36` | Team creation binds entire request body to Team model |
| MASS-M-0014-1 | 中 (Medium) | 中 (Medium) | likely | マスアサインメント (Mass Assignment) |   | `python-flask/profile.py:10` | User creation binds entire request JSON to User model |
| MASS-M-0015-1 | 中 (Medium) | 中 (Medium) | likely | マスアサインメント (Mass Assignment) |   | `python-flask/profile.py:27` | PATCH endpoint sets arbitrary attributes from request JSON |

### BFLA-R-0003-1 — Unrestricted member deletion in classic‑ASP

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** 機能レベルの認可不備 (BFLA) (missing_role_check) — CWE-285   
- **対象エンドポイント:** - -  
- **該当箇所:** `classic-asp/shop/member.asp:9`

**影響度 (Impact):** Any authenticated user can delete any member record

**脆弱性の根拠コード (Evidence):**

- `classic-asp/shop/member.asp:10` — DELETE statement executed without admin check
- `classic-asp/shop/member.asp:1` — only session login check, no role verification

**推奨対策 (Recommendation):** Add an admin role check before executing the DELETE

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: classic-asp/shop/member.asp:1-10, classic-asp/shop/inc/auth.asp:1-3. The included auth.asp only verifies a logged‑in session; it does not enforce an admin role. The delete case uses the member_id from the query string without any role check.

### BFLA-R-0007-1 — Unrestricted user deletion in ASP.NET MVC

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** 機能レベルの認可不備 (BFLA) (missing_role_check) — CWE-285   
- **対象エンドポイント:** - -  
- **該当箇所:** `dotnet-legacy/Web/Controllers/AdminController.cs:12`

**影響度 (Impact):** Any authenticated user can delete any user account

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Controllers/AdminController.cs:12` — DeleteUser action lacks [Authorize(Roles="Admin")]

**推奨対策 (Recommendation):** Add [Authorize(Roles="Admin")] to DeleteUser action

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: dotnet-legacy/Web/Controllers/AdminController.cs:6-12. The controller is marked with [Authorize], allowing any authenticated user. The DeleteUser action lacks a role restriction, so any authenticated user can delete any account.

### BFLA-R-0009-1 — Export endpoint controlled by request parameter

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** 機能レベルの認可不備 (BFLA) (role_from_request) — CWE-285   
- **対象エンドポイント:** - -  
- **該当箇所:** `dotnet-legacy/Web/Controllers/AdminController.cs:30`

**影響度 (Impact):** Any authenticated user can export all user data

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Controllers/AdminController.cs:32` — Request.QueryString["isAdmin"] == "true" allows export
- `dotnet-legacy/Web/Controllers/AdminController.cs:30` — no server‑side role check

**推奨対策 (Recommendation):** Validate admin role from session before allowing export

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: dotnet-legacy/Web/Controllers/AdminController.cs:30-34. Export logic relies solely on a request query string parameter. No server‑side role validation is performed, allowing any authenticated user to trigger the export.

### BFLA-R-0023-1 — Unrestricted user deletion in Spring MVC

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** 機能レベルの認可不備 (BFLA) (missing_role_check) — CWE-285   
- **対象エンドポイント:** - -  
- **該当箇所:** `java-legacy/src/com/acme/web/AdminUserController.java:13`

**影響度 (Impact):** Any authenticated user can delete any user

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/AdminUserController.java:13` — delete method lacks @PreAuthorize
- `java-legacy/src/com/acme/web/AdminUserController.java:19` — other actions have @PreAuthorize, but not this one

**推奨対策 (Recommendation):** Add @PreAuthorize("hasRole('ADMIN')") to delete method

*検証結果 (Verifier):* likely — 確認対象: java-legacy/src/com/acme/web/AdminUserController.java lines 13-15, java-legacy/src/com/acme/web/AdminUserController.java lines 19-21. The delete method lacks any @PreAuthorize or other role guard in the visible code. No global filter or security configuration is shown in the provided context, so a compensating control cannot be confirmed.

### BFLA-R-0030-1 — Unrestricted user deletion in Express.js

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** 機能レベルの認可不備 (BFLA) (missing_role_check) — CWE-285   
- **対象エンドポイント:** - -  
- **該当箇所:** `node-express/routes/admin.js:8`

**影響度 (Impact):** Any authenticated user can delete any user

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/admin.js:8` — no requireAdmin middleware applied

**推奨対策 (Recommendation):** Add requireAdmin middleware to the delete route

*検証結果 (Verifier):* likely — 確認対象: node-express/routes/admin.js lines 8-9. The delete route uses only ensureLoggedIn; the requireAdmin middleware is not applied in the visible snippet, and no other role check is present.

### BFLA-R-0032-1 — Export endpoint controlled by query parameter in Express.js

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** 機能レベルの認可不備 (BFLA) (role_from_request) — CWE-285   
- **対象エンドポイント:** - -  
- **該当箇所:** `node-express/routes/admin.js:16`

**影響度 (Impact):** Any authenticated user can export all user data

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/admin.js:17` — req.query.isAdmin === 'true' allows export
- `node-express/routes/admin.js:16` — no role check before export

**推奨対策 (Recommendation):** Validate admin role from session before allowing export

*検証結果 (Verifier):* likely — 確認対象: node-express/routes/admin.js lines 16-18. The export endpoint checks only a query parameter for admin status; no session‑based role verification is shown in the snippet.

### BFLA-R-0057-1 — Unrestricted user view in PHP

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** 機能レベルの認可不備 (BFLA) (missing_role_check) — CWE-285   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-plain/admin.php:6`

**影響度 (Impact):** Any authenticated user can view any user record

**脆弱性の根拠コード (Evidence):**

- `php-plain/admin.php:6` — SELECT * FROM users WHERE id = ... executed without admin check
- `php-plain/admin.php:2` — only session login check, no role verification

**推奨対策 (Recommendation):** Add admin role check before executing the SELECT

*検証結果 (Verifier):* likely — 確認対象: php-plain/admin.php lines 2-8, php-plain/inc/auth.php lines 1-7. The included auth file performs only a login check; there is no admin role guard before the SELECT statement in the visible code.

### BFLA-R-0058-1 — Unrestricted user deletion in PHP

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** 機能レベルの認可不備 (BFLA) (missing_role_check) — CWE-285   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-plain/admin.php:10`

**影響度 (Impact):** Any authenticated user can delete any user record

**脆弱性の根拠コード (Evidence):**

- `php-plain/admin.php:10` — DELETE executed without admin check
- `php-plain/admin.php:2` — only session login check, no role verification

**推奨対策 (Recommendation):** Add admin role check before executing the DELETE

*検証結果 (Verifier):* likely — 確認対象: php-plain/admin.php lines 10-12, php-plain/inc/auth.php lines 1-7. The DELETE statement is executed without any admin role check in the visible code, and the included auth file does not provide such a guard.

### BFLA-R-0059-1 — Client‑side admin check allows user deletion in PHP

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** 機能レベルの認可不備 (BFLA) (client_side_role_check) — CWE-285   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-plain/manage_users.php:1`

**影響度 (Impact):** Any authenticated user can delete any user record

**脆弱性の根拠コード (Evidence):**

- `php-plain/manage_users.php:5` — DELETE executed without server‑side admin check
- `php-plain/manage_users.php:11` — role check only in HTML, not in handler

**推奨対策 (Recommendation):** Add server‑side admin check before executing the DELETE

*検証結果 (Verifier):* likely — 確認対象: php-plain/manage_users.php, php-plain/inc/auth.php, php-plain/inc/db.php. Deletion is performed on POST without a server‑side role check; the role check appears only in the HTML output.

### BFLA-R-0063-1 — Privilege escalation via role field in profile update

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** 機能レベルの認可不備 (BFLA) (role_from_request) — CWE-285   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-plain/profile.php:1`

**影響度 (Impact):** Any authenticated user can change their own role

**脆弱性の根拠コード (Evidence):**

- `php-plain/profile.php:10` — role set from $_POST['role'] without admin check
- `php-plain/profile.php:2` — only session login check, no role verification

**推奨対策 (Recommendation):** Validate role changes against allowed values and enforce admin checks

*検証結果 (Verifier):* likely — 確認対象: php-plain/profile.php, php-plain/inc/auth.php, php-plain/inc/db.php. The role field is updated directly from POST data with no admin verification in the visible code.

### BFLA-R-0066-1 — Unrestricted user deletion in PHP

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** 機能レベルの認可不備 (BFLA) (missing_role_check) — CWE-285   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-plain/admin/delete_user.php:1`

**影響度 (Impact):** Any authenticated user can delete any user record

**脆弱性の根拠コード (Evidence):**

- `php-plain/admin/delete_user.php:6` — DELETE executed without admin check
- `php-plain/admin/delete_user.php:2` — only session login check, no role verification

**推奨対策 (Recommendation):** Add admin role check before executing the DELETE

*検証結果 (Verifier):* likely — 確認対象: php-plain/admin/delete_user.php, php-plain/inc/auth.php, php-plain/inc/db.php. No role or ownership check is present in the visible code. The included auth file only verifies session existence.

### BFLA-R-0067-1 — Privilege escalation via role promotion in PHP

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** 機能レベルの認可不備 (BFLA) (role_from_request) — CWE-285   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-plain/admin/promote.php:1`

**影響度 (Impact):** Any authenticated user can promote themselves to admin

**脆弱性の根拠コード (Evidence):**

- `php-plain/admin/promote.php:5` — role set from $_POST['is_admin'] without admin check
- `php-plain/admin/promote.php:2` — only session login check, no role verification

**推奨対策 (Recommendation):** Validate admin role from session before allowing role changes

*検証結果 (Verifier):* likely — 確認対象: php-plain/admin/promote.php, php-plain/inc/auth.php, php-plain/inc/db.php. The code sets the role directly from POST data without any server‑side admin check. No compensating control is visible.

### INJ-I-0001 — SQL Injection in classic-asp/shop/member.asp:6

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `classic-asp/shop/member.asp:6`

**脆弱性の根拠コード (Evidence):**

- `classic-asp/shop/member.asp:6` — Unsanitized input concatenated into query (member_id later)  
  `sql = "UPDATE members SET name = '" & Replace(Request.Form("name"), "'", "''") & "'"`
- `classic-asp/shop/member.asp:7` — Unsanitized input concatenated into query  
  `sql = sql & " WHERE member_id = " & Request.Form("member_id")`
- `classic-asp/shop/member.asp:8` — Query executed without parameter binding  
  `conn.Execute sql`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: classic-asp/shop/member.asp:6-8, classic-asp/shop/inc/auth.asp:1-3. The SQL UPDATE statement is built via string concatenation with unsanitized form values. The included auth.asp only verifies that a user is logged in; it does not provide parameter binding or sanitization.

### INJ-I-0002 — SQL Injection in classic-asp/shop/member.asp:7

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `classic-asp/shop/member.asp:7`

**脆弱性の根拠コード (Evidence):**

- `classic-asp/shop/member.asp:7` — Unsanitized input concatenated into query  
  `sql = sql & " WHERE member_id = " & Request.Form("member_id")`
- `classic-asp/shop/member.asp:8` — Query executed without parameter binding  
  `conn.Execute sql`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: classic-asp/shop/member.asp:7-8, classic-asp/shop/inc/auth.asp:1-3. The WHERE clause is concatenated with an unsanitized form value. No parameter binding or integer cast is present.

### INJ-I-0003 — SQL Injection in classic-asp/shop/member.asp:10

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `classic-asp/shop/member.asp:10`

**脆弱性の根拠コード (Evidence):**

- `classic-asp/shop/member.asp:10` — Unsanitized input concatenated into query  
  `conn.Execute "DELETE FROM members WHERE member_id = " & Request.QueryString("member_id")`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: classic-asp/shop/member.asp:10, classic-asp/shop/inc/auth.asp:1-3. The DELETE statement concatenates an unsanitized query string value. No sanitization or parameter binding is visible.

### INJ-I-0004 — SQL Injection in classic-asp/shop/order.asp:6

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `classic-asp/shop/order.asp:6`

**脆弱性の根拠コード (Evidence):**

- `classic-asp/shop/order.asp:6` — Unsanitized input concatenated into query  
  `Set rs = conn.Execute("SELECT * FROM orders WHERE id = " & id)`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: classic-asp/shop/order.asp lines 5-6, classic-asp/shop/order.asp line 12. The query at line 6 concatenates the unsanitized request parameter directly into the SQL statement. No ownership check or parameter binding is performed before execution. The subsequent query at line 12 includes a user_id filter, but it does not mitigate the vulnerability in the first query.

### INJ-I-0006 — SQL Injection in coldfusion/app/OrderService.cfc:5

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `coldfusion/app/OrderService.cfc:5`

**脆弱性の根拠コード (Evidence):**

- `coldfusion/app/OrderService.cfc:5` — Unsanitized input concatenated into query  
  `SELECT * FROM orders WHERE id = #arguments.orderId#`

**推奨対策 (Recommendation):** Use cfqueryparam to bind parameters

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: coldfusion/app/OrderService.cfc lines 3-6. The query at line 5 directly interpolates the unvalidated argument `orderId` into the SQL string. No parameter binding, type casting, or ownership check is present.

### INJ-I-0007 — SQL Injection in coldfusion/app/order.cfm:3

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `coldfusion/app/order.cfm:3`

**脆弱性の根拠コード (Evidence):**

- `coldfusion/app/order.cfm:3` — Unsanitized input concatenated into query  
  `SELECT * FROM orders WHERE id = #url.id#`

**推奨対策 (Recommendation):** Use cfqueryparam to bind parameters

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: coldfusion/app/order.cfm lines 2-4. The query at line 3 concatenates the unsanitized `url.id` into the SQL statement. Although a subsequent query uses `cfqueryparam` and a user_id filter, the first query remains vulnerable.

### INJ-I-0008-1 — SQL Injection in dotnet-legacy/Web/Controllers/InvoiceController.cs:28

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:28`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:27` — source: POST body  
  `var customer = Request.Form["customer"];`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` — unsanitized concatenation  
  `var list = db.Database.SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = '" + customer + "'").ToList();`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* likely — 確認対象: dotnet-legacy/Web/Controllers/InvoiceController.cs lines 25-29 (Search action). No parameter binding, casting, or allow‑list is visible in the provided code context. The raw concatenation of `customer` into the SQL string remains a potential injection vector.

### INJ-I-0009 — SQL Injection in dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` — Unsanitized input concatenated into query  
  `Dim sql As String = "UPDATE Orders SET Note = '" & txtNote.Text & "'"`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` — Unsanitized input concatenated into query  
  `sql &= " WHERE OrderId = " & hfOrderId.Value`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:10` — Query executed without parameter binding  
  `cmd.ExecuteNonQuery()`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: dotnet-legacy/Web/Orders/EditOrder.aspx.vb lines 6-8. The SQL string is built by concatenating `txtNote.Text` and `hfOrderId.Value` without any parameterization or type casting. No ownership check is performed before execution.

### INJ-I-0010 — SQL Injection in dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` — Unsanitized input concatenated into query  
  `sql &= " WHERE OrderId = " & hfOrderId.Value`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:10` — Query executed without parameter binding  
  `cmd.ExecuteNonQuery()`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: dotnet-legacy/Web/Orders/EditOrder.aspx.vb lines 7-8. Same as INJ-I-0009: the query is constructed via string concatenation with user-supplied values and executed without parameter binding or ownership validation.

### INJ-I-0011-1 — SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` — Unsanitized input concatenated into query  
  `var cmd = new SqlCommand("SELECT * FROM Orders WHERE OrderId = " + id, conn);`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:14` — Query executed without parameter binding  
  `conn.Open();`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: line 13. The query at line 13 concatenates the unsanitized request parameter "id" directly into the SQL string and is executed immediately. No ownership, role check, integer cast, or allow‑list is present in the visible code.

### INJ-I-0011-3 — SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20` — Unsanitized input concatenated into query  
  `string sql3 = $"DELETE FROM Carts WHERE CartId = {Request.Form["cart"]}";`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:22` — Query executed without parameter binding  
  `new SqlCommand(sql3, conn).ExecuteNonQuery();`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: line 20. The interpolated string at line 20 directly injects the unsanitized form parameter "cart" into a DELETE statement, executed at line 22. No protection is evident.

### INJ-I-0012 — SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19` — Unsanitized input concatenated into query  
  `string sql2 = string.Format("SELECT * FROM Logs WHERE Ref = '{0}'", Request["ref"]);`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:21` — Query executed without parameter binding  
  `new SqlCommand(sql2, conn).ExecuteReader();`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: line 19. Same as INJ-I-0011-2: unsanitized "ref" is concatenated into SQL and executed without parameter binding.

### INJ-I-0013 — SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20` — Unsanitized input concatenated into query  
  `string sql3 = $"DELETE FROM Carts WHERE CartId = {Request.Form["cart"]}";`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:22` — Query executed without parameter binding  
  `new SqlCommand(sql3, conn).ExecuteNonQuery();`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: line 20. Duplicate finding ID; same issue as INJ-I-0011-3.

### INJ-I-0014 — SQL Injection in java-legacy/WebContent/order/detail.jsp:5

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `java-legacy/WebContent/order/detail.jsp:5`

**脆弱性の根拠コード (Evidence):**

- `java-legacy/WebContent/order/detail.jsp:5` — Unsanitized input concatenated into query  
  `ResultSet rs = c.createStatement().executeQuery("SELECT * FROM orders WHERE order_no = '" + no + "'");`

**推奨対策 (Recommendation):** Use PreparedStatement with parameters

*検証結果 (Verifier):* likely — 確認対象: java-legacy/WebContent/order/detail.jsp lines 1-7. The JSP page concatenates the request parameter directly into a SQL query without any parameter binding, casting, or ownership check visible in the provided code context.

### INJ-I-0015-1 — SQL Injection in java-legacy/src/com/acme/mapper/OrderMapper.xml:9

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** SQLインジェクション (SQLi) (template_placeholder) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `java-legacy/src/com/acme/mapper/OrderMapper.xml:9`

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/mapper/OrderMapper.xml:9` — raw string substitution unsanitized  
  `ORDER BY ${orderBy}`

**推奨対策 (Recommendation):** Use parameterized queries or allow-list ORDER BY columns

*検証結果 (Verifier):* likely — 確認対象: java-legacy/src/com/acme/mapper/OrderMapper.xml lines 8-10 (ORDER BY clause). The `${orderBy}` placeholder is substituted directly into the SQL string with no visible allow‑list or type enforcement in the provided snippet.

### INJ-I-0016 — SQL Injection in java-legacy/src/com/acme/struts/EditUserAction.java:13

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `java-legacy/src/com/acme/struts/EditUserAction.java:13`

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/struts/EditUserAction.java:13` — Unsanitized input concatenated into query  
  `PreparedStatement ps = conn.prepareStatement("UPDATE users SET email = '" + email + "' WHERE id = " + userId);`
- `java-legacy/src/com/acme/struts/EditUserAction.java:14` — Query executed without parameter binding  
  `ps.executeUpdate();`

**推奨対策 (Recommendation):** Use PreparedStatement with parameters

*検証結果 (Verifier):* likely — 確認対象: java-legacy/src/com/acme/struts/EditUserAction.java lines 1-17. The action builds an UPDATE statement by concatenating user-supplied values without using prepared statement parameters or any ownership verification in the visible code.

### INJ-I-0017 — SQL Injection in java-legacy/src/com/acme/web/InvoiceController.java:29

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `java-legacy/src/com/acme/web/InvoiceController.java:29`

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/InvoiceController.java:29` — Unsanitized input concatenated into query  
  `model.addAttribute("list", session.createQuery("from Invoice i where i.customer = '" + customer + "'").list());`

**推奨対策 (Recommendation):** Use parameterized HQL/JPQL

*検証結果 (Verifier):* likely — 確認対象: java-legacy/src/com/acme/web/InvoiceController.java lines 9-31. The controller concatenates the 'customer' request parameter into an HQL query without parameter binding or ownership checks in the shown snippet.

### INJ-I-0018-1 — SQL Injection in java-legacy/src/com/acme/web/OrderServlet.java:15

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `java-legacy/src/com/acme/web/OrderServlet.java:15`

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/OrderServlet.java:11` — source: request parameter  
  `String id = request.getParameter("orderId");`
- `java-legacy/src/com/acme/web/OrderServlet.java:15` — unsanitized concatenation  
  `ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = '" + id + "'");`

**推奨対策 (Recommendation):** Use prepared statements

*検証結果 (Verifier):* likely — 確認対象: java-legacy/src/com/acme/web/OrderServlet.java lines 13-15 (first query). The `id` parameter is concatenated into the SQL string without any casting or validation in the shown code.

### INJ-I-0020-1 — SQL Injection in node-express/routes/orders.js:17

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `node-express/routes/orders.js:17`

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:17` — Unsanitized input concatenated into query  
  `db.query("SELECT * FROM reports WHERE month = '" + req.query.month + "'", function (e, rows) { res.json(rows); });`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* likely — 確認対象: node-express/routes/orders.js lines 1-32. The route constructs a raw SQL query by concatenating req.query.month without any type casting, parameter binding, or ownership verification in the visible code.

### INJ-I-0020-3 — NoSQL Injection in node-express/routes/orders.js:25

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** NoSQLインジェクション (NoSQLi) (operator_injection) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `node-express/routes/orders.js:17`

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:25` — Unescaped string used in $where expression  
  `db.collection('items').find({ $where: "this.name == '" + req.query.n + "'" }).toArray(function (e, r) { res.json(r); });`

**推奨対策 (Recommendation):** Avoid $where; use parameterized queries or safe operators

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: lines 24-26 of node-express/routes/orders.js. The query concatenates user input into a $where expression with no sanitization or allow‑list. The only guard is ensureLoggedIn, which only verifies authentication, not ownership or input validation.

### INJ-I-0020-4 — SQL Injection in node-express/routes/orders.js:29

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `node-express/routes/orders.js:17`

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:29` — Unsanitized input interpolated into query  
  `db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}', function (e, r) { res.json(r); });`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: lines 28-30 of node-express/routes/orders.js. The SQL statement interpolates req.query.shop directly into the query string. No cast, parameter binding, or ownership check is present.

### INJ-I-0021 — SQL Injection in node-express/routes/orders.js:29

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `node-express/routes/orders.js:29`

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:29` — Unsanitized input interpolated into query  
  `db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}', function (e, r) { res.json(r); });`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: lines 28-30 of node-express/routes/orders.js. Same as INJ-I-0020-4; the route is identical and lacks any compensating control.

### INJ-I-0022 — NoSQL Injection in node-express/routes/orders.js:21

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** NoSQLインジェクション (NoSQLi) (operator_injection) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `node-express/routes/orders.js:21`

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:21` — Unvalidated request body used directly as query filter  
  `db.collection('users').findOne(req.body, function (e, u) { res.json(!!u); });`

**推奨対策 (Recommendation):** Validate and whitelist query parameters; avoid passing raw request body to findOne

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: lines 20-22 of node-express/routes/orders.js. The request body is passed directly to findOne without validation or sanitization. No authentication guard is applied to this POST /login route.

### INJ-I-0023 — NoSQL Injection in node-express/routes/orders.js:25

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** NoSQLインジェクション (NoSQLi) (operator_injection) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `node-express/routes/orders.js:25`

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:25` — Unescaped string used in $where expression  
  `db.collection('items').find({ $where: "this.name == '" + req.query.n + "'" }).toArray(function (e, r) { res.json(r); });`

**推奨対策 (Recommendation):** Avoid $where; use parameterized queries or safe operators

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: lines 24-26 of node-express/routes/orders.js. Identical to INJ-I-0020-3; no sanitization or allow‑list is present.

### INJ-I-0024-1 — SQL Injection in perl-cgi/cgi-bin/order.cgi:13

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `perl-cgi/cgi-bin/order.cgi:13`

**脆弱性の根拠コード (Evidence):**

- `perl-cgi/cgi-bin/order.cgi:13` — Unsanitized input concatenated into query  
  `my $sth = $dbh->prepare("SELECT * FROM orders WHERE id = $id");`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: perl-cgi/cgi-bin/order.cgi line 13, perl-cgi/cgi-bin/order.cgi line 11-14. The query concatenates the unsanitized $id directly into the SQL string. No integer cast, parameter binding, or ownership check is present in the visible code.

### INJ-I-0025 — SQL Injection in perl-cgi/cgi-bin/order.cgi:19

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `perl-cgi/cgi-bin/order.cgi:19`

**脆弱性の根拠コード (Evidence):**

- `perl-cgi/cgi-bin/order.cgi:19` — Unsanitized input concatenated into query  
  `$dbh->do("DELETE FROM carts WHERE cart_id = " . $q->param('cart'));`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: perl-cgi/cgi-bin/order.cgi line 19, perl-cgi/cgi-bin/order.cgi line 18-20. Same as INJ-I-0024-2; unsanitized input used in a DELETE statement with no protection.

### INJ-I-0026-1 — SQL Injection in php-codeigniter/application/controllers/Invoice.php:10

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-codeigniter/application/controllers/Invoice.php:10`

**脆弱性の根拠コード (Evidence):**

- `php-codeigniter/application/controllers/Invoice.php:9` — source: URL segment  
  `$id = $this->uri->segment(3);`
- `php-codeigniter/application/controllers/Invoice.php:10` — unsanitized concatenation  
  `$q = $this->db->query("SELECT * FROM invoices WHERE id = $id");`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: php-codeigniter/application/controllers/Invoice.php:9-10. The query concatenates the raw $id parameter without any sanitization, casting, or parameter binding. No ownership or role check is present in the visible code.

### INJ-I-0028 — SQL Injection in php-plain/admin.php:12

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-plain/admin.php:12`

**脆弱性の根拠コード (Evidence):**

- `php-plain/admin.php:12` — Unsanitized input concatenated into query  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: php-plain/admin.php line 12, php-plain/admin.php lines 5-13. The DELETE query uses the raw $_POST['id'] value. No cast, parameter binding, or ownership check is present. The included auth.php only verifies login, not admin role.

### INJ-I-0029-2 — NoSQL Injection in php-plain/mongo_find.php:6

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** NoSQLインジェクション (NoSQLi) (operator_injection) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-plain/mongo_find.php:5`

**脆弱性の根拠コード (Evidence):**

- `php-plain/mongo_find.php:6` — Unescaped string used in $where expression  
  `$docs = $coll->find(array('$where' => "this.name == '" . $_GET['n'] . "'"));`

**推奨対策 (Recommendation):** Avoid $where; use parameterized queries or safe operators

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: php-plain/mongo_find.php line 6, php-plain/mongo_find.php lines 1-6. The $where expression concatenates the unsanitized $_GET['n'] value. No sanitization or ownership check is visible.

### INJ-I-0030 — NoSQL Injection in php-plain/mongo_find.php:6

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** NoSQLインジェクション (NoSQLi) (operator_injection) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-plain/mongo_find.php:6`

**脆弱性の根拠コード (Evidence):**

- `php-plain/mongo_find.php:6` — Unescaped string used in $where expression  
  `$docs = $coll->find(array('$where' => "this.name == '" . $_GET['n'] . "'"));`

**推奨対策 (Recommendation):** Avoid $where; use parameterized queries or safe operators

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: php-plain/mongo_find.php, php-plain/inc/auth.php. The query concatenates user input into a $where expression with no sanitisation or ownership check. The included auth file only verifies login, not object ownership.

### INJ-I-0031-1 — SQL Injection in php-plain/order_detail.php:6

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-plain/order_detail.php:6`

**脆弱性の根拠コード (Evidence):**

- `php-plain/order_detail.php:5` — source: GET parameter  
  `$id = $_GET['id'];`
- `php-plain/order_detail.php:6` — unsanitized input concatenated into query  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: php-plain/order_detail.php, php-plain/inc/auth.php. The SQL statement concatenates the GET id directly. No ownership or role guard is present in the visible code.

### INJ-I-0032-1 — SQL Injection in php-plain/search.php:7

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-plain/search.php:8`

**脆弱性の根拠コード (Evidence):**

- `php-plain/search.php:5` — source: GET parameter  
  `$kw = addslashes($_GET['q']);`
- `php-plain/search.php:6` — source: GET parameter  
  `$sort = $_GET['sort'];`
- `php-plain/search.php:7` — query start  
  `$sql = "SELECT id, name FROM products WHERE 1=1";`
- `php-plain/search.php:8` — unsanitized input concatenated  
  `$sql .= " AND name LIKE '%" . $kw . "%'";`
- `php-plain/search.php:9` — unsanitized ORDER BY  
  `$sql .= " ORDER BY " . $sort;`
- `php-plain/search.php:11` — sink  
  `$res = mysql_query($sql);`

**推奨対策 (Recommendation):** Use parameterized queries and allow-list ORDER BY

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: php-plain/search.php, php-plain/inc/auth.php, php-plain/inc/db.php. Both the keyword and ORDER BY values are unsanitised and no allow‑list or ownership check is visible.

### INJ-I-0032-2 — SQL Injection in php-plain/search.php:12

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-plain/search.php:8`

**脆弱性の根拠コード (Evidence):**

- `php-plain/search.php:14` — unsanitized interpolation  
  `WHERE category = '{$_GET['cat']}'`
- `php-plain/search.php:16` — sink  
  `$res2 = mysql_query($q);`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: php-plain/search.php, php-plain/inc/auth.php, php-plain/inc/db.php. The interpolated category value is used directly in the query with no sanitisation or ownership guard.

### INJ-I-0036-1 — SQL Injection in python-flask/app.py:29

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `python-flask/app.py:29`

**脆弱性の根拠コード (Evidence):**

- `python-flask/app.py:27` — source: query parameter  
  `q = request.args.get('q', '')`
- `python-flask/app.py:29` — unsanitized interpolation  
  `cur.execute(f"SELECT * FROM products WHERE name LIKE '%{q}%'")`

**推奨対策 (Recommendation):** Use parameterized queries

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: python-flask/app.py. The f‑string interpolates the query parameter directly into the SQL. The @login_required decorator only ensures authentication, not ownership or parameter validation.

### INJ-I-0037-1 — SQL Injection in sql-procs/sp_search_orders.sql:5

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (stored_procedure_dynamic_sql) — CWE-89   
- **対象エンドポイント:** - -  
- **該当箇所:** `sql-procs/sp_search_orders.sql:5`

**脆弱性の根拠コード (Evidence):**

- `sql-procs/sp_search_orders.sql:5` — unsanitized dynamic SQL  
  `SET @sql = 'SELECT * FROM Orders WHERE Customer = ''' + @Customer + ''' ORDER BY ' + @Sort`
- `sql-procs/sp_search_orders.sql:6` — sink  
  `EXEC(@sql)`

**推奨対策 (Recommendation):** Use sp_executesql with parameters

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: sql-procs/sp_search_orders.sql:5-6. Dynamic SQL is built by concatenating @Customer and @Sort directly into the statement. No allow‑list, integer cast, or parameterized execution is visible.

### MASS-M-0003-1 — Unrestricted role binding in Spring MVC

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** マスアサインメント (Mass Assignment) (privileged_field_writable) — CWE-915   
- **対象エンドポイント:** - -  
- **該当箇所:** `java-legacy/src/com/acme/web/AccountController.java:14`

**影響度 (Impact):** Any authenticated user can set the role field of an Account

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/AccountController.java:14` — Location taken from the Tier 1 inventory

**推奨対策 (Recommendation):** Bind only allowed fields or set role server‑side

*検証結果 (Verifier):* likely — 確認対象: java-legacy/src/com/acme/web/AccountController.java. The controller accepts a full Account model via @ModelAttribute and persists it without any field‑level binding or role restrictions shown.

### MASS-M-0004-1 — Unrestricted role binding in Spring MVC (duplicate)

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** マスアサインメント (Mass Assignment) (privileged_field_writable) — CWE-915   
- **対象エンドポイント:** - -  
- **該当箇所:** `java-legacy/src/com/acme/web/AccountController.java:27`

**影響度 (Impact):** Any authenticated user can set the role field of an Account

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/AccountController.java:27` — Location taken from the Tier 1 inventory

**推奨対策 (Recommendation):** Bind only allowed fields or set role server‑side

*検証結果 (Verifier):* likely — 確認対象: AccountController.update method (lines 13-28), AccountDao.save invocation. No ownership or role check, no allow‑list, and no type cast is visible in the provided code context.

### MASS-M-0005-1 — Unrestricted role binding via BeanUtils in Java Servlet

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** マスアサインメント (Mass Assignment) (privileged_field_writable) — CWE-915   
- **対象エンドポイント:** - -  
- **該当箇所:** `java-legacy/src/com/acme/web/ProfileServlet.java:12`

**影響度 (Impact):** Any authenticated user can set the role field of an Account

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/ProfileServlet.java:12` — BeanUtils.populate binds all request parameters including role
- `java-legacy/src/com/acme/web/ProfileServlet.java:10` — no field filtering or role check

**推奨対策 (Recommendation):** Bind only allowed fields or set role server‑side

*検証結果 (Verifier):* likely — 確認対象: ProfileServlet.doPost method (lines 9-16), BeanUtils.populate usage. The code shows direct population of all request parameters into the Account object with no filtering or role enforcement.

### BOLA-R-0001 — BOLA in ANY /user/edit.do: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** ANY /user/edit.do  
- **該当箇所:** `java-legacy/src/com/acme/struts/EditUserAction.java:10`

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/struts/EditUserAction.java:10` — ID from request  
  `String userId = request.getParameter("user_id");`
- `java-legacy/src/com/acme/struts/EditUserAction.java:13` — Query does not bind to user_id  
  `PreparedStatement ps = conn.prepareStatement("UPDATE users SET email = '" + email + "' WHERE id = " + userId);`

**推奨対策 (Recommendation):** Verify user ownership before update

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: java-legacy/src/com/acme/struts/EditUserAction.java. The UPDATE statement uses the user_id from the request without any ownership verification or parameter binding.

### BOLA-R-0002 — BOLA in ANY /classic-asp/shop/member.asp?mode=edit: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** ANY /classic-asp/shop/member.asp?mode=edit  
- **該当箇所:** `classic-asp/shop/member.asp:6`

**脆弱性の根拠コード (Evidence):**

- `classic-asp/shop/member.asp:6` — ID from request, no ownership check  
  `sql = "UPDATE members SET name = '" & Replace(Request.Form("name"), "'", "''") & "'"`
- `classic-asp/shop/member.asp:7` — ID from request, no ownership check  
  `sql = sql & " WHERE member_id = " & Request.Form("member_id")`
- `classic-asp/shop/member.asp:8` — Executes query without owner check  
  `conn.Execute sql`

**推奨対策 (Recommendation):** Bind query to current session user

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: classic-asp/shop/member.asp lines 6-8, classic-asp/shop/inc/auth.asp line 2. The code updates a member record using the member_id from the request without any ownership verification. The only visible check is authentication in inc/auth.asp, which does not enforce ownership.

### BOLA-R-0003 — BOLA in ANY /classic-asp/shop/member.asp?mode=delete: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** ANY /classic-asp/shop/member.asp?mode=delete  
- **該当箇所:** `classic-asp/shop/member.asp:9`

**脆弱性の根拠コード (Evidence):**

- `classic-asp/shop/member.asp:9` — ID from request, no ownership check  
  `conn.Execute "DELETE FROM members WHERE member_id = " & Request.QueryString("member_id")`

**推奨対策 (Recommendation):** Bind delete to current session user

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: classic-asp/shop/member.asp line 9, classic-asp/shop/inc/auth.asp line 2. The delete statement uses the member_id from the query string directly. No ownership check is present in the visible code.

### BOLA-R-0004 — BOLA in ANY /classic-asp/shop/order.asp: missing owner verification on first query

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** ANY /classic-asp/shop/order.asp  
- **該当箇所:** `classic-asp/shop/order.asp:5`

**脆弱性の根拠コード (Evidence):**

- `classic-asp/shop/order.asp:5` — ID from request, no ownership check  
  `id = Request("id")`
- `classic-asp/shop/order.asp:6` — Query does not bind to user_id  
  `Set rs = conn.Execute("SELECT * FROM orders WHERE id = " & id)`

**推奨対策 (Recommendation):** Bind order query to current session user

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: classic-asp/shop/order.asp lines 5-6, classic-asp/shop/inc/auth.asp line 2. The first query selects an order by id from the request without binding to the current user. The later query includes a user_id check, but the initial query remains vulnerable.

### BOLA-R-0005 — BOLA in ANY /coldfusion/app/OrderService.cfc?method=getOrder: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** ANY /coldfusion/app/OrderService.cfc?method=getOrder  
- **該当箇所:** `coldfusion/app/OrderService.cfc:4`

**脆弱性の根拠コード (Evidence):**

- `coldfusion/app/OrderService.cfc:4` — Query starts here  
  `<cfquery name="q" datasource="shop">`
- `coldfusion/app/OrderService.cfc:5` — ID from request, no ownership check  
  `SELECT * FROM orders WHERE id = #arguments.orderId#`

**推奨対策 (Recommendation):** Bind order query to current session user

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: coldfusion/app/OrderService.cfc lines 4-5. The cfquery directly interpolates the orderId argument into the SQL without any ownership verification or parameter binding.

### BOLA-R-0006 — BOLA in ANY /coldfusion/app/order.cfm: missing owner verification on first query

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** ANY /coldfusion/app/order.cfm  
- **該当箇所:** `coldfusion/app/order.cfm:2`

**脆弱性の根拠コード (Evidence):**

- `coldfusion/app/order.cfm:2` — Query starts here  
  `<cfquery name="qOrder" datasource="shop">`
- `coldfusion/app/order.cfm:3` — ID from request, no ownership check  
  `SELECT * FROM orders WHERE id = #url.id#`

**推奨対策 (Recommendation):** Bind order query to current session user

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: coldfusion/app/order.cfm lines 2-3, coldfusion/app/order.cfm lines 5-8. The first query qOrder selects an order by id from the URL without checking the current user. The subsequent qMine query includes a user_id check, but the initial query is still exposed.

### BOLA-R-0007 — BOLA in POST /Admin/DeleteUser: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** POST /Admin/DeleteUser  
- **該当箇所:** `dotnet-legacy/Web/Controllers/AdminController.cs:12`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Controllers/AdminController.cs:11` — Method signature  
  `public ActionResult DeleteUser(int id)`
- `dotnet-legacy/Web/Controllers/AdminController.cs:12` — Finds user by id from request  
  `var u = db.Users.Find(id);`
- `dotnet-legacy/Web/Controllers/AdminController.cs:13` — Deletes user without ownership check  
  `db.Users.Remove(u);`

**推奨対策 (Recommendation):** Restrict to admin role and verify ownership

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: dotnet-legacy/Web/Controllers/AdminController.cs lines 6-13. The DeleteUser action lacks any ownership or role check; the controller is only marked with [Authorize], allowing any authenticated user to delete any user.

### BOLA-R-0009 — BOLA in POST /Admin/Export: missing role check allows data exposure

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_role_check) — CWE-284, CWE-285   
- **対象エンドポイント:** POST /Admin/Export  
- **該当箇所:** `dotnet-legacy/Web/Controllers/AdminController.cs:30`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Controllers/AdminController.cs:30` — Method signature  
  `public ActionResult Export()`
- `dotnet-legacy/Web/Controllers/AdminController.cs:32` — Checks query string, not role  
  `if (Request.QueryString["isAdmin"] == "true")`
- `dotnet-legacy/Web/Controllers/AdminController.cs:33` — Returns all users  
  `return Json(db.Users.ToList(), JsonRequestBehavior.AllowGet);`

**推奨対策 (Recommendation):** Add role-based authorization

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: dotnet-legacy/Web/Controllers/AdminController.cs lines 30-35. Export is protected only by class-level [Authorize] and a query‑string flag; no role or ownership verification is performed.

### BOLA-R-0010 — BOLA in POST /Customer/Edit: missing owner verification

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** POST /Customer/Edit  
- **該当箇所:** `dotnet-legacy/Web/Controllers/CustomerController.cs:12`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Controllers/CustomerController.cs:14` — Marks the supplied customer entity as modified without checking that the current user owns it  
  `db.Entry(customer).State = System.Data.Entity.EntityState.Modified;`
- `dotnet-legacy/Web/Controllers/CustomerController.cs:15` — Persists the changes, allowing any authenticated user to modify any customer record  
  `db.SaveChanges();`

**推奨対策 (Recommendation):** Load the customer by ID and verify ownership before applying changes

*検証結果 (Verifier):* likely — 確認対象: dotnet-legacy/Web/Controllers/CustomerController.cs lines 11-15. The Edit action marks the supplied Customer entity as Modified and saves it without checking ownership. The controller is decorated with [Authorize], which only ensures authentication, not ownership.

### BOLA-R-0011 — BOLA in POST /Customer/EditName: missing owner verification

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** POST /Customer/EditName  
- **該当箇所:** `dotnet-legacy/Web/Controllers/CustomerController.cs:20`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Controllers/CustomerController.cs:22` — Saves changes to the customer entity without verifying that the current user owns it  
  `db.SaveChanges();`

**推奨対策 (Recommendation):** Verify ownership before saving changes

*検証結果 (Verifier):* likely — 確認対象: dotnet-legacy/Web/Controllers/CustomerController.cs lines 20-23. EditName receives a Customer with only Id and Name bound, then calls SaveChanges without verifying that the current user owns the customer.

### BOLA-R-0012 — BOLA in POST /Customer/Refresh: missing owner verification

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** POST /Customer/Refresh  
- **該当箇所:** `dotnet-legacy/Web/Controllers/CustomerController.cs:27`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Controllers/CustomerController.cs:29` — Loads customer by ID supplied in the request without checking ownership  
  `var customer = db.Customers.Find(id);`
- `dotnet-legacy/Web/Controllers/CustomerController.cs:30` — Updates the customer entity without verifying that the current user owns it  
  `TryUpdateModel(customer);`
- `dotnet-legacy/Web/Controllers/CustomerController.cs:31` — Persists the changes, allowing any authenticated user to modify any customer record  
  `db.SaveChanges();`

**推奨対策 (Recommendation):** Load the customer and verify ownership before updating

*検証結果 (Verifier):* likely — 確認対象: dotnet-legacy/Web/Controllers/CustomerController.cs lines 27-32. Refresh loads a Customer by id and applies TryUpdateModel before saving, with no ownership check. The [Authorize] attribute only guarantees authentication.

### BOLA-R-0013 — BOLA in GET /Invoice/Details: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** ANY /Invoice/Details  
- **該当箇所:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:11`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:11` — Method signature  
  `public ActionResult Details(int id)`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:13` — Finds invoice by id from request  
  `var inv = db.Invoices.Find(id);`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:14` — Returns invoice without ownership check  
  `return View(inv);`

**推奨対策 (Recommendation):** Verify invoice ownership

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: dotnet-legacy/Web/Controllers/InvoiceController.cs lines 6-14. Details retrieves an invoice by id without checking that the invoice belongs to the current user.

### BOLA-R-0015 — BOLA in POST /Invoice/Search: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** POST /Invoice/Search  
- **該当箇所:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:26`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:26` — Method signature  
  `public ActionResult Search(string customer)`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` — Raw query uses customer from request, no ownership check  
  `var list = db.Database.SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = '" + customer + "'").ToList();`

**推奨対策 (Recommendation):** Add ownership filter to query

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: dotnet-legacy/Web/Controllers/InvoiceController.cs lines 25-29. Search builds a raw SQL query from user input and returns all matching invoices, with no ownership filter.

### BOLA-R-0016 — BOLA in ANY /dotnet-legacy/Web/Handlers/GetFile.ashx: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** ANY /dotnet-legacy/Web/Handlers/GetFile.ashx  
- **該当箇所:** `dotnet-legacy/Web/Handlers/GetFile.ashx:8`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Handlers/GetFile.ashx:8` — Takes file identifier directly from the request  
  `string fileId = context.Request.QueryString["file_id"];`
- `dotnet-legacy/Web/Handlers/GetFile.ashx:9` — Builds file path without checking that the current user owns the file  
  `string path = DocStore.PathFor(fileId);`
- `dotnet-legacy/Web/Handlers/GetFile.ashx:10` — Serves the file to the requester, enabling download of any file  
  `context.Response.TransmitFile(path);`

**推奨対策 (Recommendation):** Verify that the current user owns the requested file before transmitting

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: dotnet-legacy/Web/Handlers/GetFile.ashx:8-10. The handler reads the file identifier directly from the query string, builds a path without any ownership verification, and transmits the file. No ownership or tenant check is present in the visible code.

### BOLA-R-0017 — BOLA in ANY /dotnet-legacy/Web/Orders/EditOrder.aspx.vb: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** ANY /dotnet-legacy/Web/Orders/EditOrder.aspx  
- **該当箇所:** `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` — SQL built from request data  
  `Dim sql As String = "UPDATE Orders SET Note = '" & txtNote.Text & "'"`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` — OrderId from hidden field, no ownership check  
  `sql &= " WHERE OrderId = " & hfOrderId.Value`

**推奨対策 (Recommendation):** Verify order ownership before update

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: dotnet-legacy/Web/Orders/EditOrder.aspx.vb lines 6-13. The update statement uses the OrderId from a hidden field without verifying that the current user owns the order.

### BOLA-R-0018 — BOLA in ANY /dotnet-legacy/Web/Orders/OrderDetail.aspx.cs: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** ANY /dotnet-legacy/Web/Orders/OrderDetail.aspx  
- **該当箇所:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10`

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10` — ID from request  
  `string id = Request.QueryString["id"];`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` — Query does not bind to user_id  
  `var cmd = new SqlCommand("SELECT * FROM Orders WHERE OrderId = " + id, conn);`

**推奨対策 (Recommendation):** Bind order query to current session user

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: dotnet-legacy/Web/Orders/OrderDetail.aspx.cs. The unsafe query at line 13 is executed before any ownership check or parameter binding. No role or ownership guard is visible in the provided code.

### BOLA-R-0019 — BOLA in ANY /java-legacy/WebContent/order/detail.jsp: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** ANY /java-legacy/WebContent/order/detail.jsp  
- **該当箇所:** `java-legacy/WebContent/order/detail.jsp:3`

**脆弱性の根拠コード (Evidence):**

- `java-legacy/WebContent/order/detail.jsp:3` — ID from request  
  `String no = request.getParameter("no");`
- `java-legacy/WebContent/order/detail.jsp:5` — Query does not bind to user_id  
  `ResultSet rs = c.createStatement().executeQuery("SELECT * FROM orders WHERE order_no = '" + no + "'");`

**推奨対策 (Recommendation):** Bind order query to current session user

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: java-legacy/WebContent/order/detail.jsp. The query concatenates the request parameter directly into the SQL string with no ownership check or parameter binding.

### BOLA-R-0020 — BOLA in POST /account/save: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** POST /account/save  
- **該当箇所:** `java-legacy/src/com/acme/web/AccountController.java:14`

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/AccountController.java:14` — Account object is bound directly from the request; attacker can set any id  
  `public String save(@ModelAttribute Account account) {`
- `java-legacy/src/com/acme/web/AccountController.java:15` — No check that the account belongs to the current user  
  `    accountDao.save(account);`

**推奨対策 (Recommendation):** Bind the save operation to the authenticated user

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: java-legacy/src/com/acme/web/AccountController.java. The Account object is bound directly from the request and passed to the DAO without any ownership check.

### BOLA-R-0021 — BOLA in POST /account/rename: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** POST /account/rename  
- **該当箇所:** `java-legacy/src/com/acme/web/AccountController.java:20`

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/AccountController.java:20` — Form contains an id that can be set by the attacker  
  `public String rename(@ModelAttribute RenameForm form) {`
- `java-legacy/src/com/acme/web/AccountController.java:21` — No check that the id belongs to the current user  
  `    accountDao.rename(form.getId(), form.getName());`

**推奨対策 (Recommendation):** Verify ownership before renaming

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: java-legacy/src/com/acme/web/AccountController.java. The RenameForm contains an id that is used directly in the DAO call with no ownership verification.

### BOLA-R-0022 — BOLA in PUT /account/api: missing owner verification

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** PUT /account/api  
- **該当箇所:** `java-legacy/src/com/acme/web/AccountController.java:27`

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/AccountController.java:27` — Account object is deserialized from the request; attacker can set any id  
  `public Account update(@RequestBody Account account) {`
- `java-legacy/src/com/acme/web/AccountController.java:28` — No ownership check before saving  
  `    return accountDao.save(account);`

**推奨対策 (Recommendation):** Bind update to the authenticated user

*検証結果 (Verifier):* likely — 確認対象: java-legacy/src/com/acme/web/AccountController.java:25-28. The update method deserializes an Account object and directly passes it to accountDao.save without any ownership or role check visible in the provided code. No global filter or cast is shown.

### BOLA-R-0023 — BOLA in POST /admin/users/{id}/delete: missing owner verification

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** POST /admin/users/{id}/delete  
- **該当箇所:** `java-legacy/src/com/acme/web/AdminUserController.java:13`

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/AdminUserController.java:13` — Endpoint accepts any user id  
  `@RequestMapping(value = "/{id}/delete", method = RequestMethod.POST)`
- `java-legacy/src/com/acme/web/AdminUserController.java:15` — No authentication or role check; any logged‑in user can delete any account  
  `    userDao.deleteById(id);`

**推奨対策 (Recommendation):** Require admin role before deleting a user

*検証結果 (Verifier):* likely — 確認対象: java-legacy/src/com/acme/web/AdminUserController.java:13-15. The delete method accepts any user id and calls userDao.deleteById without a role or ownership guard. The @PreAuthorize annotation is present only on a different method.

### BOLA-R-0025 — BOLA in GET /invoices/{id}: missing owner verification

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** GET /invoices/{id}  
- **該当箇所:** `java-legacy/src/com/acme/web/InvoiceController.java:15`

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/InvoiceController.java:15` — Endpoint accepts any invoice id  
  `@RequestMapping(value = "/{id}", method = RequestMethod.GET)`
- `java-legacy/src/com/acme/web/InvoiceController.java:17` — No check that the invoice belongs to the current user  
  `        model.addAttribute("invoice", invoiceDao.findById(id));`

**推奨対策 (Recommendation):** Bind invoice lookup to the authenticated user

*検証結果 (Verifier):* likely — 確認対象: java-legacy/src/com/acme/web/InvoiceController.java:15-17. The show method retrieves an invoice by id without verifying that the invoice belongs to the current user. No ownership check or role guard is visible.

### BOLA-R-0027 — BOLA in GET /invoices/search: missing owner verification

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** GET /invoices/search  
- **該当箇所:** `java-legacy/src/com/acme/web/InvoiceController.java:27`

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/InvoiceController.java:27` — Endpoint accepts any customer string  
  `@RequestMapping(value = "/search", method = RequestMethod.GET)`
- `java-legacy/src/com/acme/web/InvoiceController.java:29` — Query is built from user input without binding to current user  
  `        model.addAttribute("list", session.createQuery("from Invoice i where i.customer = '" + customer + "'").list());`

**推奨対策 (Recommendation):** Restrict search to invoices owned by the current user

*検証結果 (Verifier):* likely — 確認対象: java-legacy/src/com/acme/web/InvoiceController.java:27-29. The search method builds a query from a customer string without binding to the current user or applying an allow‑list. No ownership or role check is shown.

### BOLA-R-0028 — BOLA in GET /order/view: missing owner verification

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** GET /order/view  
- **該当箇所:** `java-legacy/src/com/acme/web/OrderServlet.java:11`

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/OrderServlet.java:11` — Order id comes directly from the request  
  `String id = request.getParameter("orderId");`
- `java-legacy/src/com/acme/web/OrderServlet.java:15` — No check that the order belongs to the current user  
  `ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = '" + id + "'");`

**推奨対策 (Recommendation):** Bind order lookup to the authenticated user

*検証結果 (Verifier):* likely — 確認対象: java-legacy/src/com/acme/web/OrderServlet.java:11-15. The servlet retrieves an order by id directly from the request and queries the database without verifying ownership. No role or ownership guard is visible in the provided snippet.

### BOLA-R-0029 — BOLA in POST /ProfileServlet: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** POST <see web.xml servlet-mapping>  
- **該当箇所:** `java-legacy/src/com/acme/web/ProfileServlet.java:9`

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/ProfileServlet.java:12` — Populates an Account object with all request parameters without checking ownership  
  `BeanUtils.populate(account, request.getParameterMap());`
- `java-legacy/src/com/acme/web/ProfileServlet.java:13` — No authentication or ownership check is performed before persisting the account  
  `/* no further processing shown */`

**推奨対策 (Recommendation):** Load the account by ID and verify that the current user owns it before updating

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: java-legacy/src/com/acme/web/ProfileServlet.java:12-13. The servlet populates an Account object with all request parameters and does not perform any ownership check before persisting. No compensating control is visible.

### BOLA-R-0030 — BOLA in POST /admin/users/:id/delete: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** POST /admin/users/:id/delete  
- **該当箇所:** `node-express/routes/admin.js:8`

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/admin.js:8` — Endpoint accepts any user id  
  `router.post('/admin/users/:id/delete', ensureLoggedIn, function (req, res) {`
- `node-express/routes/admin.js:9` — No role check; any logged‑in user can delete any account  
  `  User.deleteOne({ _id: req.params.id }, function () { res.sendStatus(204); });`

**推奨対策 (Recommendation):** Require admin role before deleting a user

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: router.post('/admin/users/:id/delete', ensureLoggedIn, function (req, res) {,   User.deleteOne({ _id: req.params.id }, function () { res.sendStatus(204); });. No admin role or ownership check is performed before deleting a user.

### BOLA-R-0033 — BOLA in GET /orders/:id: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** GET /orders/:id  
- **該当箇所:** `node-express/routes/orders.js:8`

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:8` — The order ID comes from the request and the query does not filter by the authenticated user.  
  `router.get('/orders/:id', ensureLoggedIn, function (req, res) { Order.findById(req.params.id, function (err, order) { res.json(order); }); });`

**推奨対策 (Recommendation):** Bind the query to the current session user.

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: router.get('/orders/:id', ensureLoggedIn, function (req, res) {,   Order.findById(req.params.id, function (err, order) { res.json(order); });. The order is retrieved by ID without filtering by the authenticated user.

### BOLA-R-0038 — BOLA in GET /stats: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** GET /stats  
- **該当箇所:** `node-express/routes/orders.js:28`

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:28` — The shop_id is taken from the request and the query is not filtered by the authenticated user.  
  `router.get('/stats', function (req, res) { db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}', function (e, r) { res.json(r); }); });`

**推奨対策 (Recommendation):** Add authentication guard and filter by the current user’s shop.

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: router.get('/stats', function (req, res) {,   db.query(`SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}`, function (e, r) { res.json(r); });. The shop_id is taken directly from the request and no authentication guard is present.

### BOLA-R-0043 — BOLA in ANY /perl-cgi/cgi-bin/order.cgi: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** ANY /perl-cgi/cgi-bin/order.cgi  
- **該当箇所:** `perl-cgi/cgi-bin/order.cgi:13`

**脆弱性の根拠コード (Evidence):**

- `perl-cgi/cgi-bin/order.cgi:13` — The order ID comes from the request and the query does not filter by the authenticated user.  
  `my $sth = $dbh->prepare("SELECT * FROM orders WHERE id = $id");`

**推奨対策 (Recommendation):** Use a parameterized query that includes the user_id.

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: my $sth = $dbh->prepare("SELECT * FROM orders WHERE id = $id");, $sth->execute();. An insecure query is executed before the safe query that includes user_id.

### BOLA-R-0044 — BOLA in ANY /invoice/view/{id}: missing owner verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** ANY /invoice/view/{id}  
- **該当箇所:** `php-codeigniter/application/controllers/Invoice.php:10`

**脆弱性の根拠コード (Evidence):**

- `php-codeigniter/application/controllers/Invoice.php:10` — The invoice ID comes from the request and the query does not filter by the authenticated user.  
  `$q = $this->db->query("SELECT * FROM invoices WHERE id = $id");`

**推奨対策 (Recommendation):** Add an owner check to the query.

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: $q = $this->db->query("SELECT * FROM invoices WHERE id = $id");, $this->load->view('invoice', array('inv' => $q->row()));. The invoice is fetched by ID without filtering by the authenticated user.

### BOLA-R-0046 — BOLA in ANY /invoice/update: missing owner verification

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** ANY /invoice/update  
- **該当箇所:** `php-codeigniter/application/controllers/Invoice.php:23`

**脆弱性の根拠コード (Evidence):**

- `php-codeigniter/application/controllers/Invoice.php:23` — The invoice ID comes from the request and the update does not filter by the authenticated user.  
  `$this->db->query("UPDATE invoices SET note = ? WHERE id = ?", array($note, $id));`

**推奨対策 (Recommendation):** Add an owner check to the update query.

*検証結果 (Verifier):* likely — 確認対象: php-codeigniter/application/controllers/Invoice.php lines 20-24. No ownership or role check, integer cast, or allow‑list is visible in the update method. The controller does not include any auth guard in the provided context.

### BOLA-R-0057-1 — BOLA in GET /php-plain/admin.php?action=view: missing admin authorization

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_role_check) — CWE-285   
- **対象エンドポイント:** GET /php-plain/admin.php?action=view  
- **該当箇所:** `php-plain/admin.php:8`

**脆弱性の根拠コード (Evidence):**

- `php-plain/admin.php:8` — No admin check; any logged-in user can view any user record by supplying uid  
  `$r = mysql_query("SELECT * FROM users WHERE id = " . $uid);`

**推奨対策 (Recommendation):** Restrict admin actions to users with admin role

*検証結果 (Verifier):* likely — 確認対象: php-plain/admin.php lines 5-9, php-plain/inc/auth.php lines 1-7. The included auth file only verifies a logged‑in session; there is no admin role check before the SELECT query.

### BOLA-R-0057-2 — BOLA in POST /php-plain/admin.php?action=delete: missing admin authorization

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_role_check) — CWE-285   
- **対象エンドポイント:** POST /php-plain/admin.php?action=delete  
- **該当箇所:** `php-plain/admin.php:6`

**脆弱性の根拠コード (Evidence):**

- `php-plain/admin.php:12` — No admin check; any logged-in user can delete any user record by supplying id  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**推奨対策 (Recommendation):** Restrict admin actions to users with admin role

*検証結果 (Verifier):* likely — 確認対象: php-plain/admin.php lines 10-13, php-plain/inc/auth.php lines 1-7. No admin role check is present before the DELETE statement; the auth file does not enforce role.

### BOLA-R-0058-1 — BOLA in GET /php-plain/admin.php?action=view: missing admin authorization

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_role_check) — CWE-285   
- **対象エンドポイント:** GET /php-plain/admin.php?action=view  
- **該当箇所:** `php-plain/admin.php:10`

**脆弱性の根拠コード (Evidence):**

- `php-plain/admin.php:8` — No admin check; any logged-in user can view any user record by supplying uid  
  `$r = mysql_query("SELECT * FROM users WHERE id = " . $uid);`

**推奨対策 (Recommendation):** Restrict admin actions to users with admin role

*検証結果 (Verifier):* likely — 確認対象: php-plain/admin.php lines 5-9, php-plain/inc/auth.php lines 1-7. Same as BOLA-R-0057-1: only a login check is performed, no admin guard before the SELECT.

### BOLA-R-0058-2 — BOLA in POST /php-plain/admin.php?action=delete: missing admin authorization

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_role_check) — CWE-285   
- **対象エンドポイント:** POST /php-plain/admin.php?action=delete  
- **該当箇所:** `php-plain/admin.php:12`

**脆弱性の根拠コード (Evidence):**

- `php-plain/admin.php:12` — No admin check; any logged-in user can delete any user record by supplying id  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**推奨対策 (Recommendation):** Restrict admin actions to users with admin role

*検証結果 (Verifier):* likely — 確認対象: php-plain/admin.php lines 10-13, php-plain/inc/auth.php lines 1-7. Same as BOLA-R-0057-2: no admin role check before the DELETE.

### BOLA-R-0059-1 — BOLA in POST /php-plain/manage_users.php: missing admin authorization

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_role_check) — CWE-285   
- **対象エンドポイント:** POST /php-plain/manage_users.php  
- **該当箇所:** `php-plain/manage_users.php:6`

**脆弱性の根拠コード (Evidence):**

- `php-plain/manage_users.php:6` — No admin check; any logged-in user can delete any user record by supplying id  
  `$stmt = $db->prepare("DELETE FROM users WHERE id = ?");`
- `php-plain/manage_users.php:7` — No admin check; any logged-in user can delete any user record by supplying id  
  `$stmt->execute(array((int)$_POST['id']));`

**推奨対策 (Recommendation):** Restrict admin actions to users with admin role

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: Checked lines 1-12 of php-plain/manage_users.php. The script performs a delete operation after a POST request but contains only a login check. No admin role check is present; the integer cast on $_POST['id'] is insufficient.

### BOLA-R-0061-1 — BOLA in GET /php-plain/order_detail.php: missing ownership verification

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** GET /php-plain/order_detail.php  
- **該当箇所:** `php-plain/order_detail.php:6`

**脆弱性の根拠コード (Evidence):**

- `php-plain/order_detail.php:6` — No ownership check; any logged-in user can view any order by supplying id  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`

**推奨対策 (Recommendation):** Bind query to current session user

*検証結果 (Verifier):* likely — 確認対象: Checked lines 1-8 of php-plain/order_detail.php. The visible code performs a direct query on the order id without any ownership verification. The auth model indicates a check exists elsewhere, but it is not shown in the provided context.

### BOLA-R-0066-1 — BOLA in POST /php-plain/admin/delete_user.php: missing admin authorization

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_role_check) — CWE-285   
- **対象エンドポイント:** POST /php-plain/admin/delete_user.php  
- **該当箇所:** `php-plain/admin/delete_user.php:6`

**脆弱性の根拠コード (Evidence):**

- `php-plain/admin/delete_user.php:6` — No admin check; any logged-in user can delete any user record by supplying id  
  `$stmt = $db->prepare("DELETE FROM users WHERE id = ?");`
- `php-plain/admin/delete_user.php:7` — No admin check; any logged-in user can delete any user record by supplying id  
  `$stmt->execute(array($id));`

**推奨対策 (Recommendation):** Restrict admin actions to users with admin role

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: Checked lines 1-8 of php-plain/admin/delete_user.php. The file includes only a login check via inc/auth.php; no admin role check is present. The integer cast on $_POST['id'] does not provide authorization.

### BOLA-R-0067-1 — BOLA in POST /php-plain/admin/promote.php: missing admin authorization

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_role_check) — CWE-285   
- **対象エンドポイント:** POST /php-plain/admin/promote.php  
- **該当箇所:** `php-plain/admin/promote.php:6`

**脆弱性の根拠コード (Evidence):**

- `php-plain/admin/promote.php:6` — No admin check; any logged-in user can promote any user to admin  
  `$stmt = $db->prepare("UPDATE users SET role = 'admin' WHERE id = ?");`
- `php-plain/admin/promote.php:7` — No admin check; any logged-in user can promote any user to admin  
  `$stmt->execute(array((int)$_POST['uid']));`

**推奨対策 (Recommendation):** Restrict admin actions to users with admin role

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: Checked lines 1-8 of php-plain/admin/promote.php. Only a login check is performed; there is no admin role verification. The cast to int on $_POST['uid'] does not mitigate the missing authorization.

### BOLA-R-0069-1 — BOLA in GET /orders/<int:order_id>: missing ownership verification

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** GET /orders/<int:order_id>  
- **該当箇所:** `python-flask/app.py:12`

**脆弱性の根拠コード (Evidence):**

- `python-flask/app.py:12` — No ownership check; any logged-in user can view any order by supplying order_id  
  `cur.execute("SELECT * FROM orders WHERE id = %s" % order_id);`

**推奨対策 (Recommendation):** Bind query to current user

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: Checked lines 8-13 of python-flask/app.py. The /orders/<int:order_id> route executes a query based solely on the order id with no user‑ownership filter. Only the login_required decorator is present.

### BOLA-R-0073 — BOLA in POST /users/<uid>/name: missing owner verification

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** POST /users/<int:uid>/name  
- **該当箇所:** `python-flask/profile.py:16`

**脆弱性の根拠コード (Evidence):**

- `python-flask/profile.py:18` — Loads user by ID supplied in the URL without checking ownership  
  `user = User.query.get(uid)`
- `python-flask/profile.py:19` — Updates the user record without verifying that the current session user owns it  
  `user.name = request.json["name"]`

**推奨対策 (Recommendation):** Bind the update to the current session user

*検証結果 (Verifier):* likely — 確認対象: python-flask/profile.py lines 16-20. The rename endpoint loads a User by the supplied uid and updates the name without any ownership or role check. No cast or allow‑list is present in the visible code.

### BOLA-R-0074 — BOLA in PATCH /users/<uid>: missing owner verification

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-284, CWE-639   
- **対象エンドポイント:** PATCH /users/<int:uid>  
- **該当箇所:** `python-flask/profile.py:24`

**脆弱性の根拠コード (Evidence):**

- `python-flask/profile.py:26` — Loads user by ID supplied in the URL without ownership check  
  `user = User.query.get(uid)`
- `python-flask/profile.py:27` — Updates arbitrary fields of the user record without verifying ownership  
  `for key, value in request.json.items():
    setattr(user, key, value)`

**推奨対策 (Recommendation):** Verify that the current session user owns the target user before updating

*検証結果 (Verifier):* likely — 確認対象: python-flask/profile.py lines 24-29. The patch endpoint retrieves a User by uid and applies arbitrary updates without verifying that the current session user owns the record. No ownership guard is visible.

### MASS-M-0009-1 — Team creation allows owner_id to be set by any user

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** マスアサインメント (Mass Assignment) (privileged_field_writable) — CWE-915   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-laravel/app/Http/Controllers/AccountController.php:23`

**影響度 (Impact):** owner_id field writable by any authenticated user

**脆弱性の根拠コード (Evidence):**

- `php-laravel/app/Http/Controllers/AccountController.php:21` — Team::create($request->all()) binds all request fields, including owner_id which is writable

**推奨対策 (Recommendation):** Restrict mass assignment to non-privileged fields or set guarded/fillable to exclude owner_id

*検証結果 (Verifier):* likely — 確認対象: php-laravel/app/Http/Controllers/AccountController.php lines 21-23. The controller calls Team::create($request->all()) with no visible mass‑assignment guard. The Team model definition (fillable/guarded) is not shown, so a compensating control cannot be confirmed.

### MASS-M-0006-1 — Profile update binds entire request body to User model

- **重要度 / 確信度:** 中 (Medium) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** マスアサインメント (Mass Assignment) (whole_object_binding) — CWE-915   
- **対象エンドポイント:** - -  
- **該当箇所:** `node-express/routes/profile.js:8`

**影響度 (Impact):** Unknown privileged fields may be writable

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/profile.js:8` — Location taken from the Tier 1 inventory

**推奨対策 (Recommendation):** Review model definition to ensure no privileged fields are mass assignable

*検証結果 (Verifier):* likely — 確認対象: profile.js router.put('/profile') handler (lines 7-9), User.findByIdAndUpdate with req.body. The handler updates the user document with the entire request body without any field filtering or privilege checks.

### MASS-M-0007-1 — Profile update binds entire request body to User model

- **重要度 / 確信度:** 中 (Medium) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** マスアサインメント (Mass Assignment) (whole_object_binding) — CWE-915   
- **対象エンドポイント:** - -  
- **該当箇所:** `node-express/routes/profile.js:16`

**影響度 (Impact):** Unknown privileged fields may be writable

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/profile.js:16` — Location taken from the Tier 1 inventory

**推奨対策 (Recommendation):** Review model definition to ensure no privileged fields are mass assignable

*検証結果 (Verifier):* likely — 確認対象: profile.js router.post('/signup') handler (lines 15-17), new User(req.body) and user.save(). The signup route creates a new user from the full request body, exposing all fields to the client.

### MASS-M-0008-1 — User registration binds entire request body to User model

- **重要度 / 確信度:** 中 (Medium) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** マスアサインメント (Mass Assignment) (whole_object_binding) — CWE-915   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-laravel/app/Http/Controllers/AccountController.php:13`

**影響度 (Impact):** Unknown privileged fields may be writable

**脆弱性の根拠コード (Evidence):**

- `php-laravel/app/Http/Controllers/AccountController.php:13` — Location taken from the Tier 1 inventory

**推奨対策 (Recommendation):** Review model definition to ensure no privileged fields are mass assignable

*検証結果 (Verifier):* likely — 確認対象: AccountController.register method (lines 11-14), User::create($request->all()). The register action mass‑assigns all request fields to the User model without any explicit field filtering.

### MASS-M-0010-1 — Team creation binds entire request body to Team model

- **重要度 / 確信度:** 中 (Medium) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** マスアサインメント (Mass Assignment) (whole_object_binding) — CWE-915   
- **対象エンドポイント:** - -  
- **該当箇所:** `php-laravel/app/Http/Controllers/AccountController.php:36`

**影響度 (Impact):** Unknown privileged fields may be writable

**脆弱性の根拠コード (Evidence):**

- `php-laravel/app/Http/Controllers/AccountController.php:36` — Location taken from the Tier 1 inventory

**推奨対策 (Recommendation):** Review model definition to ensure no privileged fields are mass assignable

*検証結果 (Verifier):* likely — 確認対象: php-laravel/app/Http/Controllers/AccountController.php lines 21-23. Same as finding 1: the entire request body is bound to the Team model with no visible guard. The model’s mass‑assignment configuration is not visible.

### MASS-M-0014-1 — User creation binds entire request JSON to User model

- **重要度 / 確信度:** 中 (Medium) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** マスアサインメント (Mass Assignment) (whole_object_binding) — CWE-915   
- **対象エンドポイント:** - -  
- **該当箇所:** `python-flask/profile.py:10`

**影響度 (Impact):** Unknown privileged fields may be writable

**脆弱性の根拠コード (Evidence):**

- `python-flask/profile.py:10` — Location taken from the Tier 1 inventory

**推奨対策 (Recommendation):** Review model definition to ensure no privileged fields are mass assignable

*検証結果 (Verifier):* likely — 確認対象: python-flask/profile.py lines 8-12. User creation uses User(**request.json) to bind all fields. No visible guard is present in the shown code, and the model’s mass‑assignment configuration is not visible.

### MASS-M-0015-1 — PATCH endpoint sets arbitrary attributes from request JSON

- **重要度 / 確信度:** 中 (Medium) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** マスアサインメント (Mass Assignment) (whole_object_binding) — CWE-915   
- **対象エンドポイント:** - -  
- **該当箇所:** `python-flask/profile.py:27`

**影響度 (Impact):** Unknown privileged fields may be writable

**脆弱性の根拠コード (Evidence):**

- `python-flask/profile.py:27` — Location taken from the Tier 1 inventory

**推奨対策 (Recommendation):** Review model definition to ensure no privileged fields are mass assignable

*検証結果 (Verifier):* likely — 確認対象: python-flask/profile.py lines 24-29. The PATCH endpoint iterates over request.json and sets attributes on the User object without any visible guard. The User model’s mass‑assignment restrictions are not shown.

## 4. 根本的恒久対策

<!-- LLM: reporter agent writes max 5 systemic fixes here (日本語で記載: 共通認可ヘルパー、パラメータバインディングDAO等のアーキテクチャ改修案と工数見積 S/M/L) -->

## 5. 調査範囲と制約事項

- missing from inventory: 0
- bola routes without verdict: 0
- injection candidates without verdict: 0
- bfla routes without verdict: 0
- mass candidates without verdict: 0
- findings without verification: 0

<!-- LLM: reporter agent lists limitations here (日本語で記載: ストアドプロシージャ、動的インクルード、設定による除外パス等) -->

## 付録A — 検証により棄却された検出事項

| ID | 該当箇所 | 棄却理由 |
|---|---|---|
| INJ-I-0035-1 | `python-flask/app.py:12` | The Flask route converter `<int:order_id>` guarantees that `order_id` is an integer before it reaches the handler, preventing SQL injection via the string formatting used in the query. |
| MASS-M-0013-1 | `php-plain/register.php:4` | The code extracts $_POST but only inserts the email and name columns into the users table. No mass assignment of privileged fields occurs, so the evidence does not support the finding. |

## 付録B — 監査手法とプロセス

1. **決定論的静的事前スキャン**: 技術スタック判定、エンドポイント候補抽出、クエリ生成箇所抽出。
2. **独立したAI監査エージェント群**: 認可モデル抽出、エンドポイント詳細精査、BOLA監査、インジェクション監査。
3. **懐疑的AI検証エージェント（Skeptic）**: 検出事項に対する反論テストを実施し、既存の防御制御による誤検知を排除。
4. **人間のエンジニアによる最終確認と承認**: `review-log.md` による判定記録とサインオフ。

**免責事項:** 本監査は侵入テスト（ペネトレーションテスト）ではありません。脆弱性が検出されなかったことは、脆弱性の非存在を証明するものではありません。
