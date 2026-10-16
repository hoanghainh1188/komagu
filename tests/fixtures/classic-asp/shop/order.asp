<!--#include file="inc/auth.asp"-->
<!--#include file="inc/conn.asp"-->
<%
Dim id, rs, sql
id = Request("id")
Set rs = conn.Execute("SELECT * FROM orders WHERE id = " & id) ' LSA-EXPECT:SQLI LSA-EXPECT:BOLA
Response.Write Server.HTMLEncode(rs("address"))

Dim sid
If IsNumeric(Request.QueryString("sid")) Then
  sid = CLng(Request.QueryString("sid"))
  Set rs2 = conn.Execute("SELECT * FROM orders WHERE id = " & sid & " AND user_id = " & CLng(Session("UserID"))) ' LSA-EXPECT:SAFE-SQL LSA-EXPECT:SAFE-BOLA
End If
%>
