<!--#include file="inc/auth.asp"-->
<!--#include file="inc/conn.asp"-->
<%
Select Case Request("mode")
  Case "edit"
    sql = "UPDATE members SET name = '" & Replace(Request.Form("name"), "'", "''") & "'" ' LSA-EXPECT:SAFE-SQL
    sql = sql & " WHERE member_id = " & Request.Form("member_id") ' LSA-EXPECT:SQLI LSA-EXPECT:BOLA
    conn.Execute sql
  Case "delete"
    conn.Execute "DELETE FROM members WHERE member_id = " & Request.QueryString("member_id") ' LSA-EXPECT:SQLI LSA-EXPECT:BOLA
End Select
%>
