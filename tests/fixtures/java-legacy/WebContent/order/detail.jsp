<%@ page import="java.sql.*" %>
<%
  String no = request.getParameter("no");
  Connection c = (Connection) application.getAttribute("conn");
  ResultSet rs = c.createStatement().executeQuery("SELECT * FROM orders WHERE order_no = '" + no + "'"); // LSA-EXPECT:SQLI LSA-EXPECT:BOLA
%>
<p>${param.no}</p>
