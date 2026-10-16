package com.acme.web;

import java.io.IOException;
import java.sql.*;
import javax.servlet.http.*;

public class OrderServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession();
        Object loginUser = session.getAttribute("loginUser");
        String id = request.getParameter("orderId");
        try {
            Connection conn = DataSourceHolder.get().getConnection();
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = '" + id + "'"); // LSA-EXPECT:SQLI LSA-EXPECT:BOLA
            StringBuilder sb = new StringBuilder("SELECT * FROM items WHERE 1=1");
            sb.append(" AND order_id = ").append(id); // LSA-EXPECT:SQLI
            ResultSet items = stmt.executeQuery(sb.toString());
            PreparedStatement ps = conn.prepareStatement("SELECT * FROM notes WHERE order_id = ?"); // LSA-EXPECT:SAFE-SQL-NOFLAG
            ps.setString(1, id);
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }
}
