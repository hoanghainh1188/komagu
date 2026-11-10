package com.example.ams.web;

import com.example.ams.Db;
import com.example.ams.model.Invoice;
import com.example.ams.model.Order;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

final class OrderDao {
    private OrderDao() {
    }

    static Order find(long id) throws SQLException {
        String sql = "SELECT id, owner_id, item, note, total FROM orders WHERE id = ?";
        try (Connection conn = Db.open(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? map(rs) : null;
            }
        }
    }

    static void updateNote(long id, String note) throws SQLException {
        String sql = "UPDATE orders SET note = ? WHERE id = ?";
        try (Connection conn = Db.open(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, note);
            ps.setLong(2, id);
            ps.executeUpdate();
        }
    }

    static Invoice findInvoice(long id) throws SQLException {
        String sql = "SELECT id, owner_id, amount FROM invoices WHERE id = ?";
        try (Connection conn = Db.open(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                Invoice invoice = new Invoice();
                invoice.setId(rs.getLong("id"));
                invoice.setOwnerId(rs.getLong("owner_id"));
                invoice.setAmount(rs.getInt("amount"));
                return invoice;
            }
        }
    }

    static List<Order> search(String q) throws SQLException {
        String sql = "SELECT id, owner_id, item, note, total FROM orders WHERE item LIKE '%" + q + "%'";
        List<Order> rows = new ArrayList<>();
        try (Connection conn = Db.open(); Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            while (rs.next()) {
                rows.add(map(rs));
            }
        }
        return rows;
    }

    private static Order map(ResultSet rs) throws SQLException {
        Order order = new Order();
        order.setId(rs.getLong("id"));
        order.setOwnerId(rs.getLong("owner_id"));
        order.setItem(rs.getString("item"));
        order.setNote(rs.getString("note"));
        order.setTotal(rs.getInt("total"));
        return order;
    }
}
