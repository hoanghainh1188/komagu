package com.example.ams.web;

import com.example.ams.Db;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

public class LoginAction extends Action {
    @Override
    public ActionForward execute(ActionMapping mapping, ActionForm form,
                                 HttpServletRequest request, HttpServletResponse response) throws Exception {
        if (!"POST".equals(request.getMethod())) {
            return mapping.findForward("form");
        }
        String sql = "SELECT id, display_name, role FROM users WHERE username = ? AND password = ?";
        try (Connection conn = Db.open(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, request.getParameter("username"));
            ps.setString(2, request.getParameter("password"));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    request.setAttribute("error", "Invalid username or password");
                    return mapping.findForward("form");
                }
                HttpSession old = request.getSession(false);
                if (old != null) {
                    old.invalidate();
                }
                HttpSession session = request.getSession(true);
                session.setAttribute("userId", rs.getLong("id"));
                session.setAttribute("displayName", rs.getString("display_name"));
                session.setAttribute("role", rs.getString("role"));
                return mapping.findForward("home");
            }
        }
    }
}
