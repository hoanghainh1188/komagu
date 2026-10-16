package com.acme.struts;

import java.sql.*;
import javax.servlet.http.*;
import org.apache.struts.action.*;

public class EditUserAction extends Action {
    public ActionForward execute(ActionMapping mapping, ActionForm form,
                                 HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userId = request.getParameter("user_id");
        String email = request.getParameter("email");
        Connection conn = DataSourceHolder.get().getConnection();
        PreparedStatement ps = conn.prepareStatement("UPDATE users SET email = '" + email + "' WHERE id = " + userId); // LSA-EXPECT:SQLI LSA-EXPECT:BOLA
        ps.executeUpdate();
        return mapping.findForward("success");
    }
}
