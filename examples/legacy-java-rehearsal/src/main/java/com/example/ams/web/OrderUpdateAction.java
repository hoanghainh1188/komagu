package com.example.ams.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import org.apache.struts.action.DynaActionForm;

public class OrderUpdateAction extends Action {
    @Override
    public ActionForward execute(ActionMapping mapping, ActionForm form,
                                 HttpServletRequest request, HttpServletResponse response) throws Exception {
        if (!"POST".equals(request.getMethod()) || !isTokenValid(request, true)) {
            return mapping.findForward("expired");
        }
        DynaActionForm orderForm = (DynaActionForm) form;
        String id = orderForm.getString("id");
        OrderDao.updateNote(Long.parseLong(id), orderForm.getString("note"));
        response.sendRedirect(request.getContextPath() + "/order/detail.do?id=" + id);
        return null;
    }
}
