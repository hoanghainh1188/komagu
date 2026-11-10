package com.example.ams.web;

import com.example.ams.model.Order;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

public class OrderDetailAction extends Action {
    @Override
    public ActionForward execute(ActionMapping mapping, ActionForm form,
                                 HttpServletRequest request, HttpServletResponse response) throws Exception {
        Order order = OrderDao.find(Long.parseLong(request.getParameter("id")));
        if (order == null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return null;
        }
        request.setAttribute("order", order);
        return mapping.findForward("ok");
    }
}
