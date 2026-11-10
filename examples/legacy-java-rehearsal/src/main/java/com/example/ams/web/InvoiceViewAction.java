package com.example.ams.web;

import com.example.ams.model.Invoice;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

public class InvoiceViewAction extends Action {
    @Override
    public ActionForward execute(ActionMapping mapping, ActionForm form,
                                 HttpServletRequest request, HttpServletResponse response) throws Exception {
        Invoice invoice = OrderDao.findInvoice(Long.parseLong(request.getParameter("invoiceId")));
        if (invoice == null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return null;
        }
        request.setAttribute("invoice", invoice);
        return mapping.findForward("ok");
    }
}
