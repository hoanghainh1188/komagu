package com.example.ams.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

/** Role check that denies with a 200 error page, as many legacy systems do. */
public class AdminReportAction extends Action {
    @Override
    public ActionForward execute(ActionMapping mapping, ActionForm form,
                                 HttpServletRequest request, HttpServletResponse response) {
        if (!"admin".equals(request.getSession().getAttribute("role"))) {
            return mapping.findForward("denied");
        }
        return mapping.findForward("ok");
    }
}
