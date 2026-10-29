package com.acme.web;

import com.acme.model.Account;
import java.io.IOException;
import javax.servlet.http.*;
import org.apache.commons.beanutils.BeanUtils;

public class ProfileServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Account account = new Account();
        try {
            BeanUtils.populate(account, request.getParameterMap()); // LSA-EXPECT:MASS
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}
