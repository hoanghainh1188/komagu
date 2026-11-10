package com.example.ams.web;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** Every action except login needs a session. */
public class AuthFilter implements Filter {
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        boolean login = "/login.do".equals(request.getServletPath());
        boolean signedIn = request.getSession(false) != null
                && request.getSession(false).getAttribute("userId") != null;
        if (login || signedIn) {
            chain.doFilter(req, res);
        } else {
            ((HttpServletResponse) res).sendRedirect(request.getContextPath() + "/login.do");
        }
    }

    @Override
    public void init(FilterConfig config) {
        // no configuration
    }

    @Override
    public void destroy() {
        // no resources
    }
}
