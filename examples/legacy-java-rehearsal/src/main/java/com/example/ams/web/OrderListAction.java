package com.example.ams.web;

import com.example.ams.mapper.OrderMapper;
import java.io.InputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.ibatis.io.Resources;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

public class OrderListAction extends Action {
    private static SqlSessionFactory factory;

    private static synchronized SqlSessionFactory factory() throws Exception {
        if (factory == null) {
            try (InputStream in = Resources.getResourceAsStream("mybatis-config.xml")) {
                factory = new SqlSessionFactoryBuilder().build(in);
            }
        }
        return factory;
    }

    @Override
    public ActionForward execute(ActionMapping mapping, ActionForm form,
                                 HttpServletRequest request, HttpServletResponse response) throws Exception {
        String sort = request.getParameter("sort");
        long userId = (Long) request.getSession().getAttribute("userId");
        try (SqlSession session = factory().openSession()) {
            request.setAttribute("orders",
                    session.getMapper(OrderMapper.class).listMine(userId, sort == null ? "id" : sort));
        }
        return mapping.findForward("ok");
    }
}
