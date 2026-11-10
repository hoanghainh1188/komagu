<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %><%@ taglib uri="http://struts.apache.org/tags-bean" prefix="bean" %><%@ taglib uri="http://struts.apache.org/tags-html" prefix="html" %><%@ taglib uri="http://struts.apache.org/tags-logic" prefix="logic" %>
<html><body><h1>AMS sign in</h1><p>${error}</p>
<form method="post" action="${pageContext.request.contextPath}/login.do">
<input name="username"><input name="password" type="password"><button>Sign in</button></form></body></html>
