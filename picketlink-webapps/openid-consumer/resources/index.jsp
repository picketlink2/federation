<%@ page session="true" %>

<%@ page import="org.jboss.identity.federation.api.openid.OpenIDManager,org.jboss.identity.federation.bindings.web.openid.HTTPProtocolAdaptor, org.jboss.identity.federation.bindings.web.openid.HTTPOpenIDContext" %>
<html>
<body>

<%
   String baseURL = "http://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
   //Correct the return url if needed
   String returnURL = baseURL + "/consumer_return.jsp";
%>

<%
    OpenIDManager manager = (OpenIDManager)session.getAttribute("openid_manager");

    if (request.getParameter("logout")!=null)
    {
        HTTPProtocolAdaptor adapter = new HTTPProtocolAdaptor(new HTTPOpenIDContext(request,response, application));
        manager.logout(adapter);
%>
 Logged out!<p>
 <%
   }
 
   if (session.getAttribute("openid")==null) {
 %>
    <form method="POST" action="<%=baseURL%>/consumer/">
       <strong>OpenID:</strong>
       <input type="text" name="openid" size="60"/><br>
       <input type="submit"/>
    </form>
 <%
  } else {

 %>

 Logged in as <%= session.getAttribute("openid") %><p>
 <a href="?logout=true">Log out</a>

 <% } %>
</body>
</html>
