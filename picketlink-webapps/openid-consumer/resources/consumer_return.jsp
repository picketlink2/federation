<%@ page session="true" %>
<%@ page import="org.picketlink.identity.federation.api.openid.*, org.picketlink.identity.federation.web.openid.*" %>

<html>
<body>


<%
    // extract the receiving URL from the HTTP request
    StringBuffer receivingURL = request.getRequestURL();
    String queryString = request.getQueryString();
    if (queryString != null && queryString.length() > 0)
        receivingURL.append("?").append(request.getQueryString());
    
    OpenIDManager manager = (OpenIDManager)session.getAttribute("openid_manager");

    HTTPProtocolAdaptor adapter = new HTTPProtocolAdaptor(new HTTPOpenIDContext(request,response,application));
    boolean auth = manager.verify(adapter, request.getParameterMap(), receivingURL.toString());
%>

<%
    if(auth)
  {
    out.println("Should have redirected to index page as we are authenticated successfully");
  }
  else
  {
%>
  Not Logged In!!!
<%}%>
</body>
</html>
