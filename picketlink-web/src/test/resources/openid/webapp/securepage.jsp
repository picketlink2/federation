<%
 session.setAttribute("authenticatedAndApproved", Boolean.TRUE);
 if( request.getUserPrincipal() != null )
 {
    session.setAttribute( "openid.claimed_id", request.getUserPrincipal().getName());
 }
%>


You have logged in.

<form method="POST" action="<%=request.getContextPath()%>/provider/?_action=complete">
<input type="submit" value="Continue"/>
</form>
