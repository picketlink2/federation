<%
 session.setAttribute("authenticatedAndApproved", Boolean.TRUE); 
%>


You have logged in.

<form method="POST" action="<%=request.getContextPath()%>/provider/?_action=complete">
<input type="submit" value="Continue"/>
</form>
