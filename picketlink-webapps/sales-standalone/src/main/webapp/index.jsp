<div align="center">
<h1>SalesTool</h1>
<br/>
Welcome to the Sales Tool,
<%
java.security.Principal principal = (java.security.Principal)session.getAttribute("picketlink.principal");
if(principal != null)
out.println(principal.getName());
else
out.println("Null Principal");
%>



<br/>
Here is your sales chart:
<br/>
<img src="piechart.gif"/>

<br/>
<a href="?GLO=true">Click to LogOut</a>
</div>
