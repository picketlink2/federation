<div align="center">
<h1>EmployeeDashboard</h1>
<br/>
Welcome to the Employee Tool,
<%
java.security.Principal principal = (java.security.Principal)session.getAttribute("picketlink.principal");
if(principal != null)
out.println(principal.getName());
else
out.println("Null Principal");
%>

<br/>
Here is your cartoon of the day:
<br/>
<img src="careermap.jpg"/>

<br/>
<a href="?GLO=true">Click to LogOut</a>

</div>
