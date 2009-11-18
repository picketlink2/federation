<%@ page import="java.util.*" %>

<div align="center">
Trusted Providers for the Identity Provider:<%=session.getAttribute("idpName")%> <br/>

<%
   HashMap<String,String> trustedProviders = (HashMap<String,String>)session.getAttribute("providers");
   if(trustedProviders != null)
   {
     Set<String> keys = trustedProviders.keySet();
     for(String key: keys) 
     {
       out.println("TrustedProvider="+key);
     }
   }

   //Remove the session attributes
   session.removeAttribute("idpName");
   session.removeAttribute("providers");
%>
<br/>
<a href="<%=request.getContextPath()%>/index.jsp">Back</a>
</div>
</form> 
