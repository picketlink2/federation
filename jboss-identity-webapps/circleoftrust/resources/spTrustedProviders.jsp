<%@ page import="java.util.*" %>

<div align="center">
Trusted Providers for the Service Provider:<%=session.getAttribute("spName")%> <br/>

<textarea name="sptrustedproviders" rows="30" columns="50">

<%
   out.println(session.getAttribute("spName"));
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
   session.removeAttribute("spName");
   session.removeAttribute("providers");
%>

</textarea>

</div>
</form> 
