<%@ page import="org.jboss.identity.federation.saml.v2.metadata.*,org.jboss.identity.federation.api.saml.v2.metadata.*" %> 

<div align="center">
An IDP has been added as a trusted provider.<br/>


Information on the IDP: <br/>

<textarea name="metadataValue" rows="30" cols="40">
<%
   EntityDescriptorType edt = (EntityDescriptorType)session.getAttribute("idp");

   out.println(MetaDataExtractor.toString(edt));

   session.removeAttribute("idp");
%>

</textarea>

<br/>
<br/>
</div>
<a href="<%=request.getContextPath()%>/index.jsp">Back</a>
