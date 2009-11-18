<%@ page import="org.jboss.identity.federation.saml.v2.metadata.*,org.jboss.identity.federation.api.saml.v2.metadata.*" %> 

<div align="center">
An SP has been added as a trusted provider.<br/>


Information on the SP: <br/>

<textarea name="metadataValue" rows="30" cols="40">
<%
   EntityDescriptorType edt = (EntityDescriptorType)session.getAttribute("sp");

   out.println(MetaDataExtractor.toString(edt));

   session.removeAttribute("sp");
%>

</textarea>

<br/>
<br/>
</div>
<a href="<%=request.getContextPath()%>/index.jsp">Back</a>
