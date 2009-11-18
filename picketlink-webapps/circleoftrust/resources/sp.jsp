
<form name="add_idp" action="/circleoftrust/COTServlet" method="post">
<div align="center">
<h1>Configure a Service Provider </h1>
<br/>
Name of the Service Provider:
<input type="text" name="spname"  value="ENTER SP NAME" /> <br/>
IDPName:
<input type="text" name="idpname"  value="ENTER IDP NAME" /> <br/>
Metadata URL of Identity Provider:
<input type="text" name="metadataURL" value="ENTER Metadata URL" /> <br/>
<input type="hidden" name="type" value="sp" /> <br/>
<input type="hidden" name="action" value="add" /> <br/>
<input type="submit" value="Submit" /> <br/>
</div>
</form> 
