
<form name="add_sp" action="/circleoftrust/COTServlet" method="post">
<div align="center">
<h1>Configure a Identity Provider </h1>
<br/>

Name of Identity Provider:
<input type="text" name="idpname"  value="ENTER IDP NAME" /> <br/>
Name of the Service Provider:
<input type="text" name="spname"  value="ENTER SP NAME" /> <br/>
Metadata URL of Service Provider:
<input type="text" name="metadataURL" value="ENTER Metadata URL" /> <br/>
<input type="hidden" name="type" value="idp" /> <br/>
<input type="hidden" name="action" value="add" /> <br/>
<input type="submit" value="Submit" /> <br/>
</div>
</form> 
