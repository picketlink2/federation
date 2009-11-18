
<form name="display_trusted_providers" action="/circleoftrust/COTServlet" method="post">
<div align="center">
Display Trusted Provider <br/>
Choose Type:
<input type="radio" name="type" value="sp"> Service Provider
<input type="radio" name="type" value="idp" checked> Identity Provider<br>
Name:
<input type="text" name="name"  value="ENTER NAME" /> <br/>
<input type="hidden" name="action" value="display_trusted_providers" /> <br/>
<input type="submit" value="Display Trusted Providers" /> <br/>
</div>
</form> 
