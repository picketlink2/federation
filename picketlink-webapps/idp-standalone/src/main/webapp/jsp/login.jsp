<html><head><title>Login Page</title></head>
<body>
<font size='5' color='blue'>Please Login</font><hr>

<form action='<%=application.getContextPath()%>/' method='post'>
<table>
 <tr><td>Name:</td>
   <td><input type='text' name='JBID_USERNAME'></td></tr>
 <tr><td>Password:</td> 
   <td><input type='password' name='JBID_PASSWORD' size='8'></td>
 </tr>
</table>
<br>
  <input type='submit' value='login'> 
</form></body>
 </html>
