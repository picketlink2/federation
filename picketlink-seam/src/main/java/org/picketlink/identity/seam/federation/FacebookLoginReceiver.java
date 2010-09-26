/*
* JBoss, Home of Professional Open Source.
* Copyright 2008, Red Hat Middleware LLC, and individual contributors
* as indicated by the @author tags. See the copyright.txt file in the
* distribution for a full listing of individual contributors. 
*
* This is free software; you can redistribute it and/or modify it
* under the terms of the GNU Lesser General Public License as
* published by the Free Software Foundation; either version 2.1 of
* the License, or (at your option) any later version.
*
* This software is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this software; if not, write to the Free
* Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
* 02110-1301 USA, or see the FSF site: http://www.fsf.org.
*/
package org.picketlink.identity.seam.federation;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.core.Events;
import org.jboss.seam.security.Identity;
import org.json.JSONException;
import org.json.JSONObject;
import org.picketlink.identity.seam.federation.configuration.ServiceProvider;

/**
* @author Marcel Kolsteren
* @since Sep 25, 2010
*/
@Name("org.picketlink.identity.seam.federation.facebookLoginReceiver")
@AutoCreate
public class FacebookLoginReceiver
{
   @In
   private FacebookLoginSender facebookLoginSender;

   @In
   private InternalAuthenticator internalAuthenticator;

   @In
   private ServiceProvider serviceProvider;

   public void handleAuthenticationResponse(HttpServletRequest request, HttpServletResponse response)
   {
      String error = request.getParameter(OAuthConstants.ERROR_PARAMETER);
      if (error != null)
      {
         sendErrorRedirect(response, error);
      }
      else
      {
         String returnUrl = request.getParameter(ExternalAuthenticationFilter.RETURN_URL_PARAMETER);
         if (returnUrl == null)
         {
            throw new RuntimeException("Return URL parameter not found");
         }
         String authorizationCode = request.getParameter(OAuthConstants.CODE_PARAMETER);
         if (returnUrl == null)
         {
            throw new RuntimeException("Authorization code parameter not found");
         }

         URLConnection connection = facebookLoginSender.sendAccessTokenRequest(returnUrl, authorizationCode, response);

         if (connection.getContentType().startsWith("text/plain"))
         {
            Map<String, String> params = formUrlDecode(readUrlContent(connection));
            String accessToken = params.get(OAuthConstants.ACCESS_TOKEN_PARAMETER);
            if (accessToken == null)
            {
               throw new RuntimeException("No access token found");
            }
            else
            {
               login(request, response, accessToken, returnUrl);
            }
         }
         else if (connection.getContentType().equals("application/json"))
         {
            sendErrorRedirect(response, readUrlContent(connection));
         }
         else
         {
            throw new RuntimeException("Unsupported content type: " + connection.getContentType());
         }
      }
   }

   private Map<String, String> formUrlDecode(String encodedData)
   {
      Map<String, String> params = new HashMap<String, String>();
      String[] elements = encodedData.split("&");
      for (String element : elements)
      {
         String[] pair = element.split("=");
         if (pair.length == 2)
         {
            String paramName = pair[0];
            String paramValue;
            try
            {
               paramValue = URLDecoder.decode(pair[1], "UTF-8");
            }
            catch (UnsupportedEncodingException e)
            {
               throw new RuntimeException(e);
            }
            params.put(paramName, paramValue);
         }
         else
         {
            throw new RuntimeException("Unexpected name-value pair in response: " + element);
         }
      }
      return params;
   }

   public void login(HttpServletRequest request, HttpServletResponse response, String accessToken, String returnUrl)
   {
      FacebookPrincipal facebookPrincipal = null;
      try
      {
         String urlString = new StringBuilder(FacebookConstants.PROFILE_ENDPOINT_URL).append("?access_token=").append(
               URLEncoder.encode(accessToken, "UTF-8")).toString();
         URL profileUrl = new URL(urlString);
         String profileContent = readUrlContent(profileUrl.openConnection());
         JSONObject jsonObject = new JSONObject(profileContent);

         facebookPrincipal = new FacebookPrincipal();
         facebookPrincipal.setAccessToken(accessToken);
         facebookPrincipal.setId(jsonObject.getString("id"));
         facebookPrincipal.setName(jsonObject.getString("name"));
         facebookPrincipal.setFirstName(jsonObject.getString("first_name"));
         facebookPrincipal.setLastName(jsonObject.getString("last_name"));
         facebookPrincipal.setGender(jsonObject.getString("gender"));
         facebookPrincipal.setTimezone(jsonObject.getString("timezone"));
         facebookPrincipal.setLocale(jsonObject.getString("locale"));
         if (jsonObject.getString("email") != null)
         {
            facebookPrincipal.setEmail(jsonObject.getString("email"));
         }
      }
      catch (JSONException e)
      {
         throw new RuntimeException(e);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }

      boolean authenticated = internalAuthenticator.authenticate(facebookPrincipal, request);

      try
      {
         if (authenticated)
         {
            response.sendRedirect(returnUrl);
         }
         else
         {
            sendErrorRedirect(response, null);
         }
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   private void sendErrorRedirect(HttpServletResponse response, String message)
   {
      LoginException exception = message != null ? new LoginException(message) : new LoginException();
      Events.instance().raiseEvent(Identity.EVENT_LOGIN_FAILED, exception);
      try
      {
         response.sendRedirect(serviceProvider.getFailedAuthenticationUrl());
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   private String readUrlContent(URLConnection connection)
   {
      StringBuilder result = new StringBuilder();
      try
      {
         Reader reader = new InputStreamReader(connection.getInputStream());
         char[] buffer = new char[50];
         int nrOfChars;
         while ((nrOfChars = reader.read(buffer)) != -1)
         {
            result.append(buffer, 0, nrOfChars);
         }
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
      return result.toString();
   }
}
