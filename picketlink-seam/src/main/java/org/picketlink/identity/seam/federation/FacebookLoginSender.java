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
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.core.Events;
import org.jboss.seam.security.Identity;
import org.picketlink.identity.seam.federation.configuration.ServiceProvider;

/**
* Component for sending login requests to Facebook.
* 
* @author Marcel Kolsteren
* @since Sep 25, 2010
*/
@Name("org.picketlink.identity.seam.federation.facebookLoginSender")
@AutoCreate
public class FacebookLoginSender
{

   @In
   private ServiceProvider serviceProvider;

   public void sendAuthorizeRequest(String returnUrl, HttpServletResponse response)
   {
      Events.instance().raiseEvent(Identity.EVENT_PRE_AUTHENTICATE);

      String returnUri = getReturnUri(returnUrl);
      String clientId = serviceProvider.getFacebookConfiguration().getClientId();
      Map<String, String> params = new HashMap<String, String>();
      params.put(OAuthConstants.REDIRECT_URI_PARAMETER, returnUri);
      params.put(OAuthConstants.CLIENT_ID_PARAMETER, clientId);
      String scope = serviceProvider.getFacebookConfiguration().getScope();
      if (scope != null)
      {
         params.put(OAuthConstants.SCOPE_PARAMETER, scope);
      }
      String location = new StringBuilder(FacebookConstants.AUTHENTICATION_ENDPOINT_URL).append("?").append(
            createQueryString(params)).toString();
      try
      {
         response.sendRedirect(location);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   public URLConnection sendAccessTokenRequest(String returnUrl, String authorizationCode, HttpServletResponse response)
   {
      String returnUri = getReturnUri(returnUrl);
      String clientId = serviceProvider.getFacebookConfiguration().getClientId();
      String clientSecret = serviceProvider.getFacebookConfiguration().getClientSecret();

      Map<String, String> params = new HashMap<String, String>();
      params.put(OAuthConstants.REDIRECT_URI_PARAMETER, returnUri);
      params.put(OAuthConstants.CLIENT_ID_PARAMETER, clientId);
      params.put(OAuthConstants.CLIENT_SECRET_PARAMETER, clientSecret);
      params.put(OAuthConstants.CODE_PARAMETER, authorizationCode);
      String location = new StringBuilder(FacebookConstants.ACCESS_TOKEN_ENDPOINT_URL).append("?").append(
            createQueryString(params)).toString();

      try
      {
         URL url = new URL(location);
         URLConnection connection = url.openConnection();
         return connection;
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   private String getReturnUri(String returnUrl)
   {
      String serviceUrl = serviceProvider.getServiceURL(ExternalAuthenticationService.FACEBOOK_SERVICE);
      Map<String, String> params = new HashMap<String, String>();
      params.put(ExternalAuthenticationFilter.RETURN_URL_PARAMETER, returnUrl);
      return new StringBuilder(serviceUrl).append("?").append(createQueryString(params)).toString();
   }

   private String createQueryString(Map<String, String> params)
   {
      StringBuilder queryString = new StringBuilder();
      boolean first = true;
      for (Map.Entry<String, String> entry : params.entrySet())
      {
         String paramName = entry.getKey();
         String paramValue = entry.getValue();
         if (first)
         {
            first = false;
         }
         else
         {
            queryString.append("&");
         }
         queryString.append(paramName).append("=");
         String encodedParamValue;
         try
         {
            encodedParamValue = URLEncoder.encode(paramValue, "UTF-8");
         }
         catch (UnsupportedEncodingException e)
         {
            throw new RuntimeException(e);
         }
         queryString.append(encodedParamValue);
      }
      return queryString.toString();
   }
}
