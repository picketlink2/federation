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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.Import;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.faces.FacesManager;
import org.picketlink.identity.seam.federation.configuration.Configuration;
import org.picketlink.identity.seam.federation.configuration.SamlIdentityProvider;
import org.picketlink.identity.seam.federation.configuration.ServiceProvider;

/**
 * Seam component that manages the external authentication of users (using, for example, SAML or OpenID).
 * 
* @author Marcel Kolsteren
* @since Dec 27, 2009
*/
@Name("org.picketlink.identity.seam.federation.externalAuthenticator")
@AutoCreate
@Import("org.picketlink.identity.seam.federation")
public class ExternalAuthenticator
{
   private String returnUrl;

   private String openId;

   @In
   private ServiceProvider serviceProvider;

   public void samlSignOn(String idpEntityId)
   {
      SamlIdentityProvider idp = Configuration.instance().getServiceProvider().getSamlConfiguration()
            .getSamlIdentityProviderByEntityId(idpEntityId);
      if (idp == null)
      {
         throw new RuntimeException("Identity provider " + idpEntityId + " not found");
      }

      String authenticationServiceURL = Configuration.instance().getServiceProvider().getServiceURL(
            ExternalAuthenticationService.AUTHENTICATION_SERVICE);
      Map<String, String> params = new HashMap<String, String>();
      params.put(ExternalAuthenticationFilter.IDP_ENTITY_ID_PARAMETER, idpEntityId);
      params.put(ExternalAuthenticationFilter.RETURN_URL_PARAMETER, returnUrl);
      redirect(authenticationServiceURL, params);
   }

   public void openIdSignOn()
   {
      openIdSignOn(openId);
   }

   public void openIdSignOn(String openId)
   {
      String authenticationServiceURL = Configuration.instance().getServiceProvider().getServiceURL(
            ExternalAuthenticationService.AUTHENTICATION_SERVICE);
      Map<String, String> params = new HashMap<String, String>();
      params.put(ExternalAuthenticationFilter.RETURN_URL_PARAMETER, returnUrl);
      params.put(ExternalAuthenticationFilter.OPEN_ID_PARAMETER, openId);
      redirect(authenticationServiceURL, params);
   }

   public void singleLogout()
   {
      String logoutServiceURL = serviceProvider.getServiceURL(ExternalAuthenticationService.LOGOUT_SERVICE);
      redirect(logoutServiceURL, null);
   }

   private void redirect(String urlBase, Map<String, String> params)
   {
      StringBuilder url = new StringBuilder();
      url.append(urlBase);
      if (params != null && params.size() > 0)
      {
         url.append("?");
         boolean first = true;
         for (Map.Entry<String, String> paramEntry : params.entrySet())
         {
            if (first)
            {
               first = false;
            }
            else
            {
               url.append("&");
            }
            url.append(paramEntry.getKey());
            url.append("=");
            try
            {
               url.append(URLEncoder.encode(paramEntry.getValue(), "UTF-8"));
            }
            catch (UnsupportedEncodingException e)
            {
               throw new RuntimeException(e);
            }
         }
      }

      FacesManager.instance().redirectToExternalURL(url.toString());
   }

   public String getReturnUrl()
   {
      return returnUrl;
   }

   public void setReturnUrl(String returnUrl)
   {
      this.returnUrl = returnUrl;
   }

   public String getOpenId()
   {
      return openId;
   }

   public void setOpenId(String openId)
   {
      this.openId = openId;
   }
}
