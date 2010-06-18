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
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.Import;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.ax.FetchRequest;
import org.picketlink.identity.seam.federation.configuration.ServiceProvider;
import org.picketlink.identity.seam.federation.jaxb.config.OpenIdAttributeType;

/**
* @author Marcel Kolsteren
* @since Jan 29, 2010
*/
@Name("org.picketlink.identity.seam.federation.openIdSingleLoginSender")
@AutoCreate
@Import("org.picketlink.identity.seam.federation")
public class OpenIdSingleLoginSender
{
   @In
   private OpenIdRequest openIdRequest;

   @In
   private ConsumerManager openIdConsumerManager;

   @In
   private ServiceProvider serviceProvider;

   public String sendAuthRequest(String openId, String returnUrl, HttpServletResponse httpResponse)
   {
      try
      {
         @SuppressWarnings("unchecked")
         List<DiscoveryInformation> discoveries = openIdConsumerManager.discover(openId);

         DiscoveryInformation discovered = openIdConsumerManager.associate(discoveries);

         openIdRequest.setDiscoveryInformation(discovered);
         openIdRequest.setReturnUrl(returnUrl);

         String openIdServiceUrl = serviceProvider.getServiceURL(ExternalAuthenticationService.OPEN_ID_SERVICE);
         String realm = serviceProvider.getOpenIdRealm();
         AuthRequest authReq = openIdConsumerManager.authenticate(discovered, openIdServiceUrl, realm);

         // Request attributes
         List<OpenIdAttributeType> attributes = serviceProvider.getOpenIdConfiguration().getAttributes();
         if (attributes.size() > 0)
         {
            FetchRequest fetch = FetchRequest.createFetchRequest();
            for (OpenIdAttributeType attribute : attributes)
            {
               fetch.addAttribute(attribute.getAlias(), attribute.getTypeUri(), attribute.isRequired());
            }
            // attach the extension to the authentication request
            authReq.addExtension(fetch);
         }

         String url = authReq.getDestinationUrl(true);

         httpResponse.sendRedirect(url);
      }
      catch (OpenIDException e)
      {
         try
         {
            httpResponse.sendRedirect(serviceProvider.getFailedAuthenticationUrl());
         }
         catch (IOException e1)
         {
            throw new RuntimeException(e);
         }
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }

      return null;
   }
}
