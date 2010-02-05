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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.Import;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.security.Identity;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.saml.v2.protocol.LogoutRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.RequestAbstractType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusResponseType;
import org.picketlink.identity.seam.federation.configuration.Binding;
import org.picketlink.identity.seam.federation.configuration.SamlEndpoint;
import org.picketlink.identity.seam.federation.configuration.SamlIdentityProvider;
import org.picketlink.identity.seam.federation.configuration.ServiceProvider;

/**
* @author Marcel Kolsteren
* @since Jan 24, 2010
*/
@Name("org.picketlink.identity.seam.federation.samlSingleLogoutReceiver")
@AutoCreate
@Import("org.picketlink.identity.seam.federation")
public class SamlSingleLogoutReceiver
{
   @In
   private SamlMessageFactory samlMessageFactory;

   @In
   private SamlMessageSender samlMessageSender;

   @In
   private Identity identity;

   @In
   private ServiceProvider serviceProvider;

   public void processIDPRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
         RequestAbstractType request, SamlIdentityProvider idp) throws InvalidRequestException
   {
      if (!(request instanceof LogoutRequestType))
      {
         throw new InvalidRequestException("Request should be a single logout request.");
      }

      if (!identity.isLoggedIn())
      {
         throw new InvalidRequestException("No active session to logout.");
      }

      Identity.instance().logout();

      StatusResponseType response = samlMessageFactory.createStatusResponse(request,
            JBossSAMLURIConstants.STATUS_SUCCESS.get(), null);

      Binding binding = httpRequest.getMethod().equals("POST") ? Binding.HTTP_Post : Binding.HTTP_Redirect;
      SamlEndpoint endpoint = idp.getService(SamlProfile.SINGLE_LOGOUT).getEndpointForBinding(binding);

      samlMessageSender.sendResponseToIDP(httpRequest, httpResponse, idp, endpoint, response);
   }

   public void processIDPResponse(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
         StatusResponseType response, RequestContext requestContext, SamlIdentityProvider idp)
   {
      if (response.getStatus() != null
            && response.getStatus().getStatusCode().getValue().equals(JBossSAMLURIConstants.STATUS_SUCCESS.get()))
      {
         Identity.instance().logout();
      }
      else
      {
         throw new RuntimeException("Single logout failed. Status code: "
               + (response.getStatus() == null ? "null" : response.getStatus().getStatusCode().getValue()));
      }
      try
      {
         httpResponse.sendRedirect(serviceProvider.getLoggedOutUrl());
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }
}
