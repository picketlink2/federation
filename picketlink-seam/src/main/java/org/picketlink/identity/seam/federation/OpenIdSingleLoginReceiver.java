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
import java.net.URL;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.Import;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.core.Events;
import org.jboss.seam.security.Identity;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchResponse;
import org.picketlink.identity.seam.federation.configuration.ServiceProvider;

/**
* @author Marcel Kolsteren
* @since Jan 24, 2010
*/
@Name("org.picketlink.identity.seam.federation.openIdSingleLoginReceiver")
@AutoCreate
@Import("org.picketlink.identity.seam.federation")
public class OpenIdSingleLoginReceiver
{
   @In
   private OpenIdRequest openIdRequest;

   @In
   private ConsumerManager openIdConsumerManager;

   @In
   private InternalAuthenticator internalAuthenticator;

   @In
   private ServiceProvider serviceProvider;

   @SuppressWarnings("unchecked")
   public void handleIncomingMessage(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
         throws InvalidRequestException
   {
      try
      {
         // extract the parameters from the authentication response
         // (which comes in as a HTTP request from the OpenID provider)
         ParameterList response = new ParameterList(httpRequest.getParameterMap());

         // retrieve the previously stored discovery information
         DiscoveryInformation discovered = openIdRequest.getDiscoveryInformation();

         // extract the receiving URL from the HTTP request
         StringBuffer receivingURL = httpRequest.getRequestURL();
         String queryString = httpRequest.getQueryString();
         if (queryString != null && queryString.length() > 0)
            receivingURL.append("?").append(httpRequest.getQueryString());

         // verify the response; ConsumerManager needs to be the same
         // (static) instance used to place the authentication request
         VerificationResult verification = openIdConsumerManager.verify(receivingURL.toString(), response, discovered);

         boolean authenticated = true;

         // examine the verification result and extract the verified identifier
         Identifier identifier = verification.getVerifiedId();

         if (identifier != null)
         {
            AuthSuccess authSuccess = (AuthSuccess) verification.getAuthResponse();

            Map<String, List<String>> attributes = null;
            if (authSuccess.hasExtension(AxMessage.OPENID_NS_AX))
            {
               FetchResponse fetchResp = (FetchResponse) authSuccess.getExtension(AxMessage.OPENID_NS_AX);

               attributes = fetchResp.getAttributes();
            }

            OpenIdPrincipal principal = createPrincipal(identifier.getIdentifier(), discovered.getOPEndpoint(),
                  attributes);

            authenticated = internalAuthenticator.authenticate(principal, httpRequest);
         }
         else
         {
            if (Events.exists())
            {
               Events.instance().raiseEvent(Identity.EVENT_LOGIN_FAILED, new LoginException());
            }
            authenticated = false;
         }

         if (authenticated)
         {
            httpResponse.sendRedirect(openIdRequest.getReturnUrl());
         }
         else
         {
            httpResponse.sendRedirect(serviceProvider.getFailedAuthenticationUrl());
         }
      }
      catch (OpenIDException e)
      {
         throw new RuntimeException(e);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }

   }

   private OpenIdPrincipal createPrincipal(String identifier, URL openIdProvider, Map<String, List<String>> attributes)
   {
      return new OpenIdPrincipal(identifier, openIdProvider, attributes);
   }
}
