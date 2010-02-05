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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.Import;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.seam.federation.configuration.SamlIdentityProvider;

/**
* @author Marcel Kolsteren
* @since Jan 16, 2010
*/
@Name("org.picketlink.identity.seam.federation.samlSingleSignOnSender")
@AutoCreate
@Import("org.picketlink.identity.seam.federation")
public class SamlSingleSignOnSender
{
   @In
   private Requests requests;

   @In
   private SamlMessageFactory samlMessageFactory;

   @In
   private SamlMessageSender samlMessageSender;

   public void sendAuthenticationRequestToIDP(HttpServletRequest request, HttpServletResponse response,
         SamlIdentityProvider samlIdentityProvider, String returnUrl)
   {
      AuthnRequestType authnRequest = samlMessageFactory.createAuthnRequest();
      requests.addRequest(authnRequest.getID(), samlIdentityProvider, returnUrl);

      samlMessageSender.sendRequestToIDP(request, response, samlIdentityProvider, SamlProfile.SINGLE_SIGN_ON,
            authnRequest);
   }
}
