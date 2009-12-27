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

import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;

import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.intercept.BypassInterceptors;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.faces.FacesManager;

/**
 * Seam component that manages the external authentication of users (using, for example, SAML or OpenID).
 * 
* @author Marcel Kolsteren
* @since Dec 27, 2009
*/
@Name("org.picketlink.identity.seam.federation.externalAuthenticator")
@BypassInterceptors
public class ExternalAuthenticator
{
   public void startAuthentication()
   {
      Integer relayState = Integer.valueOf((String) Contexts.getPageContext().get("relayState"));
      if (relayState == null)
      {
         throw new IllegalStateException(
               "relayState parameter not found; the cause may be that the startExternalAuthentication method is not called from the login page, or that the login page doesn't have a page parameter with the name relayState");
      }
      startAuthentication(relayState);
   }

   public void startAuthentication(Integer relayState)
   {
      HttpServletRequest httpRequest = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext()
            .getRequest();

      String authenticationFilterURL = httpRequest.getScheme() + "://" + httpRequest.getServerName() + ":"
            + httpRequest.getServerPort() + httpRequest.getContextPath() + "/SamlAuthenticationFilter.seam";
      FacesManager.instance().redirectToExternalURL(authenticationFilterURL + "?newRelayState=" + relayState);
   }
}
