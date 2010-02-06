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

import java.util.HashMap;
import java.util.Map;

import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;

import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Startup;
import org.jboss.seam.annotations.intercept.BypassInterceptors;
import org.jboss.seam.faces.FacesManager;
import org.jboss.seam.navigation.Pages;
import org.picketlink.identity.seam.federation.configuration.Configuration;
import org.picketlink.identity.seam.federation.configuration.OpenIdConfiguration;
import org.picketlink.identity.seam.federation.configuration.SamlConfiguration;
import org.picketlink.identity.seam.federation.configuration.ServiceProvider;

/**
 * Override of Seam's Pages component. It replaces the login page redirection method with a version
 * that redirects to an URL that is filtered by the SamlAuthenticationFilter.
 * 
 * @author Marcel Kolsteren
 */
@Scope(ScopeType.APPLICATION)
@BypassInterceptors
@Name("org.jboss.seam.navigation.pages")
@Install(precedence = Install.FRAMEWORK, classDependencies = "javax.faces.context.FacesContext")
@Startup
public class PagesSupportingExternalAuthentication extends Pages
{
   @Override
   public void redirectToLoginView()
   {
      notLoggedIn();

      HttpServletRequest httpRequest = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext()
            .getRequest();

      StringBuffer returnUrl = httpRequest.getRequestURL();

      ExternalAuthenticator externalAuthenticator = (ExternalAuthenticator) Component
            .getInstance(ExternalAuthenticator.class);
      externalAuthenticator.setReturnUrl(returnUrl.toString());

      ServiceProvider serviceProvider = Configuration.instance().getServiceProvider();

      // Use default SAML identity provider, if configured
      SamlConfiguration samlConfiguration = serviceProvider.getSamlConfiguration();
      if (samlConfiguration != null && samlConfiguration.getDefaultIdentityProvider() != null)
      {
         externalAuthenticator.samlSignOn(samlConfiguration.getDefaultIdentityProvider().getEntityId());
      }
      else
      {
         // Otherwise, use default OpenId identity provider, if configured
         OpenIdConfiguration openIdConfiguration = serviceProvider.getOpenIdConfiguration();
         if (openIdConfiguration != null && openIdConfiguration.getDefaultOpenIdProvider() != null)
         {
            externalAuthenticator.openIdSignOn(openIdConfiguration.getDefaultOpenIdProvider());
         }
         else
         {
            // Otherwise, redirect to the login view, so that the user can choose an IDP
            if (getLoginViewId() == null)
            {
               throw new RuntimeException("Login view id not specified in pages.xml.");
            }
            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put(ExternalAuthenticationFilter.RETURN_URL_PARAMETER, returnUrl);
            FacesManager.instance().redirect(getLoginViewId(), parameters, false);
         }
      }
   }
}
