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

import static org.jboss.seam.ScopeType.APPLICATION;

import java.io.IOException;

import javax.security.auth.login.LoginException;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.Component;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.intercept.BypassInterceptors;
import org.jboss.seam.annotations.web.Filter;
import org.jboss.seam.log.Log;
import org.jboss.seam.security.Identity;
import org.jboss.seam.servlet.ContextualHttpServletRequest;
import org.jboss.seam.web.AbstractFilter;
import org.picketlink.identity.seam.federation.configuration.Configuration;
import org.picketlink.identity.seam.federation.configuration.SamlIdentityProvider;

/**
 * Seam Servlet Filter supporting SAMLv2 authentication. It implements the Web
 * Browser SSO Profile. For outgoing authentication requests it can use either
 * HTTP Post or HTTP Redirect binding. For the responses, it uses HTTP Post
 * binding, with or without signature validation.
 * 
 * @author Marcel Kolsteren
 * @author Anil Saldhana
 */
@Scope(APPLICATION)
@Name("org.picketlink.identity.seam.federation.externalAuthenticationFilter")
@BypassInterceptors
@Filter(within = "org.jboss.seam.web.exceptionFilter")
@Install(true)
public class ExternalAuthenticationFilter extends AbstractFilter
{
   public static final String IDP_ENTITY_ID_PARAMETER = "idpEntityId";

   public static final String RETURN_URL_PARAMETER = "returnUrl";

   public static final String OPEN_ID_PARAMETER = "openId";

   @Logger
   private Log log;

   @Override
   public void init(FilterConfig filterConfig) throws ServletException
   {
      super.init(filterConfig);
      Configuration.instance().setContextRoot(filterConfig.getServletContext().getContextPath());
   }

   public void doFilter(ServletRequest request, ServletResponse response, final FilterChain chain) throws IOException,
         ServletException
   {
      if (!(request instanceof HttpServletRequest))
      {
         throw new ServletException("This filter can only process HttpServletRequest requests");
      }

      final HttpServletRequest httpRequest = (HttpServletRequest) request;
      final HttpServletResponse httpResponse = (HttpServletResponse) response;

      final ExternalAuthenticationService service = determineService(httpRequest);

      if (service != null)
      {
         try
         {
            new ContextualHttpServletRequest(httpRequest)
            {
               @Override
               public void process() throws ServletException, IOException, LoginException
               {
                  try
                  {
                     doFilter(httpRequest, httpResponse, service);
                  }
                  catch (InvalidRequestException e)
                  {
                     httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                     if (log.isInfoEnabled())
                     {
                        log.info("Bad request received from {0} ({1})", e.getCause(), httpRequest.getRemoteHost(), e
                              .getDescription());
                     }
                  }
               }
            }.run();
         }
         catch (ServletException e)
         {
            throw new RuntimeException(e);
         }
         catch (IOException e)
         {
            throw new RuntimeException(e);
         }
      }
      else
      {
         // Request is not related to external authentication. Pass the request on to
         // the next filter in the chain.
         chain.doFilter(httpRequest, httpResponse);
      }
   }

   private void doFilter(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
         ExternalAuthenticationService service) throws InvalidRequestException, IOException, ServletException
   {
      SamlMessageReceiver samlMessageReceiver = (SamlMessageReceiver) Component.getInstance(SamlMessageReceiver.class);
      OpenIdSingleLoginReceiver openIdSingleLoginReceiver = (OpenIdSingleLoginReceiver) Component
            .getInstance(OpenIdSingleLoginReceiver.class);

      switch (service)
      {
         case OPEN_ID_SERVICE :
            openIdSingleLoginReceiver.handleIncomingMessage(httpRequest, httpResponse);
            break;
         case SAML_SINGLE_LOGOUT_SERVICE :
            samlMessageReceiver.handleIncomingSamlMessage(SamlProfile.SINGLE_LOGOUT, httpRequest, httpResponse);
            break;
         case SAML_ASSERTION_CONSUMER_SERVICE :
            samlMessageReceiver.handleIncomingSamlMessage(SamlProfile.SINGLE_SIGN_ON, httpRequest, httpResponse);
            break;
         case AUTHENTICATION_SERVICE :
            String returnUrl = httpRequest.getParameter(RETURN_URL_PARAMETER);

            String providerName = httpRequest.getParameter(IDP_ENTITY_ID_PARAMETER);
            if (providerName != null)
            {
               SamlIdentityProvider identityProvider = Configuration.instance().getServiceProvider()
                     .getSamlConfiguration().getSamlIdentityProviderByEntityId(providerName);

               // User requested a page for which login is required. Return a page
               // that instructs the browser to post an authentication request to the IDP.
               if (identityProvider instanceof SamlIdentityProvider)
               {
                  SamlSingleSignOnSender samlSingleSignOnSender = (SamlSingleSignOnSender) Component
                        .getInstance(SamlSingleSignOnSender.class);
                  samlSingleSignOnSender.sendAuthenticationRequestToIDP(httpRequest, httpResponse,
                        (SamlIdentityProvider) identityProvider, returnUrl);
               }
               else
               {
                  throw new RuntimeException("Only SAML identity providers are supported in this version");
               }
            }
            else
            {
               OpenIdSingleLoginSender openIdSingleLoginSender = (OpenIdSingleLoginSender) Component
                     .getInstance(OpenIdSingleLoginSender.class);
               String openId = httpRequest.getParameter(OPEN_ID_PARAMETER);
               openIdSingleLoginSender.sendAuthRequest(openId, returnUrl, httpResponse);
            }
            break;
         case LOGOUT_SERVICE :
            Identity identity = (Identity) Component.getInstance(Identity.class);

            if (!identity.isLoggedIn())
            {
               throw new RuntimeException("User not logged in.");
            }
            SamlPrincipal principal = (SamlPrincipal) identity.getPrincipal();
            SamlIdentityProvider idp = principal.getIdentityProvider();
            if (!(idp instanceof SamlIdentityProvider))
            {
               throw new RuntimeException("Only SAML identity providers are supported in this version");
            }

            SamlSingleLogoutSender samlSingleLogoutSender = (SamlSingleLogoutSender) Component
                  .getInstance(SamlSingleLogoutSender.class);

            samlSingleLogoutSender.sendSingleLogoutRequestToIDP(httpRequest, httpResponse, identity);
            break;
         case SAML_META_DATA_SERVICE :
            SamlMetaDataProvider samlMetaDataProvider = (SamlMetaDataProvider) Component
                  .getInstance(SamlMetaDataProvider.class);

            samlMetaDataProvider.writeMetaData(httpResponse.getOutputStream());
            httpResponse.setCharacterEncoding("UTF-8");
            httpResponse.setContentType("application/xml");
            httpResponse.flushBuffer();
            break;
         default :
            throw new RuntimeException("Unsupported service " + service);
      }
   }

   private ExternalAuthenticationService determineService(HttpServletRequest httpRequest)
   {
      String path = ((HttpServletRequest) httpRequest).getRequestURI().replace(".seam", "");

      for (ExternalAuthenticationService service : ExternalAuthenticationService.values())
      {
         if (path.endsWith("/" + service.getName()))
         {
            return service;
         }
      }
      return null;
   }
}
