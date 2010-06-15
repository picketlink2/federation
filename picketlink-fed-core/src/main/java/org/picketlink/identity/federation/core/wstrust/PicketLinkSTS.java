/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2009, Red Hat Middleware LLC, and individual contributors
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
package org.picketlink.identity.federation.core.wstrust;

import java.io.File;
import java.io.InputStream;
import java.net.URL;

import javax.annotation.Resource;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.ws.Provider;
import javax.xml.ws.Service;
import javax.xml.ws.ServiceMode;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.WebServiceException;
import javax.xml.ws.WebServiceProvider;

import org.apache.log4j.Logger;
import org.picketlink.identity.federation.core.config.STSType;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLDocumentHolder;
import org.picketlink.identity.federation.core.wstrust.wrappers.BaseRequestSecurityToken;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenCollection;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponse;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponseCollection;
import org.w3c.dom.Document;

/**
 * <p>
 * Default implementation of the {@code SecurityTokenService} interface.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
@WebServiceProvider(serviceName = "PicketLinkSTS", portName = "PicketLinkSTSPort", targetNamespace = "urn:picketlink:identity-federation:sts", wsdlLocation = "WEB-INF/wsdl/PicketLinkSTS.wsdl")
@ServiceMode(value = Service.Mode.PAYLOAD)
public class PicketLinkSTS implements Provider<Source>//SecurityTokenService
{
   private static Logger logger = Logger.getLogger(PicketLinkSTS.class);

   private static final String SEPARATOR = System.getProperty("file.separator");

   private static final String STS_CONFIG_FILE = "picketlink-sts.xml";

   private static final String STS_CONFIG_DIR = "picketlink-store" + SEPARATOR + "sts" + SEPARATOR;

   @Resource
   protected WebServiceContext context;

   protected STSConfiguration config;

   /*
    * (non-Javadoc)
    * 
    * @see org.picketlink.identity.federation.core.wstrust.SecurityTokenService#invoke(javax.xml.transform.Source)
    */
   public Source invoke(Source request)
   {
      BaseRequestSecurityToken baseRequest;
      try
      {
         baseRequest = WSTrustJAXBFactory.getInstance().parseRequestSecurityToken(request);
      }
      catch (WSTrustException we)
      {
         throw new RuntimeException(we);
      }

      if (baseRequest instanceof RequestSecurityToken)
         return this.handleTokenRequest((RequestSecurityToken) baseRequest);
      else if (baseRequest instanceof RequestSecurityTokenCollection)
         return this.handleTokenRequestCollection((RequestSecurityTokenCollection) baseRequest);
      else
         throw new WebServiceException("Invalid security token request");
   }

   /**
    * <p>
    * Process a security token request.
    * </p>
    * 
    * @param request a {@code RequestSecurityToken} instance that contains the request information.
    * @return a {@code Source} instance representing the marshalled response.
    * @throws WebServiceException Any exception encountered in handling token
    */
   protected Source handleTokenRequest(RequestSecurityToken request)
   {
      SAMLDocumentHolder holder = WSTrustJAXBFactory.getInstance().getSAMLDocumentHolderOnThread();

      /**
       * The RST Document is very important for XML Signatures
       */
      request.setRSTDocument(holder.getSamlDocument());

      if (this.config == null)
         try
         {
            if (logger.isInfoEnabled())
               logger.info("Loading STS configuration");
            this.config = this.getConfiguration();
         }
         catch (ConfigurationException e)
         {
            throw new WebServiceException("Encountered configuration exception:", e);
         }

      WSTrustRequestHandler handler = this.config.getRequestHandler();
      String requestType = request.getRequestType().toString();
      if (logger.isDebugEnabled())
         logger.debug("STS received request of type " + requestType);

      try
      {
         if (requestType.equals(WSTrustConstants.ISSUE_REQUEST))
         {
            Source source = this.marshallResponse(handler.issue(request, this.context.getUserPrincipal()));
            Document doc = handler.postProcess((Document) ((DOMSource) source).getNode(), request);
            return new DOMSource(doc);
         }
         else if (requestType.equals(WSTrustConstants.RENEW_REQUEST))
         {
            Source source = this.marshallResponse(handler.renew(request, this.context.getUserPrincipal()));
            // we need to sign/encrypt renewed tokens.
            Document document = handler.postProcess((Document) ((DOMSource) source).getNode(), request);
            return new DOMSource(document);
         }
         else if (requestType.equals(WSTrustConstants.CANCEL_REQUEST))
            return this.marshallResponse(handler.cancel(request, this.context.getUserPrincipal()));
         else if (requestType.equals(WSTrustConstants.VALIDATE_REQUEST))
            return this.marshallResponse(handler.validate(request, this.context.getUserPrincipal()));
         else
            throw new WSTrustException("Invalid request type: " + requestType);
      }
      catch (WSTrustException we)
      {
         throw new WebServiceException("Exception in handling token request:", we);
      }
   }

   /**
    * <p>
    * Process a collection of security token requests.
    * </p>
    * 
    * @param requestCollection a {@code RequestSecurityTokenCollection} containing the various requests information.
    * @return a {@code Source} instance representing the marshalled response.
    */
   protected Source handleTokenRequestCollection(RequestSecurityTokenCollection requestCollection)
   {
      throw new UnsupportedOperationException();
   }

   /**
    * <p>
    * Marshalls the specified {@code RequestSecurityTokenResponse} into a {@code Source} instance.
    * </p>
    * 
    * @param response the {@code RequestSecurityTokenResponse} to be marshalled.
    * @return the resulting {@code Source} instance.
    */
   protected Source marshallResponse(RequestSecurityTokenResponse response)
   {
      // add the single response to a RequestSecurityTokenResponse collection, as per the specification.
      RequestSecurityTokenResponseCollection responseCollection = new RequestSecurityTokenResponseCollection();
      responseCollection.addRequestSecurityTokenResponse(response);
      return WSTrustJAXBFactory.getInstance().marshallRequestSecurityTokenResponse(responseCollection);
   }

   /**
    * <p>
    * Obtains the STS configuration options.
    * </p>
    * 
    * @return an instance of {@code STSConfiguration} containing the STS configuration properties.
    */
   protected STSConfiguration getConfiguration() throws ConfigurationException
   {
      URL configurationFileURL = null;

      try
      {
         // check the user home for a configuration file generated by the picketlink console.
         String configurationFilePath = System.getProperty("user.home") + SEPARATOR + STS_CONFIG_DIR + STS_CONFIG_FILE;
         File configurationFile = new File(configurationFilePath);
         if (configurationFile.exists())
            configurationFileURL = configurationFile.toURI().toURL();
         else
            // if not configuration file was found in the user home, check the context classloader.
            configurationFileURL = SecurityActions.getContextClassLoader().getResource(STS_CONFIG_FILE);

         // if no configuration file was found, log a warn message and use default configuration values.
         if (configurationFileURL == null)
         {
            logger.warn(STS_CONFIG_FILE + " configuration file not found. Using default configuration values");
            return new PicketLinkSTSConfiguration();
         }

         InputStream stream = configurationFileURL.openStream();
         STSType stsConfig = WSTrustUtil.getSTSConfiguration(stream);
         STSConfiguration configuration = new PicketLinkSTSConfiguration(stsConfig);
         if (logger.isInfoEnabled())
            logger.info(STS_CONFIG_FILE + " configuration file loaded");
         return configuration;
      }
      catch (Exception e)
      {
         throw new ConfigurationException("Error parsing the configuration file:", e);
      }
   }
}