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
package org.jboss.identity.federation.web.handlers.saml2;
 

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.jboss.identity.federation.core.config.IDPType;
import org.jboss.identity.federation.core.exceptions.ConfigurationException;
import org.jboss.identity.federation.core.exceptions.ProcessingException;
import org.jboss.identity.federation.core.impl.EmptyAttributeManager;
import org.jboss.identity.federation.core.interfaces.AttributeManager;
import org.jboss.identity.federation.core.saml.v2.interfaces.SAML2HandlerChainConfig;
import org.jboss.identity.federation.core.saml.v2.interfaces.SAML2HandlerConfig;
import org.jboss.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.jboss.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;
import org.jboss.identity.federation.saml.v2.protocol.LogoutRequestType;
import org.jboss.identity.federation.web.constants.GeneralConstants;
import org.jboss.identity.federation.web.core.HTTPContext;

/**
 * Handler dealing with attributes for SAML2
 * @author Anil.Saldhana@redhat.com
 * @since Oct 12, 2009
 */
public class SAML2AttributeHandler extends BaseSAML2Handler
{ 
   private static Logger log = Logger.getLogger(SAML2AttributeHandler.class);
   private boolean trace = log.isTraceEnabled();
   
   protected AttributeManager attribManager = new EmptyAttributeManager(); 
   protected List<String> attributeKeys = new ArrayList<String>();
   
   @Override
   public void initChainConfig(SAML2HandlerChainConfig handlerChainConfig) throws ConfigurationException
   {
      super.initChainConfig(handlerChainConfig);
      Object config = this.handlerChainConfig.getParameter(GeneralConstants.CONFIGURATION);
      if(config instanceof IDPType)
      {
         IDPType idpType = (IDPType) config;
         String attribStr = idpType.getAttributeManager();
         insantiateAttributeManager(attribStr);
      }   
   }

   @SuppressWarnings("unchecked")
   @Override
   public void initHandlerConfig(SAML2HandlerConfig handlerConfig) throws ConfigurationException
   {
      super.initHandlerConfig(handlerConfig);
      
      String attribStr = (String) this.handlerConfig.getParameter(GeneralConstants.ATTIBUTE_MANAGER);
      this.insantiateAttributeManager(attribStr);
      List<String> ak = (List<String>) this.handlerConfig.getParameter(GeneralConstants.ATTRIBUTE_KEYS);
      if(ak != null)
         this.attributeKeys.addAll(ak);
   }

   @SuppressWarnings("unchecked")
   public void handleRequestType(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException
   {
      //Do not handle log out request interaction
      if(request.getSAML2Object() instanceof LogoutRequestType)
         return ;
      
      //only handle IDP side
      if(getType() == HANDLER_TYPE.SP)
         return;
      
      HTTPContext httpContext = (HTTPContext) request.getContext();
      HttpSession session = httpContext.getRequest().getSession(false);
      
      Principal userPrincipal = (Principal) session.getAttribute(GeneralConstants.PRINCIPAL_ID);
      Map<String, Object> attribs = (Map<String, Object>) session.getAttribute(GeneralConstants.ATTRIBUTES);
      if(attribs == null)
      {   
         attribs = this.attribManager.getAttributes(userPrincipal, attributeKeys);
         session.setAttribute(GeneralConstants.ATTRIBUTES, attribs);
      }  
   } 
   
   private void insantiateAttributeManager(String attribStr) 
   throws ConfigurationException
   {
      if(attribStr != null && !"".equals(attribStr))
      {
         ClassLoader tcl = SecurityActions.getContextClassLoader();
         try
         {
            attribManager = (AttributeManager) tcl.loadClass(attribStr).newInstance();
            if(trace)
               log.trace("AttributeManager set to " + this.attribManager);
         }
         catch (Exception e)
         {
            log.error("Exception initializing attribute manager:",e);
            throw new ConfigurationException(); 
         }  
      } 
   }
}