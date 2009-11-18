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
package org.jboss.test.identity.federation.core.wstrust;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import org.jboss.identity.federation.core.exceptions.ConfigurationException;
import org.jboss.identity.federation.core.saml.v2.common.IDGenerator;
import org.jboss.identity.federation.core.saml.v2.util.DocumentUtil;
import org.jboss.identity.federation.core.wstrust.SecurityToken;
import org.jboss.identity.federation.core.wstrust.SecurityTokenProvider;
import org.jboss.identity.federation.core.wstrust.StandardSecurityToken;
import org.jboss.identity.federation.core.wstrust.WSTrustException;
import org.jboss.identity.federation.core.wstrust.WSTrustRequestContext;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * <p>
 * Mock {@code SecurityTokenProvider} used in the test scenarios.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class SpecialTokenProvider implements SecurityTokenProvider
{
   
   private Map<String, String> properties;
   
   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.identity.federation.core.wstrust.SecurityTokenProvider#initialize(java.util.Map)
    */
   public void initialize(Map<String, String> properties)
   {
      this.properties = properties;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.identity.federation.core.wstrust.SecurityTokenProvider#cancelToken(org.jboss.identity.federation.core.wstrust.WSTrustRequestContext)
    */
   public void cancelToken(WSTrustRequestContext context) throws WSTrustException
   {
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.identity.federation.core.wstrust.SecurityTokenProvider#issueToken(org.jboss.identity.federation.core.wstrust.WSTrustRequestContext)
    */
   public void issueToken(WSTrustRequestContext context) throws WSTrustException
   {
      // create a simple sample token using the info from the request.
      String caller = context.getCallerPrincipal() == null ? "anonymous" : context.getCallerPrincipal().getName();
      URI tokenType = context.getRequestSecurityToken().getTokenType();
      if (tokenType == null)
      {
         try
         {
            tokenType = new URI("http://www.tokens.org/SpecialToken");
         }
         catch (URISyntaxException ignore)
         {
         }
      }

      // we will use DOM to create the token.
      try
      {
         Document doc = DocumentUtil.createDocument();

         String namespaceURI = "http://www.tokens.org";
         Element root = doc.createElementNS(namespaceURI, "token:SpecialToken");
         root.appendChild(doc.createTextNode("Principal:" + caller));
         String id = IDGenerator.create("ID_");
         root.setAttributeNS(namespaceURI, "ID", id);
         root.setAttributeNS(namespaceURI, "TokenType", tokenType.toString());
         doc.appendChild(root);

         SecurityToken token = new StandardSecurityToken(tokenType.toString(), root, id);
         context.setSecurityToken(token);
      }
      catch (ConfigurationException pce)
      {
         pce.printStackTrace();
      }
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.identity.federation.core.wstrust.SecurityTokenProvider#renewToken(org.jboss.identity.federation.core.wstrust.WSTrustRequestContext)
    */
   public void renewToken(WSTrustRequestContext context) throws WSTrustException
   {
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.identity.federation.core.wstrust.SecurityTokenProvider#validateToken(org.jboss.identity.federation.core.wstrust.WSTrustRequestContext)
    */
   public void validateToken(WSTrustRequestContext context) throws WSTrustException
   {
   }
   
   /**
    * <p>
    * Just returns a reference to the properties that have been configured for testing purposes.
    * </p>
    * 
    * @return a reference to the properties map.
    */
   public Map<String, String> getProperties()
   {
      return this.properties;
   }
}
