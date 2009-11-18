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
package org.picketlink.identity.federation.core.saml.v2.util;

import javax.xml.bind.JAXBElement;

import org.picketlink.identity.federation.core.factories.SOAPFactory;
import org.picketlink.identity.federation.core.saml.v2.factories.SAMLAssertionFactory;
import org.picketlink.identity.federation.core.saml.v2.factories.SAMLProtocolFactory;
import org.picketlink.identity.federation.core.saml.v2.factories.XACMLStatementFactory;
import org.picketlink.identity.federation.org.xmlsoap.schemas.soap.envelope.Envelope;
import org.picketlink.identity.federation.saml.v2.assertion.EncryptedElementType;
import org.picketlink.identity.federation.saml.v2.profiles.xacml.assertion.XACMLAuthzDecisionStatementType;
import org.picketlink.identity.federation.saml.v2.protocol.ArtifactResolveType;
import org.picketlink.identity.federation.saml.v2.protocol.ArtifactResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.AssertionIDRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.LogoutRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.ManageNameIDRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.NameIDMappingRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.NameIDMappingResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.RequestAbstractType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusResponseType;

/**
 * Maps various saml/xacml types to their corresponding JAXBElement
 * @author Anil.Saldhana@redhat.com
 * @since Jan 22, 2009
 */
public class JAXBElementMappingUtil
{
   /**
    * Get the JAXBElement for the request type
    * @param requestAbstractType
    * @return
    */
   public static JAXBElement<?> get(RequestAbstractType requestAbstractType)
   { 
      if(requestAbstractType instanceof AuthnRequestType)
      {
         AuthnRequestType art = (AuthnRequestType) requestAbstractType;
         return SAMLProtocolFactory.getObjectFactory().createAuthnRequest(art);
      }
      
      if(requestAbstractType instanceof LogoutRequestType)
      {
         LogoutRequestType lrt = (LogoutRequestType) requestAbstractType;
         return SAMLProtocolFactory.getObjectFactory().createLogoutRequest(lrt);
      }
      if(requestAbstractType instanceof AssertionIDRequestType)
      {
         AssertionIDRequestType airt = (AssertionIDRequestType) requestAbstractType;
         return SAMLProtocolFactory.getObjectFactory().createAssertionIDRequest(airt);
      }
      if(requestAbstractType instanceof NameIDMappingRequestType)
      {
         NameIDMappingRequestType airt = (NameIDMappingRequestType) requestAbstractType;
         return SAMLProtocolFactory.getObjectFactory().createNameIDMappingRequest(airt);
      }
      if(requestAbstractType instanceof ArtifactResolveType)
      {
         ArtifactResolveType airt = (ArtifactResolveType) requestAbstractType;
         return SAMLProtocolFactory.getObjectFactory().createArtifactResolve(airt);
      } 
      if(requestAbstractType instanceof ManageNameIDRequestType)
      {
         ManageNameIDRequestType airt = (ManageNameIDRequestType) requestAbstractType;
         return SAMLProtocolFactory.getObjectFactory().createManageNameIDRequest(airt);
      } 
      throw new IllegalArgumentException("Unknown Type:"+requestAbstractType); 
   }
   
   /**
    * Get the JAXBElement for an encrypted assertion
    * @param encryptedAssertion
    * @return
    */
   public static JAXBElement<?> get(EncryptedElementType encryptedAssertion)
   {
      return SAMLAssertionFactory.getObjectFactory().createEncryptedAssertion(encryptedAssertion);
   }
   
   /**
    * Get the JAXBElement for response
    * @param responseType
    * @return
    */
   public static JAXBElement<?> get(StatusResponseType statusResponseType)
   { 
      if(statusResponseType instanceof ResponseType)
      {
         ResponseType responseType = (ResponseType) statusResponseType;
         return SAMLProtocolFactory.getObjectFactory().createResponse(responseType);  
      }
      else if(statusResponseType instanceof NameIDMappingResponseType)
      {
         NameIDMappingResponseType nameIDResponseType = (NameIDMappingResponseType) statusResponseType;
         return SAMLProtocolFactory.getObjectFactory().createNameIDMappingResponse(nameIDResponseType);
      }
      else if(statusResponseType instanceof StatusResponseType)
      {
         StatusResponseType srt = (StatusResponseType) statusResponseType;
         return SAMLProtocolFactory.getObjectFactory().createLogoutResponse(srt);
      }
      
      ArtifactResponseType artifactResponse = (ArtifactResponseType) statusResponseType;
      return SAMLProtocolFactory.getObjectFactory().createArtifactResponse(artifactResponse); 
   }
   
   /**
    * Get the JAXBElement for a SOAP envelope
    * @param envelope
    * @return
    */
   public static JAXBElement<?> get(Envelope envelope)
   {
      return SOAPFactory.getObjectFactory().createEnvelope(envelope);
   }
   
   /**
    * Get the JAXBElement for an XACML authorization statement
    * @param xacmlStatement
    * @return
    */
   public static JAXBElement<?> get(XACMLAuthzDecisionStatementType xacmlStatement)
   {
      return XACMLStatementFactory.getObjectFactory().createXACMLAuthzDecisionStatement(xacmlStatement);
   }
}