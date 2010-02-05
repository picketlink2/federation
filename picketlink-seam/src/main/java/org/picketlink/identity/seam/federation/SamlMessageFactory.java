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

import javax.xml.datatype.XMLGregorianCalendar;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.factories.JBossSAMLBaseFactory;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.LogoutRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.ObjectFactory;
import org.picketlink.identity.federation.saml.v2.protocol.RequestAbstractType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusCodeType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusType;
import org.picketlink.identity.seam.federation.configuration.ServiceProvider;

/**
* @author Marcel Kolsteren
* @since Jan 25, 2010
*/
@Name("org.picketlink.identity.seam.federation.samlMessageFactory")
@AutoCreate
public class SamlMessageFactory
{
   @In
   private ServiceProvider serviceProvider;

   public StatusResponseType createStatusResponse(RequestAbstractType request, String statusCode, String statusMessage)
   {
      ObjectFactory objectFactory = new ObjectFactory();
      org.picketlink.identity.federation.saml.v2.assertion.ObjectFactory assertionObjectFactory = new org.picketlink.identity.federation.saml.v2.assertion.ObjectFactory();

      StatusResponseType response = objectFactory.createStatusResponseType();

      response.setID(generateId());
      response.setIssueInstant(generateIssueInstant());

      NameIDType issuer = assertionObjectFactory.createNameIDType();
      issuer.setValue(serviceProvider.getSamlConfiguration().getEntityId());
      response.setIssuer(issuer);

      response.setVersion(JBossSAMLConstants.VERSION_2_0.get());
      response.setInResponseTo(request.getID());

      StatusCodeType statusCodeJaxb = objectFactory.createStatusCodeType();
      statusCodeJaxb.setValue(statusCode);

      StatusType statusType = objectFactory.createStatusType();
      statusType.setStatusCode(statusCodeJaxb);
      if (statusMessage != null)
      {
         statusType.setStatusMessage(statusMessage);
      }

      response.setStatus(statusType);

      return response;
   }

   public AuthnRequestType createAuthnRequest()
   {
      ObjectFactory objectFactory = new ObjectFactory();
      org.picketlink.identity.federation.saml.v2.assertion.ObjectFactory assertionObjectFactory = new org.picketlink.identity.federation.saml.v2.assertion.ObjectFactory();

      AuthnRequestType authnRequest = objectFactory.createAuthnRequestType();

      authnRequest.setID(generateId());
      authnRequest.setIssueInstant(generateIssueInstant());

      NameIDType issuer = assertionObjectFactory.createNameIDType();
      issuer.setValue(serviceProvider.getSamlConfiguration().getEntityId());
      authnRequest.setIssuer(issuer);

      authnRequest.setVersion(JBossSAMLConstants.VERSION_2_0.get());

      // Fill in the optional fields that indicate where and how the response should be delivered.
      authnRequest.setAssertionConsumerServiceURL(serviceProvider
            .getServiceURL(ExternalAuthenticationService.SAML_ASSERTION_CONSUMER_SERVICE));
      authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

      return authnRequest;
   }

   public LogoutRequestType createLogoutRequest(SamlPrincipal principal) throws ConfigurationException
   {
      ObjectFactory objectFactory = new ObjectFactory();
      org.picketlink.identity.federation.saml.v2.assertion.ObjectFactory assertionObjectFactory = new org.picketlink.identity.federation.saml.v2.assertion.ObjectFactory();

      LogoutRequestType logoutRequest = objectFactory.createLogoutRequestType();

      logoutRequest.setID(generateId());
      logoutRequest.setIssueInstant(generateIssueInstant());

      NameIDType issuer = assertionObjectFactory.createNameIDType();
      issuer.setValue(serviceProvider.getSamlConfiguration().getEntityId());
      logoutRequest.setIssuer(issuer);

      NameIDType nameID = JBossSAMLBaseFactory.createNameID();
      nameID.setValue(principal.getNameId().getValue());
      logoutRequest.setNameID(nameID);

      logoutRequest.setVersion(JBossSAMLConstants.VERSION_2_0.get());
      logoutRequest.getSessionIndex().add(principal.getSessionIndex());

      return logoutRequest;
   }

   private String generateId()
   {
      return IDGenerator.create("ID_");
   }

   private XMLGregorianCalendar generateIssueInstant()
   {
      try
      {
         return XMLTimeUtil.getIssueInstant();
      }
      catch (ConfigurationException e)
      {
         throw new RuntimeException(e);
      }
   }
}
