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

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.Import;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.log.Log;
import org.jboss.seam.util.Base64;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.util.JAXBUtil;
import org.picketlink.identity.federation.saml.v2.protocol.RequestAbstractType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusResponseType;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;
import org.picketlink.identity.seam.federation.configuration.SamlIdentityProvider;
import org.picketlink.identity.seam.federation.configuration.ServiceProvider;
import org.w3c.dom.Document;

/**
* @author Marcel Kolsteren
* @since Jan 24, 2010
*/
@Name("org.picketlink.identity.seam.federation.samlMessageReceiver")
@AutoCreate
@Import("org.picketlink.identity.seam.federation")
public class SamlMessageReceiver
{
   @Logger
   private Log log;

   @In
   private Requests requests;

   @In
   private SamlSingleLogoutReceiver samlSingleLogoutReceiver;

   @In
   private SamlSingleSignOnReceiver samlSingleSignOnReceiver;

   @In
   private SamlSignatureValidator samlSignatureValidator;

   @In
   private ServiceProvider serviceProvider;

   public void handleIncomingSamlMessage(SamlProfile samlProfile, HttpServletRequest httpRequest,
         HttpServletResponse httpResponse) throws InvalidRequestException
   {
      String samlRequestParam = httpRequest.getParameter(SamlConstants.QSP_SAML_REQUEST);
      String samlResponseParam = httpRequest.getParameter(SamlConstants.QSP_SAML_RESPONSE);

      RequestOrResponse requestOrResponse;
      String samlMessage;

      if (samlRequestParam != null && samlResponseParam == null)
      {
         samlMessage = samlRequestParam;
         requestOrResponse = RequestOrResponse.REQUEST;
      }
      else if (samlRequestParam == null && samlResponseParam != null)
      {
         samlMessage = samlResponseParam;
         requestOrResponse = RequestOrResponse.RESPONSE;
      }
      else
      {
         throw new InvalidRequestException(
               "SAML message should either have a SAMLRequest parameter or a SAMLResponse parameter");
      }

      InputStream is = RedirectBindingUtil.base64DeflateDecode(samlMessage);
      if (httpRequest.getMethod().equals("POST"))
      {
         byte[] decodedMessage = Base64.decode(samlMessage);
         is = new ByteArrayInputStream(decodedMessage);
      }
      else
      {
         is = RedirectBindingUtil.base64DeflateDecode(samlMessage);
      }

      Document document = getDocument(is);
      String issuerEntityId;
      RequestAbstractType samlRequest = null;
      StatusResponseType samlResponse = null;
      if (requestOrResponse.isRequest())
      {
         samlRequest = getSamlRequest(document);
         issuerEntityId = samlRequest.getIssuer().getValue();
      }
      else
      {
         samlResponse = getSamlResponse(document);
         issuerEntityId = samlResponse.getIssuer().getValue();
      }
      if (log.isDebugEnabled())
      {
         log.debug("Received from IDP: " + DocumentUtil.asString(document));
      }

      SamlIdentityProvider idp = serviceProvider.getSamlConfiguration().getSamlIdentityProviderByEntityId(
            issuerEntityId);
      if (idp == null)
      {
         throw new InvalidRequestException("Received message from unknown idp " + issuerEntityId);
      }

      boolean validate;
      if (samlProfile == SamlProfile.SINGLE_SIGN_ON)
      {
         validate = serviceProvider.getSamlConfiguration().isWantAssertionsSigned();
      }
      else
      {
         validate = idp.isSingleLogoutMessagesSigned();
      }

      if (validate)
      {
         if (log.isDebugEnabled())
         {
            log.debug("Validating the signature");
         }
         if (httpRequest.getMethod().equals("POST"))
         {
            samlSignatureValidator.validateSignatureForPostBinding(idp, document);
         }
         else
         {
            samlSignatureValidator.validateSignatureForRedirectBinding(idp, httpRequest, requestOrResponse);
         }
      }

      RequestContext requestContext = null;
      if (requestOrResponse.isResponse() && samlResponse.getInResponseTo() != null)
      {
         requestContext = requests.getRequest(samlResponse.getInResponseTo());
         if (requestContext == null)
         {
            throw new InvalidRequestException("No request that corresponds with the received response");
         }
         else if (!(requestContext.getIdentityProvider().equals(idp)))
         {
            throw new InvalidRequestException("Identity provider of request and response do not match");
         }
      }

      if (samlProfile == SamlProfile.SINGLE_SIGN_ON)
      {
         if (requestOrResponse.isRequest())
         {
            throw new InvalidRequestException("Assertion consumer service can only process SAML responses");
         }
         else
         {
            samlSingleSignOnReceiver.processIDPResponse(httpRequest, httpResponse, samlResponse, requestContext, idp);
         }
      }
      else
      {
         if (requestOrResponse.isRequest())
         {
            samlSingleLogoutReceiver.processIDPRequest(httpRequest, httpResponse, samlRequest, idp);
         }
         else
         {
            samlSingleLogoutReceiver.processIDPResponse(httpRequest, httpResponse, samlResponse, requestContext, idp);
         }
      }
   }

   private RequestAbstractType getSamlRequest(Document document) throws InvalidRequestException
   {
      try
      {
         JAXBContext jaxb = JAXBUtil.getJAXBContext(StatusResponseType.class);
         Unmarshaller unmarshaller = jaxb.createUnmarshaller();
         @SuppressWarnings("unchecked")
         JAXBElement<RequestAbstractType> jaxbRequest = (JAXBElement<RequestAbstractType>) unmarshaller
               .unmarshal(document);
         RequestAbstractType request = jaxbRequest.getValue();
         return request;
      }
      catch (JAXBException e)
      {
         throw new InvalidRequestException("SAML message could not be parsed", e);
      }
   }

   private StatusResponseType getSamlResponse(Document document) throws InvalidRequestException
   {
      try
      {
         JAXBContext jaxb = JAXBUtil.getJAXBContext(StatusResponseType.class);
         Unmarshaller unmarshaller = jaxb.createUnmarshaller();
         @SuppressWarnings("unchecked")
         JAXBElement<StatusResponseType> jaxbResponseType = (JAXBElement<StatusResponseType>) unmarshaller
               .unmarshal(document);
         StatusResponseType statusResponse = jaxbResponseType.getValue();
         return statusResponse;
      }
      catch (JAXBException e)
      {
         throw new InvalidRequestException("SAML message could not be parsed", e);
      }
   }

   private Document getDocument(InputStream is) throws InvalidRequestException
   {
      try
      {
         return DocumentUtil.getDocument(is);
      }
      catch (ConfigurationException e)
      {
         throw new RuntimeException(e);
      }
      catch (ProcessingException e)
      {
         throw new RuntimeException(e);
      }
      catch (ParsingException e)
      {
         throw new InvalidRequestException("SAML request could not be parsed", e);
      }
   }
}
