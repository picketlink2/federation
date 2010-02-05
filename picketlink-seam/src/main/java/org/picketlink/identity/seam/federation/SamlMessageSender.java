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

import static org.picketlink.identity.federation.core.util.StringUtil.isNotNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.Binder;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.Import;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.log.Log;
import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.api.saml.v2.sig.SAML2Signature;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.holders.DestinationInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.util.JAXBUtil;
import org.picketlink.identity.federation.saml.v2.protocol.ObjectFactory;
import org.picketlink.identity.federation.saml.v2.protocol.RequestAbstractType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusResponseType;
import org.picketlink.identity.federation.web.util.HTTPRedirectUtil;
import org.picketlink.identity.federation.web.util.PostBindingUtil;
import org.picketlink.identity.federation.web.util.RedirectBindingSignatureUtil;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;
import org.picketlink.identity.seam.federation.configuration.Binding;
import org.picketlink.identity.seam.federation.configuration.SamlEndpoint;
import org.picketlink.identity.seam.federation.configuration.SamlIdentityProvider;
import org.picketlink.identity.seam.federation.configuration.SamlService;
import org.picketlink.identity.seam.federation.configuration.ServiceProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
* @author Marcel Kolsteren
* @since Jan 24, 2010
*/
@Name("org.picketlink.identity.seam.federation.samlMessageSender")
@AutoCreate
@Import("org.picketlink.identity.seam.federation")
public class SamlMessageSender
{
   @Logger
   private Log log;

   @In
   private ServiceProvider serviceProvider;

   public void sendRequestToIDP(HttpServletRequest request, HttpServletResponse response,
         SamlIdentityProvider samlIdentityProvider, SamlProfile profile, RequestAbstractType samlRequest)
   {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      Document message = null;
      SamlEndpoint endpoint = null;
      try
      {
         SamlService service = samlIdentityProvider.getService(profile);
         endpoint = service.getEndpointForBinding(Binding.HTTP_Post);
         if (endpoint == null)
         {
            endpoint = service.getEndpointForBinding(Binding.HTTP_Redirect);
         }
         if (endpoint == null)
         {
            throw new RuntimeException("Idp " + samlIdentityProvider.getEntityId()
                  + " has no endpoint found for profile " + profile);
         }
         SAML2Request saml2Request = new SAML2Request();
         samlRequest.setDestination(endpoint.getLocation());
         saml2Request.marshall(samlRequest, baos);
         message = saml2Request.convert(samlRequest);
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e);
      }
      catch (ConfigurationException e)
      {
         throw new RuntimeException(e);
      }
      catch (SAXException e)
      {
         throw new RuntimeException(e);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }

      sendMessageToIDP(request, response, samlIdentityProvider, message, RequestOrResponse.REQUEST, endpoint);
   }

   public void sendResponseToIDP(HttpServletRequest request, HttpServletResponse response,
         SamlIdentityProvider samlIdentityProvider, SamlEndpoint endpoint, StatusResponseType samlResponse)
   {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      Document message = null;
      try
      {
         samlResponse.setDestination(endpoint.getResponseLocation());

         JAXBElement<StatusResponseType> responseElement;
         if (endpoint.getService().getProfile().equals(SamlProfile.SINGLE_LOGOUT))
         {
            responseElement = new ObjectFactory().createLogoutResponse(samlResponse);
         }
         else
         {
            throw new RuntimeException("Responses can currently only be created for the single logout service");
         }

         JAXBContext jaxbContext = JAXBUtil.getJAXBContext(RequestAbstractType.class);
         Marshaller marshaller = jaxbContext.createMarshaller();
         marshaller.marshal(responseElement, baos);

         Binder<Node> binder = jaxbContext.createBinder();
         message = DocumentUtil.createDocument();
         binder.marshal(responseElement, message);
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e);
      }
      catch (ConfigurationException e)
      {
         throw new RuntimeException(e);
      }

      sendMessageToIDP(request, response, samlIdentityProvider, message, RequestOrResponse.RESPONSE, endpoint);
   }

   private void sendMessageToIDP(HttpServletRequest request, HttpServletResponse response,
         SamlIdentityProvider samlIdentityProvider, Document message, RequestOrResponse requestOrResponse,
         SamlEndpoint endpoint)
   {
      if (log.isDebugEnabled())
      {
         log.debug("Sending over to IDP: " + DocumentUtil.asString(message));
      }

      try
      {
         boolean signMessage;
         if (endpoint.getService().getProfile().equals(SamlProfile.SINGLE_SIGN_ON))
         {
            signMessage = samlIdentityProvider.isWantAuthnRequestsSigned();
         }
         else
         {
            signMessage = samlIdentityProvider.isWantSingleLogoutMessagesSigned();
         }

         PrivateKey privateKey = serviceProvider.getSamlConfiguration().getPrivateKey();

         if (endpoint.getBinding() == Binding.HTTP_Redirect)
         {
            byte[] responseBytes = DocumentUtil.getDocumentAsString(message).getBytes("UTF-8");

            String urlEncodedResponse = RedirectBindingUtil.deflateBase64URLEncode(responseBytes);

            String finalDest = endpoint.getLocation()
                  + getQueryString(urlEncodedResponse, null, signMessage, requestOrResponse, privateKey);
            HTTPRedirectUtil.sendRedirectForResponder(finalDest, response);
         }
         else
         {
            if (signMessage)
            {
               //Sign the document
               SAML2Signature samlSignature = new SAML2Signature();

               PublicKey publicKey = serviceProvider.getSamlConfiguration().getCertificate().getPublicKey();
               samlSignature.signSAMLDocument(message, new KeyPair(publicKey, privateKey));
            }
            byte[] responseBytes = DocumentUtil.getDocumentAsString(message).getBytes("UTF-8");

            String samlResponse = PostBindingUtil.base64Encode(new String(responseBytes));

            PostBindingUtil.sendPost(new DestinationInfoHolder(endpoint.getLocation(), samlResponse, null), response,
                  requestOrResponse.isRequest());

         }
      }
      catch (ConfigurationException e)
      {
         throw new RuntimeException();
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
      catch (ProcessingException e)
      {
         throw new RuntimeException(e);
      }
   }

   private String getQueryString(String urlEncodedSamlMessage, String urlEncodedRelayState, boolean supportSignature,
         RequestOrResponse requestOrResponse, PrivateKey signingKey)
   {
      StringBuilder sb = new StringBuilder();
      sb.append("?");

      if (supportSignature)
      {
         try
         {
            sb.append(RedirectBindingSignatureUtil.getSAMLResponseURLWithSignature(urlEncodedSamlMessage,
                  urlEncodedRelayState, signingKey));
         }
         catch (IOException e)
         {
            throw new RuntimeException(e);
         }
         catch (GeneralSecurityException e)
         {
            throw new RuntimeException(e);
         }
      }
      else
      {
         if (requestOrResponse == RequestOrResponse.REQUEST)
         {
            sb.append(SamlConstants.QSP_SAML_REQUEST);
         }
         else
         {
            sb.append(SamlConstants.QSP_SAML_RESPONSE);
         }
         sb.append("=").append(urlEncodedSamlMessage);
         if (isNotNull(urlEncodedRelayState))
         {
            sb.append("&").append(SamlConstants.QSP_RELAY_STATE).append("=").append(urlEncodedRelayState);
         }
      }
      return sb.toString();
   }
}
