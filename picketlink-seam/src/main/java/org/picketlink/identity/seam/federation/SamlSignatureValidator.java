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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import javax.servlet.http.HttpServletRequest;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.Name;
import org.picketlink.identity.federation.core.saml.v2.util.SignatureUtil;
import org.picketlink.identity.federation.core.util.XMLSignatureUtil;
import org.picketlink.identity.federation.web.util.RedirectBindingSignatureUtil;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;
import org.picketlink.identity.seam.federation.configuration.SamlIdentityProvider;
import org.w3c.dom.Document;

/**
* @author Marcel Kolsteren
* @since Jan 26, 2010
*/
@Name("org.picketlink.identity.seam.federation.samlSignatureValidator")
@AutoCreate
public class SamlSignatureValidator
{
   public void validateSignatureForPostBinding(SamlIdentityProvider idp, Document document)
         throws InvalidRequestException
   {
      boolean signatureValid;
      try
      {
         signatureValid = XMLSignatureUtil.validate(document, idp.getPublicKey());
      }
      catch (MarshalException e)
      {
         throw new RuntimeException(e);
      }
      catch (XMLSignatureException e)
      {
         throw new RuntimeException(e);
      }

      if (!signatureValid)
      {
         throw new InvalidRequestException("Invalid signature");
      }
   }

   public void validateSignatureForRedirectBinding(SamlIdentityProvider idp, HttpServletRequest httpRequest,
         RequestOrResponse requestOrResponse) throws InvalidRequestException
   {
      String queryString = httpRequest.getQueryString();

      // Check if there is a signature   
      String sigValueParam = RedirectBindingSignatureUtil.getTokenValue(queryString, SamlConstants.QSP_SIGNATURE);
      if (sigValueParam == null)
      {
         throw new InvalidRequestException("Signature parameter is not present.");
      }

      // Decode the signature
      byte[] sigValue;
      try
      {
         sigValue = RedirectBindingUtil.urlBase64Decode(sigValueParam);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }

      String samlMessageParameter;
      if (requestOrResponse == RequestOrResponse.REQUEST)
      {
         samlMessageParameter = SamlConstants.QSP_SAML_REQUEST;
      }
      else
      {
         samlMessageParameter = SamlConstants.QSP_SAML_RESPONSE;
      }

      // Construct the url again
      String reqFromURL = RedirectBindingSignatureUtil.getTokenValue(queryString, samlMessageParameter);
      String relayStateFromURL = RedirectBindingSignatureUtil.getTokenValue(queryString, SamlConstants.QSP_RELAY_STATE);
      String sigAlgFromURL = RedirectBindingSignatureUtil.getTokenValue(queryString, SamlConstants.QSP_SIG_ALG);

      StringBuilder sb = new StringBuilder();
      sb.append(samlMessageParameter).append("=").append(reqFromURL);

      if (isNotNull(relayStateFromURL))
      {
         sb.append("&").append(SamlConstants.QSP_RELAY_STATE).append("=").append(relayStateFromURL);
      }
      sb.append("&").append(SamlConstants.QSP_SIG_ALG).append("=").append(sigAlgFromURL);

      PublicKey validatingKey = idp.getPublicKey();

      boolean isValid;
      try
      {
         isValid = SignatureUtil.validate(sb.toString().getBytes("UTF-8"), sigValue, validatingKey);
      }
      catch (UnsupportedEncodingException e)
      {
         throw new RuntimeException(e);
      }
      catch (GeneralSecurityException e)
      {
         throw new RuntimeException(e);
      }

      if (!isValid)
      {
         throw new InvalidRequestException("Invalid signature.");
      }
   }
}
