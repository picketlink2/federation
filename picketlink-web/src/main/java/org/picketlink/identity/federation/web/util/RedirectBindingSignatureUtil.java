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
package org.picketlink.identity.federation.web.util;

import static org.picketlink.identity.federation.core.util.StringUtil.isNotNull;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.api.saml.v2.response.SAML2Response;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.saml.v2.util.SignatureUtil; 
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.web.constants.GeneralConstants;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
 

/**
 * Signature Support for the HTTP/Redirect binding
 * @author Anil.Saldhana@redhat.com
 * @since Dec 16, 2008
 */
public class RedirectBindingSignatureUtil
{  
   /**
    * Get the URL for the SAML request that contains the signature and signature algorithm
    * @param authRequest
    * @param relayState
    * @param signingKey
    * @return
    * @throws SAXException  
    * @throws IOException 
    * @throws GeneralSecurityException 
    */
   public static String getSAMLRequestURLWithSignature(AuthnRequestType authRequest, String relayState,
         PrivateKey signingKey) throws SAXException, IOException, GeneralSecurityException
   {
      SAML2Request saml2Request = new SAML2Request();
       
      // Deal with the original request
      StringWriter sw = new StringWriter();
      saml2Request.marshall(authRequest, sw);
      
      //URL Encode the Request
      String urlEncodedRequest = RedirectBindingUtil.deflateBase64URLEncode(sw.toString()); 
    
      String urlEncodedRelayState = null;
      if(isNotNull(relayState))
         urlEncodedRelayState = URLEncoder.encode(relayState, "UTF-8");
      
      byte[] sigValue =  computeSignature("SAMLRequest=" + urlEncodedRequest, urlEncodedRelayState, signingKey); 
      
      //Now construct the URL
      return getRequestRedirectURLWithSignature(urlEncodedRequest, urlEncodedRelayState, sigValue, signingKey.getAlgorithm());
   }
   
   /**
    * Get the URL for the SAML request that contains the signature and signature algorithm
    * @param responseType
    * @param relayState
    * @param signingKey
    * @return   
    * @throws IOException 
    * @throws GeneralSecurityException
    */
   public static String getSAMLResponseURLWithSignature(ResponseType responseType, String relayState,
         PrivateKey signingKey) throws IOException, GeneralSecurityException
   {
      SAML2Response saml2Response = new SAML2Response();
       
      Document responseDoc =  saml2Response.convert(responseType);
        
      
      //URL Encode the Request
      String responseString = DocumentUtil.getDocumentAsString(responseDoc);
      
      String urlEncodedResponse = RedirectBindingUtil.deflateBase64URLEncode(responseString); 
    
      String urlEncodedRelayState = null;
      if(isNotNull(relayState))
         urlEncodedRelayState = URLEncoder.encode(relayState, "UTF-8");
      
      byte[] sigValue =  computeSignature("SAMLResponse=" + urlEncodedResponse, urlEncodedRelayState, signingKey); 
      
      //Now construct the URL
      return getResponseRedirectURLWithSignature(urlEncodedResponse, urlEncodedRelayState, sigValue, signingKey.getAlgorithm());
   }
   
   /**
    * Given an url-encoded saml request and relay state and a private key, compute the url
    * @param urlEncodedRequest
    * @param urlEncodedRelayState
    * @param signingKey
    * @return 
    * @throws GeneralSecurityException 
    * @throws IOException 
    */
   public static String getSAMLRequestURLWithSignature(String urlEncodedRequest, String urlEncodedRelayState,
         PrivateKey signingKey) throws IOException, GeneralSecurityException  
   {
      byte[] sigValue =  computeSignature("SAMLRequest=" + urlEncodedRequest, urlEncodedRelayState, signingKey); 
      return getRequestRedirectURLWithSignature(urlEncodedRequest, urlEncodedRelayState, sigValue, signingKey.getAlgorithm());
   }
   
   /**
    * Given an url-encoded saml response and relay state and a private key, compute the url
    * @param urlEncodedResponse
    * @param urlEncodedRelayState
    * @param signingKey
    * @return 
    * @throws GeneralSecurityException 
    * @throws IOException 
    */
   public static String getSAMLResponseURLWithSignature(String urlEncodedResponse, String urlEncodedRelayState,
         PrivateKey signingKey) throws IOException, GeneralSecurityException 
   {
      byte[] sigValue =  computeSignature("SAMLResponse=" + urlEncodedResponse, urlEncodedRelayState, signingKey); 
      return getResponseRedirectURLWithSignature(urlEncodedResponse, urlEncodedRelayState, sigValue, signingKey.getAlgorithm());
   }
   
   /**
    * From the SAML Request URL, get the Request object
    * @param signedURL
    * @return  
    * @throws IOException 
    * @throws ParsingException 
    * @throws ProcessingException 
    * @throws ConfigurationException 
    */
   public static AuthnRequestType getRequestFromSignedURL(String signedURL) 
   throws ConfigurationException, ProcessingException, ParsingException, IOException 
   {
      String samlRequestTokenValue =  getTokenValue(signedURL, "SAMLRequest");
      
      SAML2Request saml2Request = new SAML2Request();
      return saml2Request.getAuthnRequestType(RedirectBindingUtil.urlBase64DeflateDecode(samlRequestTokenValue));
   }

   /**
    * Get the signature value from the url
    * @param signedURL
    * @return 
    * @throws IOException 
    */
   public static byte[] getSignatureValueFromSignedURL(String signedURL) throws IOException 
   { 
      String sigValueTokenValue =  getTokenValue(signedURL,"Signature");
      if(sigValueTokenValue == null)
         throw new IllegalArgumentException("Signature Token is not present");
      return RedirectBindingUtil.urlBase64Decode(sigValueTokenValue); 
   }
   
   
   /**
    * From the query string that contains key/value pairs, get the value of a key
    * <b>Note:</b> if the token is null, a null value is returned
    * @param queryString
    * @param token
    * @return
    */
   public static String getTokenValue(String queryString, String token)
   {
      return getTokenValue(getToken(queryString, token));
   }
   
   public static boolean validateSignature(String queryString, 
         PublicKey validatingKey, byte[] sigValue ) throws UnsupportedEncodingException, GeneralSecurityException
   {
      //Construct the url again
      String reqFromURL = RedirectBindingSignatureUtil.getTokenValue(queryString, "SAMLRequest"); 
      String relayStateFromURL = RedirectBindingSignatureUtil.getTokenValue(queryString, 
            GeneralConstants.RELAY_STATE);
      String sigAlgFromURL = RedirectBindingSignatureUtil.getTokenValue(queryString, "SigAlg"); 

      StringBuilder sb = new StringBuilder();
      sb.append("SAMLRequest=").append(reqFromURL);
       
      if(isNotNull(relayStateFromURL))
      {
         sb.append("&RelayState=").append(relayStateFromURL);
      }
      sb.append("&SigAlg=").append(sigAlgFromURL);
      
       
      return SignatureUtil.validate(sb.toString().getBytes("UTF-8"), sigValue, validatingKey); 
   }
   
   //***************** Private Methods **************
   
   private static byte[] computeSignature(
         String requestOrResponseKeyValuePair, String urlEncodedRelayState,
         PrivateKey signingKey) throws IOException, GeneralSecurityException
   {
      StringBuilder sb = new StringBuilder();
      sb.append(requestOrResponseKeyValuePair);
      if(isNotNull(urlEncodedRelayState))
      {
         sb.append("&RelayState=").append(urlEncodedRelayState); 
      }
      //SigAlg
      String algo = signingKey.getAlgorithm();
      String sigAlg = SignatureUtil.getXMLSignatureAlgorithmURI(algo);
      
      sigAlg = URLEncoder.encode(sigAlg, "UTF-8");
    
      sb.append("&SigAlg=").append(sigAlg);
      
      byte[] sigValue = SignatureUtil.sign(sb.toString(), signingKey);
      
      return sigValue; 
   }
   
   private static String getRequestRedirectURLWithSignature(
         String urlEncodedRequest, String urlEncodedRelayState, byte[] signature, String sigAlgo) 
   throws IOException
   {
      StringBuilder sb = new StringBuilder();
      sb.append("SAMLRequest=").append(urlEncodedRequest);
      if(isNotNull(urlEncodedRelayState))
      {
         sb.append("&").append("RelayState=").append(urlEncodedRelayState); 
      }
      //SigAlg 
      String sigAlg = SignatureUtil.getXMLSignatureAlgorithmURI(sigAlgo);
      
      sigAlg = URLEncoder.encode(sigAlg, "UTF-8");
    
      sb.append("&").append("SigAlg=").append(sigAlg);
      
      //Encode the signature value
      String encodedSig = RedirectBindingUtil.base64URLEncode(signature);
      
      sb.append("&").append("Signature=").append(encodedSig);
      
      return sb.toString(); 
   }
   
   private static String getResponseRedirectURLWithSignature(
         String urlEncodedResponse, String urlEncodedRelayState, byte[] signature, String sigAlgo) 
   throws IOException 
   {
      StringBuilder sb = new StringBuilder();
      sb.append("SAMLResponse=").append(urlEncodedResponse);
      if(isNotNull(urlEncodedRelayState))
      {
         sb.append("&").append("RelayState=").append(urlEncodedRelayState); 
      }
      //SigAlg 
      String sigAlg = SignatureUtil.getXMLSignatureAlgorithmURI(sigAlgo);
      
      sigAlg = URLEncoder.encode(sigAlg, "UTF-8");
    
      sb.append("&").append("SigAlg=").append(sigAlg);
      
      //Encode the signature value
      String encodedSig = RedirectBindingUtil.base64URLEncode(signature);
      
      sb.append("&").append("Signature=").append(encodedSig);
      
      return sb.toString(); 
   }
   
   private static String getToken(String queryString, String token)
   {
      if(queryString == null)
         throw new IllegalArgumentException("queryString is null");
      
      token += "=";
      
      int start = queryString.indexOf(token);
      if(start < 0)
         return null;
      
      int end = queryString.indexOf("&",start);
      
      if(end == -1)
         return queryString.substring(start);
      
      return queryString.substring(start,end);
   }
   
   private static String getTokenValue(String token)
   {
      if(token == null)
         return token;
      
      int eq = token.indexOf('=');
      if(eq == -1)
         return token;
      else
         return token.substring(eq + 1);
   }
}