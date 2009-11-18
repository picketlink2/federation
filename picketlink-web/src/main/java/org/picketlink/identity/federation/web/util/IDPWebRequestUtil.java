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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PrivateKey;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBException;

import org.apache.log4j.Logger;
import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.api.saml.v2.response.SAML2Response;
import org.picketlink.identity.federation.api.saml.v2.sig.SAML2Signature;
import org.picketlink.identity.federation.core.config.IDPType;
import org.picketlink.identity.federation.core.config.TrustType;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.interfaces.AttributeManager;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLDocumentHolder;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.saml.v2.exceptions.IssueInstantMissingException;
import org.picketlink.identity.federation.core.saml.v2.exceptions.IssuerNotTrustedException;
import org.picketlink.identity.federation.core.saml.v2.holders.DestinationInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.holders.IDPInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.holders.IssuerInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.holders.SPInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.saml.v2.util.StatementUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.protocol.RequestAbstractType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * Request Util
 * <b> Not thread safe</b>
 * @author Anil.Saldhana@redhat.com
 * @since May 18, 2009
 */
public class IDPWebRequestUtil
{
   private static Logger log = Logger.getLogger(IDPWebRequestUtil.class);
   private boolean trace = log.isTraceEnabled();
   
   private boolean redirectProfile = false;
   private boolean postProfile = false;

   private IDPType idpConfiguration;
   private TrustKeyManager keyManager;
   private AttributeManager attributeManager;
   private List<String> attribKeys;
   
   public IDPWebRequestUtil(HttpServletRequest request, IDPType idp, TrustKeyManager keym)
   {
      this.idpConfiguration = idp;
      this.keyManager = keym;
      this.redirectProfile = "GET".equals(request.getMethod());
      this.postProfile = "POST".equals(request.getMethod()); 
   }
   
   public void setAttributeKeys(List<String> attribKeys)
   {
      this.attribKeys = attribKeys;
   }
   
   public void setAttributeManager(AttributeManager attributeManager)
   {
      this.attributeManager = attributeManager;
   }
   
   public boolean hasSAMLRequestInRedirectProfile()
   {
      return redirectProfile;  
   }
   
   public boolean hasSAMLRequestInPostProfile()
   {
      return postProfile;
   }
   
   public SAMLDocumentHolder getSAMLDocumentHolder(String samlMessage)
   throws ParsingException, ConfigurationException, ProcessingException
   { 
      InputStream is = null; 
      SAML2Request saml2Request = new SAML2Request();  
      if(redirectProfile)
      {
         is = RedirectBindingUtil.base64DeflateDecode(samlMessage);
      }
      else
      {
         try
         {
            byte[] samlBytes = PostBindingUtil.base64Decode(samlMessage);
            if(trace) log.trace("SAMLRequest=" + new String(samlBytes));
            is = new ByteArrayInputStream(samlBytes);
         }
         catch(Exception rte)
         {
            if(trace)
               log.trace("Error in base64 decoding saml message: "+rte);
            throw new ParsingException(rte);
         } 
      }
      saml2Request.getSAML2ObjectFromStream(is);
      return saml2Request.getSamlDocumentHolder();
   }
   
   public RequestAbstractType getSAMLRequest(String samlMessage) 
   throws ParsingException, ConfigurationException, ProcessingException
   { 
      InputStream is = null; 
      SAML2Request saml2Request = new SAML2Request();  
      if(redirectProfile)
      {
         try
         {
            is = RedirectBindingUtil.base64DeflateDecode(samlMessage); 
         }
         catch(Exception e)
         {
            log.error("Exception in parsing saml message:", e);
            throw new ParsingException();
         }
      }
      else
      {
         byte[] samlBytes = PostBindingUtil.base64Decode(samlMessage);
         if(trace) log.trace("SAMLRequest=" + new String(samlBytes));
         is = new ByteArrayInputStream(samlBytes);
      }
      return saml2Request.getRequestType(is);
   } 
   
    
   public Document getResponse( String assertionConsumerURL,
         Principal userPrincipal,
         List<String> roles, 
         String identityURL,
         long assertionValidity,
         boolean supportSignature) 
   throws ConfigurationException, IssueInstantMissingException
   {
      Document samlResponseDocument = null;
      
      if(trace) 
         log.trace("AssertionConsumerURL=" + assertionConsumerURL + 
            "::assertion validity=" + assertionValidity);
      ResponseType responseType = null;     
      
      SAML2Response saml2Response = new SAML2Response();
            
      //Create a response type
      String id = IDGenerator.create("ID_");

      IssuerInfoHolder issuerHolder = new IssuerInfoHolder(identityURL); 
      issuerHolder.setStatusCode(JBossSAMLURIConstants.STATUS_SUCCESS.get());

      IDPInfoHolder idp = new IDPInfoHolder();
      idp.setNameIDFormatValue(userPrincipal.getName());
      idp.setNameIDFormat(JBossSAMLURIConstants.NAMEID_FORMAT_PERSISTENT.get());

      SPInfoHolder sp = new SPInfoHolder();
      sp.setResponseDestinationURI(assertionConsumerURL);
      responseType = saml2Response.createResponseType(id, sp, idp, issuerHolder);
      
      //Add information on the roles
      AssertionType assertion = (AssertionType) responseType.getAssertionOrEncryptedAssertion().get(0);

      AttributeStatementType attrStatement = StatementUtil.createAttributeStatement(roles);
      assertion.getStatementOrAuthnStatementOrAuthzDecisionStatement().add(attrStatement);
      
      //Add timed conditions
      saml2Response.createTimedConditions(assertion, assertionValidity);
      
      //Add in the attributes information
      if(this.attributeManager != null)
      {
         try
         {
            Map<String, Object> attribs = 
               attributeManager.getAttributes(userPrincipal, this.attribKeys);
            AttributeStatementType attStatement = StatementUtil.createAttributeStatement(attribs);
            assertion.getStatementOrAuthnStatementOrAuthzDecisionStatement().add(attStatement);
         }
         catch(Exception e)
         {
            log.error("Exception in generating attributes:",e);
         }
      }
 
      //Lets see how the response looks like 
      if(log.isTraceEnabled())
      {
         StringWriter sw = new StringWriter();
         try
         {
            saml2Response.marshall(responseType, sw);
         }
         catch (JAXBException e)
         {
            log.trace(e);
         }
         catch (SAXException e)
         {
            log.trace(e);
         }
         log.trace("Response="+sw.toString()); 
      }
      
      if(trace) 
         log.trace("Support Sig=" + supportSignature + " ::Post Profile?=" + hasSAMLRequestInPostProfile());
      if(supportSignature && hasSAMLRequestInPostProfile())
      {
         try
         {
            SAML2Signature saml2Signature = new SAML2Signature();
            samlResponseDocument = saml2Signature.sign(responseType, keyManager.getSigningKeyPair());
         }  
         catch (Exception e)
         {  
            if(trace) log.trace(e);
         } 
      }
      else
         try
         {
            samlResponseDocument = saml2Response.convert(responseType);
         }
         catch (Exception e)
         {
            log.trace(e);
         } 
      
      return samlResponseDocument; 
   }
   
   
   
   /**
    * Verify that the issuer is trusted
    * @param issuer
    * @throws IssuerNotTrustedException
    */
   public void isTrusted(String issuer) throws IssuerNotTrustedException
   {
      if(idpConfiguration == null)
         throw new IllegalStateException("IDP Configuration is null");
      try
      {
         String issuerDomain = getDomain(issuer);
         TrustType idpTrust =  idpConfiguration.getTrust();
         if(idpTrust != null)
         {
            String domainsTrusted = idpTrust.getDomains();
            if(trace) 
               log.trace("Domains that IDP trusts="+domainsTrusted + " and issuer domain="+issuerDomain);
            if(domainsTrusted.indexOf(issuerDomain) < 0)
            {
               //Let us do string parts checking
               StringTokenizer st = new StringTokenizer(domainsTrusted, ",");
               while(st != null && st.hasMoreTokens())
               {
                  String uriBit = st.nextToken();
                  if(trace) 
                     log.trace("Matching uri bit="+ uriBit);
                  if(issuerDomain.indexOf(uriBit) > 0)
                  {
                     if(trace) 
                        log.trace("Matched " + uriBit + " trust for " + issuerDomain );
                     return;
                  } 
               } 
               throw new IssuerNotTrustedException(issuer);
            } 
         }
      }
      catch (Exception e)
      {
         throw new IssuerNotTrustedException(e.getLocalizedMessage(),e);
      }
   }
   
   /** 
    * Send a response
    * @param responseDoc
    * @param relayState
    * @param response 
    * @throws GeneralSecurityException 
    * @throws IOException  
    */
   public void send(Document responseDoc, String destination,
         String relayState, 
         HttpServletResponse response, 
         boolean supportSignature,
         PrivateKey signingKey,
         boolean sendRequest) throws GeneralSecurityException, IOException
   {
      if(responseDoc == null)
         throw new IllegalArgumentException("responseType is null");

      byte[] responseBytes = DocumentUtil.getDocumentAsString(responseDoc).getBytes("UTF-8"); 
       
      if(redirectProfile)
      { 
         String urlEncodedResponse = RedirectBindingUtil.deflateBase64URLEncode(responseBytes);
 
         if(trace) log.trace("IDP:Destination=" + destination);

         if(isNotNull(relayState))
            relayState = RedirectBindingUtil.urlEncode(relayState);

         String finalDest = destination + getDestination(urlEncodedResponse, relayState, 
               supportSignature, sendRequest);
         if(trace) log.trace("Redirecting to="+ finalDest);
         HTTPRedirectUtil.sendRedirectForResponder(finalDest, response); 
      }  
      else
      {   
         String samlResponse = PostBindingUtil.base64Encode(new String(responseBytes));
          
         PostBindingUtil.sendPost(new DestinationInfoHolder(destination, 
               samlResponse, relayState), response, sendRequest);
      }
   }
   
   /**
    * Generate a Destination URL for the HTTPRedirect binding
    * with the saml response and relay state
    * @param urlEncodedResponse
    * @param urlEncodedRelayState
    * @return
    */
   public String getDestination(String urlEncodedResponse, String urlEncodedRelayState, 
         boolean supportSignature, boolean sendRequest)
   {
      StringBuilder sb = new StringBuilder();

      if (supportSignature)
      {
         try
         {
            sb.append("?");
            sb.append(RedirectBindingSignatureUtil.getSAMLResponseURLWithSignature(urlEncodedResponse,
                  urlEncodedRelayState, keyManager.getSigningKey()));
         }
         catch (Exception e)
         {
            if(trace) log.trace(e);
         }
      }
      else
      {
         if(sendRequest)
            sb.append("?SAMLRequest=").append(urlEncodedResponse);
         else
            sb.append("?SAMLResponse=").append(urlEncodedResponse);
         if (isNotNull(urlEncodedRelayState))
            sb.append("&RelayState=").append(urlEncodedRelayState);
      }
      return sb.toString();
   }
   
   /**
    * Create an Error Response
    * @param responseURL
    * @param status
    * @param identityURL
    * @param supportSignature
    * @return
    * @throws ConfigurationException   
    */
   public Document getErrorResponse(String responseURL, String status,
         String identityURL, boolean supportSignature)
   { 
      Document samlResponse = null;
      ResponseType responseType = null; 

      SAML2Response saml2Response = new SAML2Response();

      //Create a response type
      String id = IDGenerator.create("ID_");

      IssuerInfoHolder issuerHolder = new IssuerInfoHolder(identityURL); 
      issuerHolder.setStatusCode(status);

      IDPInfoHolder idp = new IDPInfoHolder();
      idp.setNameIDFormatValue(null);
      idp.setNameIDFormat(JBossSAMLURIConstants.NAMEID_FORMAT_PERSISTENT.get());

      SPInfoHolder sp = new SPInfoHolder();
      sp.setResponseDestinationURI(responseURL);
      try
      {
         responseType = saml2Response.createResponseType(id, sp, idp, issuerHolder);
      }
      catch (ConfigurationException e1)
      {
         if(trace) log.trace(e1);
         responseType = saml2Response.createResponseType();
      } 

      //Lets see how the response looks like 
      if(log.isTraceEnabled())
      {
         log.trace("Error_ResponseType = ");
         StringWriter sw = new StringWriter();
         try
         {
            saml2Response.marshall(responseType, sw);
         }
         catch (JAXBException e)
         {
            log.trace(e);
         }
         catch (SAXException e)
         {
            log.trace(e);
         }
         log.trace("Response="+sw.toString()); 
      }

      if(supportSignature)
      { 
         try
         {   
            SAML2Signature ss = new SAML2Signature();
            samlResponse = ss.sign(responseType, keyManager.getSigningKeyPair());
         }
         catch (Exception e)
         {
            if(trace) log.trace(e);
         } 
      }
      else
         try
         {
            samlResponse = saml2Response.convert(responseType);
         }
         catch (Exception e)
         {
            if(trace) log.trace(e);
         } 
      
      return samlResponse;    
   }
   
   /**
    * Given a SP or IDP issuer from the assertion, return the host
    * @param domainURL
    * @return
    * @throws IOException  
    */
   private static String getDomain(String domainURL) throws IOException  
   {
      URL url = new URL(domainURL);
      return url.getHost();
   }
}