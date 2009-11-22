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

import static org.jboss.seam.ScopeType.APPLICATION;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.LoginException;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;

import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.intercept.BypassInterceptors;
import org.jboss.seam.annotations.web.Filter;
import org.jboss.seam.contexts.Context;
import org.jboss.seam.contexts.SessionContext;
import org.jboss.seam.log.Log;
import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;
import org.jboss.seam.servlet.ContextualHttpServletRequest;
import org.jboss.seam.servlet.ServletRequestSessionMap;
import org.jboss.seam.util.Base64;
import org.jboss.seam.web.AbstractFilter;
import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.api.saml.v2.response.SAML2Response;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLDocumentHolder;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.saml.v2.holders.DestinationInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.util.XMLSignatureUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusType;
import org.picketlink.identity.federation.web.util.HTTPRedirectUtil;
import org.picketlink.identity.federation.web.util.PostBindingUtil;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * Seam Servlet Filter supporting SAMLv2 authentication. It implements the Web
 * Browser SSO Profile. For outgoing authentication requests it can use either
 * HTTP Post or HTTP Redirect binding. For the responses, it uses HTTP Post
 * binding, with signature validation.
 * 
 * Properties that configure this component:
 * 
 * <dl>
 * <dt>serviceProviderEntityId</dt>
 * <dd>Identifier of this SP (sent to the IDP as issuer).</dd>
 * <dt>singleSignOnServiceURL</dt>
 * <dd>URL of the SSO Service of the identity provider.</dd>
 * <dt>keyStoreURL</dt>
 * <dd>URL of the keystore.</dd>
 * <dt>keyStorePass</dt>
 * <dd>Password that gives access to the keystore.</dd>
 * <dt>idpCertificateAlias</dt>
 * <dd>The alias of the keystore entry that contains the certificate of the IDP.
 * </dd>
 * <dt>binding</dt>
 * <dd>Method for sending the authentication request: HTTP_Redirect or
 * HTTP_Post. Default: HTTP_Post.</dd>
 * <dt>signatureRequired</dt>
 * <dd>Specifies whether IDP responses are required to have a valid signature.
 * Default: true.</dd>
 * </dl>
 * 
 * @author Marcel Kolsteren
 * @author Anil Saldhana
 */
@Scope(APPLICATION)
@Name("org.picketlink.identity.seam.federation.samlAuthenticationFilter")
@BypassInterceptors
@Filter(within = "org.jboss.seam.web.exceptionFilter")
public class SamlAuthenticationFilter extends AbstractFilter
{
   enum Binding {
      HTTP_Redirect, HTTP_Post
   };

   private String serviceProviderEntityId;

   private String singleSignOnServiceURL;

   private String keyStoreURL;

   private String keyStorePass;

   private String idpCertificateAlias;

   private PublicKey publicKeyOfIDP;

   private Binding binding = Binding.HTTP_Post;

   private boolean signatureRequired = true;

   protected static class AuthenticatedUser
   {
      String userName;

      Map<String, List<String>> attributes = new HashMap<String, List<String>>();
   }

   @Logger
   private Log log;

   @Override
   public void init(FilterConfig filterConfig) throws ServletException
   {
      super.init(filterConfig);
      if (signatureRequired)
      {
         publicKeyOfIDP = getPublicKeyOfIDP();
      }
   }

   public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
         ServletException
   {
      if (!(request instanceof HttpServletRequest))
      {
         throw new ServletException("This filter can only process HttpServletRequest requests");
      }

      HttpServletRequest httpRequest = (HttpServletRequest) request;
      HttpServletResponse httpResponse = (HttpServletResponse) response;

      if (request.getParameter("SAMLResponse") != null)
      {
         // Received an authentication response from the IDP.

         AuthenticatedUser user = processIDPResponse((HttpServletRequest) request);
         if (user != null)
         {
            // Login the user. This ends with a redirect to the URL that was
            // requested by the user.
            loginUser(httpRequest, httpResponse, user);
         }
      }
      else if (request.getParameter("newRelayState") != null)
      {
         // User requested a page for which login is required. Return a page
         // that instructs the browser to post an
         // authentication request to the IDP.
         sendRequestToIDP(httpRequest, httpResponse);
      }
      else
      {
         // Request is not related to SAMLv2 authentication. Pass it on to
         // the next chain.
         chain.doFilter(request, response);
      }
   }

   private void loginUser(HttpServletRequest httpRequest, HttpServletResponse httpResponse, AuthenticatedUser user)
         throws ServletException, IOException
   {
      // Force session creation
      httpRequest.getSession();

      Context ctx = new SessionContext(new ServletRequestSessionMap(httpRequest));

      // Only reauthenticate if username doesn't match Identity.username
      // and user isn't authenticated
      Credentials credentials = (Credentials) ctx.get(Credentials.class);
      Identity identity = (Identity) ctx.get(Identity.class);

      if (identity.isLoggedIn())
      {
         throw new RuntimeException("User is already logged in.");
      }

      credentials.setPassword("");
      authenticate(httpRequest, user);
      RelayStates relayStates = (RelayStates) ctx.get(RelayStates.class);
      String relayState = httpRequest.getParameter("RelayState");
      if (relayState == null)
      {
         throw new RuntimeException("RelayState parameter is missing");
      }
      relayStates.restoreState(Integer.parseInt(relayState), httpResponse);
   }

   private void authenticate(HttpServletRequest request, final AuthenticatedUser user) throws ServletException,
         IOException
   {
      new ContextualHttpServletRequest(request)
      {
         @Override
         public void process() throws ServletException, IOException, LoginException
         {
            SamlIdentity identity = (SamlIdentity) Identity.instance();
            identity.getCredentials().setUsername(user.userName);
            identity.setAttributes(user.attributes);
            identity.authenticate();
         }
      }.run();
   }

   private AuthenticatedUser processIDPResponse(HttpServletRequest request)
   {
      String samlResponse = request.getParameter("SAMLResponse");

      // deal with SAML response from IDP
      byte[] base64DecodedResponse = Base64.decode(samlResponse);
      InputStream is = new ByteArrayInputStream(base64DecodedResponse);

      SAML2Response saml2Response = new SAML2Response();

      ResponseType responseType;
      try
      {
         responseType = saml2Response.getResponseType(is);
      }
      catch (GeneralSecurityException e)
      {
         throw new RuntimeException(e);
      }

      if (signatureRequired && !validateSignature(saml2Response.getSamlDocumentHolder()))
      {
         log.error("Invalid signature");
         throw new RuntimeException("Validity Checks failed");
      }

      StatusType statusType = responseType.getStatus();
      if (statusType == null)
      {
         throw new RuntimeException("Status Type from the IDP is null");
      }

      String statusValue = statusType.getStatusCode().getValue();
      if (JBossSAMLURIConstants.STATUS_SUCCESS.get().equals(statusValue) == false)
      {
         throw new RuntimeException("IDP forbid the user");
      }

      List<Object> assertions = responseType.getAssertionOrEncryptedAssertion();
      if (assertions.size() == 0)
      {
         throw new RuntimeException("IDP response does not contain assertions");
      }

      AuthenticatedUser user = null;

      for (Object assertion : responseType.getAssertionOrEncryptedAssertion())
      {
         if (assertion instanceof AssertionType)
         {
            AuthenticatedUser userInAssertion = handleAssertion((AssertionType) assertion);
            if (user == null)
            {
               user = userInAssertion;
            }
            else
            {
               log.warn("Multiple authenticated users found in assertions. Using the first one.");
            }
         }
         else
         {
            /* assertion instanceof EncryptedElementType */
            log.warn("Encountered encrypted assertion. Skipping it because decryption is not yet supported.");
         }
      }
      if (user == null)
      {
         log.warn("No authenticated users found in assertions.");
      }

      return user;
   }

   private AuthenticatedUser handleAssertion(AssertionType assertion)
   {
      try
      {
         if (AssertionUtil.hasExpired(assertion))
         {
            log.warn("Received assertion will not be processed because it has expired.");
            return null;
         }
      }
      catch (ConfigurationException e)
      {
         throw new RuntimeException(e);
      }

      AuthenticatedUser user = null;

      for (JAXBElement<?> contentElement : assertion.getSubject().getContent())
      {
         if (contentElement.getName().getLocalPart().equals("NameID"))
         {
            user = new AuthenticatedUser();
            user.userName = ((NameIDType) contentElement.getValue()).getValue();
         }
      }

      if (user != null)
      {
         for (StatementAbstractType statement : assertion.getStatementOrAuthnStatementOrAuthzDecisionStatement())
         {
            if (statement instanceof AttributeStatementType)
            {
               AttributeStatementType attributeStatement = (AttributeStatementType) statement;
               for (Object object : attributeStatement.getAttributeOrEncryptedAttribute())
               {
                  if (object instanceof AttributeType)
                  {
                     AttributeType attr = (AttributeType) object;
                     List<String> values = user.attributes.get(attr.getName());
                     if (values == null)
                     {
                        values = new LinkedList<String>();
                     }
                     for (Object value : attr.getAttributeValue())
                     {
                        values.add((String) value);
                     }
                     user.attributes.put(attr.getName(), values);
                  }
                  else
                  {
                     log.warn("Encrypted attributes are not supported. Ignoring the attribute.");
                  }
               }
            }
         }
      }
      else
      {
         log.warn("Subject is not specified using the NameID element. Ignoring the assertion.");
      }

      return user;
   }

   private boolean validateSignature(SAMLDocumentHolder documentHolder)
   {
      try
      {
         Document samlDocument = documentHolder.getSamlDocument();
         return XMLSignatureUtil.validate(samlDocument, this.publicKeyOfIDP);
      }
      catch (MarshalException e)
      {
         throw new RuntimeException(e);
      }
      catch (XMLSignatureException e)
      {
         throw new RuntimeException(e);
      }
   }

   private PublicKey getPublicKeyOfIDP()
   {
      final String classPathPrefix = "classpath:";

      try
      {
         KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
         InputStream keyStoreStream;
         if (keyStoreURL.startsWith(classPathPrefix))
         {
            keyStoreStream = getClass().getClassLoader().getResourceAsStream(
                  keyStoreURL.substring(classPathPrefix.length()));
         }
         else
         {
            keyStoreStream = new URL(keyStoreURL).openStream();
         }
         keyStore.load(keyStoreStream, keyStorePass != null ? keyStorePass.toCharArray() : null);
         return keyStore.getCertificate(idpCertificateAlias).getPublicKey();
      }
      catch (KeyStoreException e)
      {
         throw new RuntimeException(e);
      }
      catch (NoSuchAlgorithmException e)
      {
         throw new RuntimeException(e);
      }
      catch (CertificateException e)
      {
         throw new RuntimeException(e);
      }
      catch (MalformedURLException e)
      {
         throw new RuntimeException(e);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   private void sendRequestToIDP(HttpServletRequest request, HttpServletResponse response)
   {
      Integer relayState = Integer.parseInt(request.getParameter("newRelayState"));

      try
      {
         /*
          * Derive the assertion consumer service URL from the current
          * request URL. Replace the last part with a place holder, because
          * we do not want the IDP to know what page the user requested.
          */
         String assertionConsumerServiceURL = request.getScheme() + "://" + request.getServerName() + ":"
               + request.getServerPort() + request.getContextPath() + "/SamlAuthenticationFilter.seam";

         AuthnRequestType authnRequest = createSAMLRequest(assertionConsumerServiceURL, singleSignOnServiceURL,
               serviceProviderEntityId);

         SAML2Request saml2Request = new SAML2Request();
         ByteArrayOutputStream baos = new ByteArrayOutputStream();
         saml2Request.marshall(authnRequest, baos);

         if (log.isDebugEnabled())
         {
            log.debug("Sending over to SP: {0}", DocumentUtil.asString(saml2Request.convert(authnRequest)));
         }

         String samlMessage = PostBindingUtil.base64Encode(baos.toString());
         if (binding == Binding.HTTP_Redirect)
         {
            String deflatedRequest = RedirectBindingUtil.deflateBase64URLEncode(baos.toByteArray());
            StringBuilder sb = new StringBuilder();
            sb.append(singleSignOnServiceURL.contains("?") ? '&' : '?');
            sb.append("SAMLRequest=").append(deflatedRequest);
            sb.append("&RelayState=").append(relayState);
            HTTPRedirectUtil.sendRedirectForRequestor(singleSignOnServiceURL + sb.toString(), response);
         }
         else
         {
            DestinationInfoHolder destinationInfoHolder = new DestinationInfoHolder(singleSignOnServiceURL,
                  samlMessage, Integer.toString(relayState));
            PostBindingUtil.sendPost(destinationInfoHolder, response, true);
         }
      }
      catch (ConfigurationException e)
      {
         throw new RuntimeException();
      }
      catch (SAXException e)
      {
         throw new RuntimeException(e);
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   private AuthnRequestType createSAMLRequest(String assertionConsumerServiceURL, String singleSignOnServiceURL,
         String serviceProviderEntityId) throws ConfigurationException
   {
      if (assertionConsumerServiceURL == null)
         throw new IllegalArgumentException("assertionConsumerServiceURL is null");
      if (singleSignOnServiceURL == null)
         throw new IllegalArgumentException("singleSignOnServiceURL is null");
      if (serviceProviderEntityId == null)
         throw new IllegalArgumentException("serviceProviderEntityId is null");

      SAML2Request saml2Request = new SAML2Request();
      String id = IDGenerator.create("ID_");
      return saml2Request.createAuthnRequestType(id, assertionConsumerServiceURL, singleSignOnServiceURL,
            serviceProviderEntityId);
   }
}
