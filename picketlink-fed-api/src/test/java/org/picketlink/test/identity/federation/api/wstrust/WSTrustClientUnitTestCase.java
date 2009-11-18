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
package org.picketlink.test.identity.federation.api.wstrust;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.KeyStore;
import java.security.PublicKey;
import java.util.Map;

import javax.xml.bind.JAXBException;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Dispatch;
import javax.xml.ws.Service;
import javax.xml.ws.Service.Mode;
import javax.xml.ws.soap.SOAPBinding;

import junit.framework.TestCase;

import org.picketlink.identity.federation.api.wstrust.WSTrustClient;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.util.KeyStoreUtil;
import org.picketlink.identity.federation.core.util.XMLSignatureUtil;
import org.picketlink.identity.federation.core.wstrust.WSTrustConstants;
import org.picketlink.identity.federation.core.wstrust.WSTrustJAXBFactory;
import org.picketlink.identity.federation.api.wstrust.WSTrustClient.SecurityInfo;
import org.picketlink.identity.federation.core.wstrust.plugins.saml.SAMLUtil;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponse;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponseCollection;
import org.picketlink.identity.federation.ws.trust.StatusType;
import org.picketlink.identity.federation.ws.trust.ValidateTargetType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Unit tests for WS-Trust STS Clients
 * @author Anil.Saldhana@redhat.com
 * @since Aug 26, 2009
 */
public class WSTrustClientUnitTestCase extends TestCase
{
   //Specify whether this test is run as part of build
   private boolean usetest = false;
   
   
   public void testSTS() throws Exception
   {
      if(usetest == false)
         return;
      
      // create a dispatch object to invoke JBoss STSs.
      Dispatch<Source> dispatch = createDispatch();

      // create a custom token request message.
      RequestSecurityToken request = new RequestSecurityToken();
      request.setTokenType(URI.create(SAMLUtil.SAML2_TOKEN_TYPE));
      request.setRequestType(URI.create(WSTrustConstants.ISSUE_REQUEST));
      request.setContext("context");

      // send the token request to JBoss STS and get the response.
      WSTrustJAXBFactory jaxbFactory = WSTrustJAXBFactory.getInstance();
      DOMSource requestSource = (DOMSource) jaxbFactory.marshallRequestSecurityToken(request);
      Source response = dispatch.invoke(requestSource);
       
      Node documentNode = ((DOMSource) response).getNode();
      Document responseDoc = documentNode instanceof Document ? (Document) documentNode : documentNode.getOwnerDocument();
      
      
      Document myDocument = DocumentUtil.createDocument();
      
      Node importedNode = myDocument.importNode(responseDoc.getDocumentElement(), true);
      
      myDocument.appendChild(importedNode);
      
      NodeList nodes = null;
      if(responseDoc instanceof SOAPPart)
      {
         SOAPPart soapPart = (SOAPPart) responseDoc;
         SOAPEnvelope env = soapPart.getEnvelope();
         SOAPBody body = env.getBody();
         Node data = body.getFirstChild();
         nodes = ((Element)data).getElementsByTagName("RequestedSecurityToken");
      }
      else
        nodes = responseDoc.getElementsByTagNameNS(WSTrustConstants.BASE_NAMESPACE, "RequestedSecurityToken"); 
      
      assertNotNull("Nodelist not null", nodes);
      Node rstr = nodes.item(0);
      /*RequestSecurityTokenResponseCollection responseCollection = (RequestSecurityTokenResponseCollection) jaxbFactory.parseRequestSecurityTokenResponse(response);
      RequestSecurityTokenResponse tokenResponse = responseCollection.getRequestSecurityTokenResponses().get(0);

      // the SAML assertion is returned as an Element.
      Element assertion = (Element) tokenResponse.getRequestedSecurityToken().getAny();*/
      Element assertion = (Element) rstr.getFirstChild();
      System.out.println("NAMESPACE=" + assertion.getNamespaceURI());
      
//      PublicKey key = getValidatingKey();
//      Document validate = DocumentUtil.createDocument();
//      validate.appendChild(validate.importNode(assertion, true));
//      System.out.println("Is token valid? " + XMLSignatureUtil.validate(validate, key));

      // print the assertion for demonstration purposes.
      System.out.println("\nSuccessfully issued a standard SAMLV2.0 Assertion!");
      printAssertion(assertion);
      
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      KeyStore ks = KeyStoreUtil.getKeyStore(tcl.getResource("keystore/sts_keystore.jks")
            , "testpass".toCharArray());
      
      PublicKey pk = KeyStoreUtil.getPublicKey(ks, "sts", "keypass".toCharArray());
      
      assertNotNull("Public key is not null", pk);
      Document tokenDocument = DocumentUtil.createDocument();
      importedNode = tokenDocument.importNode(assertion, true); 
      tokenDocument.appendChild(importedNode);
      
      //System.out.println("Going to validate:" + DocumentUtil.getDocumentAsString(tokenDocument));
      //assertTrue("SignedInfo valid", XMLSignatureUtil.preCheckSignedInfo(tokenDocument));
      //Locally we will validate the assertion
      assertTrue("Recieved assertion sig valid", XMLSignatureUtil.validate(tokenDocument, pk)); 
      
      // let's validate the received SAML assertion.
      request.getAny().clear();
      request.setTokenType(URI.create(WSTrustConstants.STATUS_TYPE));
      request.setRequestType(URI.create(WSTrustConstants.VALIDATE_REQUEST));
      ValidateTargetType validateTarget = new ValidateTargetType();
      validateTarget.setAny(assertion);
      request.setValidateTarget(validateTarget);

      requestSource = (DOMSource) jaxbFactory.marshallRequestSecurityToken(request);
      
      response = dispatch.invoke(requestSource);
      RequestSecurityTokenResponseCollection 
      responseCollection = (RequestSecurityTokenResponseCollection) jaxbFactory
            .parseRequestSecurityTokenResponse(response);
      RequestSecurityTokenResponse tokenResponse = responseCollection.getRequestSecurityTokenResponses().get(0);

      StatusType status = tokenResponse.getStatus();
      if (status != null)
      {
         String code = status.getCode();
         assertFalse("Signature is valid", WSTrustConstants.STATUS_CODE_INVALID.equals(code));
         
         System.out.println("\n\nSAMLV2.0 Assertion successfuly validated!");
         System.out.println("Validation status code: " + tokenResponse.getStatus().getCode());
         System.out.println("Validation status reason: " + tokenResponse.getStatus().getReason());
      }
      else
         System.out.println("\n\nFailed to validate SAMLV2.0 Assertion"); 
   }
   
   public void testIssue_Validate_Renew() throws Exception
   {
      if(usetest == false)
         return;
      
      String  serviceName = "JBossSTS";
      String  portName = "JBossSTSPort";
      String endpointAddress = "http://localhost:8080/jboss-sts/JBossSTS";
      WSTrustClient client = new WSTrustClient(serviceName, portName, endpointAddress, new SecurityInfo("admin", "admin") );
      Element token = client.issueToken(SAMLUtil.SAML2_TOKEN_TYPE);
      assertTrue("Token is valid" , client.validateToken(token));
      
      Element renewedToken = client.renewToken(SAMLUtil.SAML2_TOKEN_TYPE, token);
      System.out.println("Renewed Token=" + DocumentUtil.getNodeAsString(renewedToken));
   }
    
   
   private  Dispatch<Source> createDispatch() throws MalformedURLException, JAXBException
   {
      // JBoss STS target information.
      String targetNS = "http://org.picketlink.trust/sts/";
      QName serviceName = new QName(targetNS, "JBossSTS");
      QName portName = new QName(targetNS, "JBossSTSPort");
      URL endpointAddress = new URL("http://localhost:8080/jboss-sts/JBossSTS");
//      URL securityConfigURL = new File("jboss-wsse-client.xml").toURI().toURL();

      Service service = Service.create(serviceName);
      service.addPort(portName, SOAPBinding.SOAP11HTTP_BINDING, endpointAddress.toExternalForm());

      // create the dispatch, setting the client security configuration file.
      Dispatch<Source> dispatch = service.createDispatch(portName, Source.class, Mode.PAYLOAD);
//      ((ConfigProvider) dispatch).setSecurityConfig(securityConfigURL.toExternalForm());
//      ((ConfigProvider) dispatch).setConfigName("Standard WSSecurity Client");

      // add the username and password to the request context.
      Map<String, Object> reqContext = dispatch.getRequestContext();
      reqContext.put(BindingProvider.USERNAME_PROPERTY, "admin");
      reqContext.put(BindingProvider.PASSWORD_PROPERTY, "admin");

      return dispatch;
   }

   private  void printAssertion(Element assertion) throws Exception
   {
      TransformerFactory tranFactory = TransformerFactory.newInstance();
      Transformer aTransformer = tranFactory.newTransformer();
      Source src = new DOMSource(assertion);
      Result dest = new StreamResult(System.out);
      aTransformer.transform(src, dest);
   }
}