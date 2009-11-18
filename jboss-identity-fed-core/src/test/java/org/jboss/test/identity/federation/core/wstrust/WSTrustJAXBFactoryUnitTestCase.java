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

import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;

import junit.framework.TestCase;

import org.jboss.identity.federation.core.saml.v2.util.DocumentUtil;
import org.jboss.identity.federation.core.wstrust.WSTrustJAXBFactory;
import org.jboss.identity.federation.core.wstrust.wrappers.BaseRequestSecurityToken;
import org.jboss.identity.federation.core.wstrust.wrappers.BaseRequestSecurityTokenResponse;
import org.jboss.identity.federation.core.wstrust.wrappers.RequestSecurityToken;
import org.jboss.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponse;
import org.jboss.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponseCollection;
import org.w3c.dom.Document;

/**
 * <p>
 * This {@code TestCase} tests the methods of the {@code WSTrustJAXBFactory}.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class WSTrustJAXBFactoryUnitTestCase extends TestCase
{

   /**
    * <p>
    * Tests parsing a WS-Trust request message.
    * </p>
    * 
    * @throws Exception
    *            if an error occurs while running the test.
    */
   public void testParseRequestSecurityToken() throws Exception
   {
      // load a sample ws-trust request from a test file.
      Document document = DocumentUtil
            .getDocument(this.getClass().getResourceAsStream("/wstrust/ws-trust-request.xml"));

      // encapsulate the request in a source object.
      Source source = new DOMSource(document);
      
      // parse the request using the WSTrustJAXBFactory.
      WSTrustJAXBFactory factory = WSTrustJAXBFactory.getInstance();
      BaseRequestSecurityToken baseRequest = factory.parseRequestSecurityToken(source);
      assertNotNull("Unexpected null request message", baseRequest);

      // check the contents of the parsed request.
      assertTrue("Unexpected request message type", baseRequest instanceof RequestSecurityToken);
      RequestSecurityToken parsedRequest = (RequestSecurityToken) baseRequest;
      assertEquals("Unexpected context name", "testcontext", parsedRequest.getContext());
      assertEquals("Unexpected token type", "http://www.tokens.org/SpecialToken", parsedRequest.getTokenType().toString());
      assertEquals("Unexpected request type", "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue", parsedRequest
            .getRequestType().toString());
   }

   /**
    * <p>
    * Tests parsing a WS-Trust response message.
    * </p>
    * 
    * @throws Exception
    *            if an error occurs while running the test.
    */
   public void testParseRequestSecurityTokenResponse() throws Exception
   {
      // load a ws-trust response from a file.
      Document document = DocumentUtil.getDocument(this.getClass()
            .getResourceAsStream("/wstrust/ws-trust-response.xml"));

      // encapsulate the response in a source object.
      Source source = new DOMSource(document);

      // parse the response using the WSTrustJAXBFactory.
      WSTrustJAXBFactory factory = WSTrustJAXBFactory.getInstance();
      BaseRequestSecurityTokenResponse baseResponse = factory.parseRequestSecurityTokenResponse(source);
      assertNotNull("Unexpected null response message", baseResponse);

      // check the contents of the parsed response.
      assertTrue("Unexpected response message type", baseResponse instanceof RequestSecurityTokenResponseCollection);
      RequestSecurityTokenResponseCollection parsedCollection = (RequestSecurityTokenResponseCollection) baseResponse;
      assertNotNull("Unexpected null response list", parsedCollection.getRequestSecurityTokenResponses());
      assertEquals("Unexpected number of responses", 1, parsedCollection.getRequestSecurityTokenResponses().size());

      RequestSecurityTokenResponse parsedResponse = parsedCollection.getRequestSecurityTokenResponses().get(0);
      assertEquals("Unexpected context name", "testcontext", parsedResponse.getContext());
      assertEquals("Unexpected token type", "http://www.tokens.org/SpecialToken", parsedResponse.getTokenType()
            .toString());
      assertFalse(parsedResponse.isForwardable());
   }

   /**
    * <p>
    * Tests the marshalling of a WS-Trust request.
    * </p>
    * 
    * @throws Exception
    *            if an error occurs while running the test.
    */
   public void testMarshallRequestSecurityToken() throws Exception
   {
      // create a request object.
      RequestSecurityToken request = new RequestSecurityToken();
      request.setContext("testcontext");
      request.setTokenType(new URI("http://www.tokens.org/SpecialToken"));
      request.setRequestType(new URI("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"));

      // use the factory to marshall the request.
      WSTrustJAXBFactory factory = WSTrustJAXBFactory.getInstance();
      Source source = factory.marshallRequestSecurityToken(request);
      assertNotNull("Unexpected null source", source);
      assertTrue("Unexpected source type", source instanceof DOMSource);

      // at this point we know that the parsing works, so parse the generated source and compare to the original request.
      BaseRequestSecurityToken baseRequest = factory.parseRequestSecurityToken(source);
      assertNotNull("Unexpected null value for the parsed request", baseRequest);
      assertTrue("Unexpected parsed request type", baseRequest instanceof RequestSecurityToken);
      RequestSecurityToken parsedRequest = (RequestSecurityToken) baseRequest;
      assertEquals("Unexpected context value", request.getContext(), parsedRequest.getContext());
      assertTrue("Unexpected token type", request.getTokenType().equals(parsedRequest.getTokenType()));
      assertTrue("Unexpected request type", request.getRequestType().equals(parsedRequest.getRequestType()));
   }

   /**
    * <p>
    * Tests the marshalling of a WS-Trust response.
    * </p>
    * 
    * @throws Exception
    *            if an error occurs while running the test.
    */
   public void testMarshallRequestSecurityTokenResponse() throws Exception
   {
      // create a sample ws-trust response message.
      RequestSecurityTokenResponse response = new RequestSecurityTokenResponse();
      response.setContext("testcontext");
      response.setTokenType(new URI("http://www.tokens.org/SpecialToken"));
      response.setForwardable(false);

      RequestSecurityTokenResponseCollection collection = new RequestSecurityTokenResponseCollection();
      collection.addRequestSecurityTokenResponse(response);

      // use the factory to marshall the response.
      WSTrustJAXBFactory factory = WSTrustJAXBFactory.getInstance();
      Source source = factory.marshallRequestSecurityTokenResponse(collection);
      assertNotNull("Unexpected null source", source);
      assertTrue("Unexpected source type", source instanceof DOMSource);

      // at this point we know that the parsing works, so parse the generated source and compare to the original response.
      BaseRequestSecurityTokenResponse baseResponse = factory.parseRequestSecurityTokenResponse(source);
      assertNotNull("Unexpected null value for the parsed response", baseResponse);
      assertTrue("Unexpected parsed request type", baseResponse instanceof RequestSecurityTokenResponseCollection);
      RequestSecurityTokenResponseCollection parsedCollection = (RequestSecurityTokenResponseCollection) baseResponse;
      assertNotNull("Unexpected null response list", parsedCollection.getRequestSecurityTokenResponses());
      assertEquals("Unexpected number of responses", 1, parsedCollection.getRequestSecurityTokenResponses().size());

      RequestSecurityTokenResponse parsedResponse = parsedCollection.getRequestSecurityTokenResponses().get(0);
      assertEquals("Unexpected context value", response.getContext(), parsedResponse.getContext());
      assertTrue("Unexpected token type", response.getTokenType().equals(parsedResponse.getTokenType()));
      assertFalse(parsedResponse.isForwardable());
   }
}
