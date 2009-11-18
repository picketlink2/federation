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
package org.picketlink.test.identity.federation.ws.trust;

import java.io.File;
import java.net.URI;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;

import junit.framework.TestCase;

import org.picketlink.identity.federation.ws.trust.RequestSecurityTokenCollectionType;
import org.picketlink.identity.federation.ws.trust.RequestSecurityTokenType;

/**
 * <p>
 * A {@code TestCase} that validates the unmarshalling of ws-trust messages.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class UnmarshallingTestCase extends TestCase
{

   /**
    * <p>
    * Tests unmarshalling a simple ws-trust security token request.
    * </p>
    * 
    * @throws Exception if an error occurs while running the test.
    */
   @SuppressWarnings("unchecked")
   public void testUnmarshallTokenRequest() throws Exception
   {
      JAXBContext context = JAXBContext.newInstance("org.picketlink.identity.federation.ws.policy:org.picketlink.identity.federation.ws.trust");
      Unmarshaller unmarshaller = context.createUnmarshaller();
      // this.setValidatingSchema("/schema/wstrust/v1_3/ws-trust-1.3.xsd", unmarshaller);

      // unmarshall the sample security token request.
      URI sampleURI = this.getClass().getResource("/wstrust/simple-request.xml").toURI();
      Object object = unmarshaller.unmarshal(new File(sampleURI));
      assertNotNull("Unexpected null object", object);
      assertTrue("Unexpected object type", object instanceof JAXBElement);

      JAXBElement element = (JAXBElement) object;
      assertEquals("Invalid element name", "RequestSecurityToken", element.getName().getLocalPart());
      assertEquals("Invalid element type", RequestSecurityTokenType.class, element.getDeclaredType());

      // validate the request contents.
      RequestSecurityTokenType request = (RequestSecurityTokenType) element.getValue();
      List<Object> contents = request.getAny();
      assertNotNull("Unexpected null value for the request contents", contents);
      assertEquals("Unexpected number of contents", 2, contents.size());

      // first element should be TokenType.
      JAXBElement<String> tokenType = (JAXBElement<String>) contents.get(0);
      assertEquals("TokenType", tokenType.getName().getLocalPart());
      assertEquals("http://example.org/mySpecialToken", tokenType.getValue());

      // second element should be RequestType.
      JAXBElement<String> requestType = (JAXBElement<String>) contents.get(1);
      assertEquals("RequestType", requestType.getName().getLocalPart());
      assertEquals("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue", requestType.getValue());
   }

   /**
    * <p>
    * Tests unmarshalling a ws-trust request for a collection of security tokens.
    * </p>
    * 
    * @throws Exception if an error occurs while running the test.
    */
   @SuppressWarnings("unchecked")
   public void testUnmarshallTokenCollectionRequest() throws Exception
   {
      JAXBContext context = JAXBContext.newInstance("org.picketlink.identity.federation.ws.trust");
      Unmarshaller unmarshaller = context.createUnmarshaller();
      // this.setValidatingSchema("/schema/wstrust/v1_3/ws-trust-1.3.xsd", unmarshaller);

      // unmarshall the sample security token request.
      URI sampleURI = this.getClass().getResource("/wstrust/collection-request.xml").toURI();
      Object object = unmarshaller.unmarshal(new File(sampleURI));
      assertNotNull("Unexpected null object", object);
      assertTrue("Unexpected object type", object instanceof JAXBElement);

      JAXBElement element = (JAXBElement) object;
      assertEquals("Invalid element name", "RequestSecurityTokenCollection", element.getName().getLocalPart());
      assertEquals("Invalid element type", RequestSecurityTokenCollectionType.class, element.getDeclaredType());

      List<RequestSecurityTokenType> requests = ((RequestSecurityTokenCollectionType) element.getValue())
            .getRequestSecurityToken();
      assertNotNull("Unexpected null request list", requests);
      assertEquals("Unexpected number of requests", 2, requests.size());
      
      // first request must have the http://www.example.com/1 context.
      RequestSecurityTokenType request = requests.get(0);
      assertEquals("Invalid context id", "http://www.example.com/1", request.getContext());
      List<Object> contents = request.getAny();
      assertNotNull("Unexpected null value for the request contents", contents);
      assertEquals("Unexpected number of contents", 4, contents.size());

      // second request must have the http://www.example.com/2 context.
      request = requests.get(1);
      assertEquals("Invalid context id", "http://www.example.com/2", request.getContext());
      contents = request.getAny();
      assertNotNull("Unexpected null value for the request contents", contents);
      assertEquals("Unexpected number of contents", 4, contents.size());
   }
}