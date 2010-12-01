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
package org.picketlink.identity.federation.core.wstrust.plugins.saml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import javax.xml.bind.JAXBException;

import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.parsers.saml.SAMLAssertionParser;
import org.picketlink.identity.federation.core.parsers.util.StaxParserUtil;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.saml.v2.writers.SAMLAssertionWriter;
import org.picketlink.identity.federation.core.util.StaxUtil;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AssertionType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * <p>
 * This class contains utility methods and constants that are used by the SAML token providers.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class SAMLUtil
{

   public static final String SAML2_BEARER_URI = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

   public static final String SAML2_HOLDER_OF_KEY_URI = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";

   public static final String SAML2_SENDER_VOUCHES_URI = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";

   public static final String SAML2_TOKEN_TYPE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

   public static final String SAML2_VALUE_TYPE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID";

   /**
    * <p>
    * Utility method that marshals the specified {@code AssertionType} object into an {@code Element} instance.
    * </p>
    * 
    * @param assertion
    *           an {@code AssertionType} object representing the SAML assertion to be marshaled.
    * @return a reference to the {@code Element} that contains the marshaled SAML assertion.
    * @throws Exception
    *            if an error occurs while marshaling the assertion.
    */
   public static Element toElement( AssertionType assertion ) throws Exception
   {
      /*Document document = DocumentUtil.createDocument();
      DOMResult result = new DOMResult(document);
      */
      ByteArrayOutputStream baos = new ByteArrayOutputStream(); 
      SAMLAssertionWriter writer = new SAMLAssertionWriter(StaxUtil.getXMLStreamWriter(baos)); 
      writer.write( assertion ); 
      
      ByteArrayInputStream bis = new ByteArrayInputStream( baos.toByteArray() );
      Document document = DocumentUtil.getDocument( bis ); //throws exceptions
      /*Marshaller marshaller = JAXBUtil.getMarshaller("org.picketlink.identity.federation.saml.v2.assertion");
      marshaller.marshal(new ObjectFactory().createAssertion(assertion), result);
*/
      // normalize the document to remove unused namespaces.
      // DOMConfiguration docConfig = document.getDomConfig(); 
      // docConfig.setParameter("namespaces", Boolean.TRUE); 
      // docConfig.setParameter("namespace-declarations", Boolean.FALSE); 
      // document.normalizeDocument();

      return document.getDocumentElement();
   }

   /**
    * <p>
    * Utility method that unmarshals the specified {@code Element} into an {@code AssertionType} instance.
    * </p>
    * 
    * @param assertionElement
    *           the {@code Element} that contains the marshaled SAMLV2.0 assertion.
    * @return a reference to the unmarshaled {@code AssertionType} instance.
    * @throws JAXBException if an error occurs while unmarshalling the document.
    * @throws ConfigurationException 
    * @throws ProcessingException 
    * @throws ParsingException 
    */ 
   public static AssertionType fromElement(Element assertionElement) throws JAXBException, ProcessingException, ConfigurationException, ParsingException
   {
      String assertionAsString = DocumentUtil.getDOMElementAsString(assertionElement);
      
      SAMLAssertionParser assertionParser = new SAMLAssertionParser();
      return (AssertionType) assertionParser.parse( StaxParserUtil.getXMLEventReader( new ByteArrayInputStream( assertionAsString.getBytes() )));
      
      
      /*Unmarshaller unmarshaller = JAXBUtil.getUnmarshaller("org.picketlink.identity.federation.saml.v2.assertion");
      Object object = unmarshaller.unmarshal(assertionElement);
      if (object instanceof AssertionType)
         return (AssertionType) object;
      else if (object instanceof JAXBElement)
      {
         JAXBElement<?> element = (JAXBElement<?>) object;
         if (element.getDeclaredType().equals(AssertionType.class))
            return (AssertionType) element.getValue();
      }
      throw new IllegalArgumentException("Supplied document does not contain a SAMLV2.0 Assertion");*/
   }
}
