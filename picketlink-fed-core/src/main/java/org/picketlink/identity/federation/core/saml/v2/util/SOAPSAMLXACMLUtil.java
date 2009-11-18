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
package org.picketlink.identity.federation.core.saml.v2.util;

import java.io.StringReader;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.util.JAXBUtil;
import org.picketlink.identity.federation.saml.v2.profiles.xacml.assertion.ObjectFactory;
import org.picketlink.identity.federation.saml.v2.profiles.xacml.assertion.XACMLAuthzDecisionStatementType;
import org.picketlink.identity.federation.saml.v2.profiles.xacml.protocol.XACMLAuthzDecisionQueryType;
import org.w3c.dom.Element;

/**
 * Utility associated with SOAP 1.1 Envelope,
 * SAML2 and XACML2
 * @author Anil.Saldhana@redhat.com
 * @since Jan 28, 2009
 */
public class SOAPSAMLXACMLUtil
{   
   private static String SOAP_PKG = "org.picketlink.identity.federation.org.xmlsoap.schemas.soap.envelope";
   private static String SAML_PROTO_PKG = "org.picketlink.identity.federation.saml.v2.protocol";
   private static String XACML_CTX_PKG = "org.jboss.security.xacml.core.model.context";
   private static String XACML_SAMLPROTO_PKG = "org.picketlink.identity.federation.saml.v2.profiles.xacml.protocol";
   private static String XACML_SAMLASSERT_PKG = "org.picketlink.identity.federation.saml.v2.profiles.xacml.assertion";
   
   private static String COLON = ":";
   
   private static String collectivePackage = getPackage();
   
   private static org.picketlink.identity.federation.saml.v2.profiles.xacml.protocol.ObjectFactory
       queryTypeObjectFactory = new org.picketlink.identity.federation.saml.v2.profiles.xacml.protocol.ObjectFactory();
   
   private static ObjectFactory statementObjectFactory = new ObjectFactory();
   
   /**
    * Parse the XACML Authorization Decision Query from the Dom Element
    * @param samlRequest
    * @return 
    * @throws TransformerException 
    * @throws TransformerFactoryConfigurationError 
    * @throws JAXBException 
    */
   public static XACMLAuthzDecisionQueryType getXACMLQueryType(Element samlRequest) 
   throws ConfigurationException, ProcessingException, JAXBException 
   {
      //We reparse it because the document may have issues with namespaces
      String elementString = DocumentUtil.getDOMElementAsString(samlRequest);
      Unmarshaller um = JAXBUtil.getUnmarshaller(collectivePackage);
      um.setEventHandler(new javax.xml.bind.helpers.DefaultValidationEventHandler());

      JAXBElement<?> obj = (JAXBElement<?>) um.unmarshal(new StringReader(elementString));
      Object xacmlObject = obj.getValue();
      if(xacmlObject instanceof XACMLAuthzDecisionQueryType == false)
         throw new RuntimeException("Unsupported type:" + xacmlObject);
      return (XACMLAuthzDecisionQueryType)xacmlObject;  
   }
   
   public static XACMLAuthzDecisionQueryType createXACMLAuthzDecisionQueryType()
   {
      return queryTypeObjectFactory.createXACMLAuthzDecisionQueryType();
   } 
   
   public static XACMLAuthzDecisionStatementType createXACMLAuthzDecisionStatementType()
   {
      return statementObjectFactory.createXACMLAuthzDecisionStatementType();
   }
   
   public static JAXBElement<XACMLAuthzDecisionQueryType> getJAXB(XACMLAuthzDecisionQueryType queryType)
   {
      return queryTypeObjectFactory.createXACMLAuthzDecisionQuery(queryType);
   }
   
   public static JAXBElement<XACMLAuthzDecisionStatementType> getJAXB(XACMLAuthzDecisionStatementType stmtType)
   {
      return statementObjectFactory.createXACMLAuthzDecisionStatement(stmtType);
   }
   
   public static Marshaller getMarshaller() throws JAXBException
   {
      return JAXBUtil.getMarshaller(getPackage());
   }
   
   public static Unmarshaller getUnmarshaller() throws JAXBException
   {
      return JAXBUtil.getUnmarshaller(getPackage());
   }
   
   public static String getPackage()
   {
      StringBuffer buf = new StringBuffer();
      buf.append(SOAP_PKG).append(COLON).append(SAML_PROTO_PKG).append(COLON);
      buf.append(XACML_CTX_PKG).append(COLON).append(XACML_SAMLPROTO_PKG).append(COLON).append(XACML_SAMLASSERT_PKG); 
      return buf.toString();
   }
}