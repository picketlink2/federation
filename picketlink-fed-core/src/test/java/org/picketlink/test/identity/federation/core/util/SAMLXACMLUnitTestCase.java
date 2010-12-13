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
package org.picketlink.test.identity.federation.core.util;

import java.io.InputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;

import junit.framework.TestCase;

import org.picketlink.identity.federation.saml.v2.profiles.xacml.protocol.XACMLAuthzDecisionQueryType; 
import org.jboss.security.xacml.core.model.context.RequestType;

/**
 * Read a SAML-XACML request
 * @author Anil.Saldhana@redhat.com
 * @since Jan 8, 2009
 */
public class SAMLXACMLUnitTestCase extends TestCase
{
   @SuppressWarnings("unchecked")
   /**
    * Usage of samlp with xsi-type 
    */
   public void testSAML_XACML_Read() throws Exception
   {
      throw new RuntimeException();
      /*String resourceName = "saml-xacml/saml-xacml-request.xml";
      String samlPath = "org.picketlink.identity.federation.saml.v2.protocol";
      String xacmlPath = "org.jboss.security.xacml.core.model.context"; 
      String xsAssert = "org.picketlink.identity.federation.saml.v2.profiles.xacml.assertion";
      String xsProto = "org.picketlink.identity.federation.saml.v2.profiles.xacml.protocol";
      String path = samlPath + ":" + xacmlPath + ":" + xsAssert + ":" + xsProto;
      
      JAXBContext jaxb = JAXBContext.newInstance(path);
      Unmarshaller un = jaxb.createUnmarshaller();
      
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream is = tcl.getResourceAsStream(resourceName);
    
      un.setEventHandler(new javax.xml.bind.helpers.DefaultValidationEventHandler());

      JAXBElement<RequestAbstractType> jaxbRequestType = (JAXBElement<RequestAbstractType>) un.unmarshal(is);
      RequestAbstractType req = jaxbRequestType.getValue();
      assertNotNull(req);
      assertTrue( req instanceof XACMLAuthzDecisionQueryType);
      
      XACMLAuthzDecisionQueryType xadqt = (XACMLAuthzDecisionQueryType) req;
      RequestType requestType = xadqt.getRequest();
      assertNotNull(requestType);*/
   }
   
   @SuppressWarnings("unchecked")
   /**
    * Usage of xacml-samlp
    */
   public void testSAML_XACML_Read_2() throws Exception
   {
      throw new RuntimeException();
      
      /*String resourceName = "saml-xacml/saml-xacml-request-2.xml";
      String samlPath = "org.picketlink.identity.federation.saml.v2.protocol";
      String xacmlPath = "org.jboss.security.xacml.core.model.context"; 
      String xsAssert = "org.picketlink.identity.federation.saml.v2.profiles.xacml.assertion";
      String xsProto = "org.picketlink.identity.federation.saml.v2.profiles.xacml.protocol";
      String path = samlPath + ":" + xacmlPath + ":" + xsAssert + ":" + xsProto;
      
      JAXBContext jaxb = JAXBContext.newInstance(path);
      Unmarshaller un = jaxb.createUnmarshaller();
      
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream is = tcl.getResourceAsStream(resourceName);
    
      un.setEventHandler(new javax.xml.bind.helpers.DefaultValidationEventHandler());

      JAXBElement<RequestAbstractType> jaxbRequestType = (JAXBElement<RequestAbstractType>) un.unmarshal(is);
      RequestAbstractType req = jaxbRequestType.getValue();
      assertNotNull(req);
      assertTrue( req instanceof XACMLAuthzDecisionQueryType);
      
      XACMLAuthzDecisionQueryType xadqt = (XACMLAuthzDecisionQueryType) req;
      RequestType requestType = xadqt.getRequest();
      assertNotNull(requestType);*/
   }
}