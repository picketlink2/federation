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
package org.jboss.test.identity.federation.bindings.servlets;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.HashMap;

import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;

import junit.framework.TestCase;

import org.jboss.identity.federation.bindings.servlets.SOAPSAMLXACMLServlet;
import org.jboss.identity.federation.core.saml.v2.util.SOAPSAMLXACMLUtil;
import org.jboss.identity.federation.core.util.JAXBUtil;
import org.jboss.identity.federation.org.xmlsoap.schemas.soap.envelope.Envelope;
import org.jboss.identity.federation.org.xmlsoap.schemas.soap.envelope.Fault;
import org.jboss.identity.federation.saml.v2.assertion.AssertionType;
import org.jboss.identity.federation.saml.v2.profiles.xacml.assertion.XACMLAuthzDecisionStatementType;
import org.jboss.identity.federation.saml.v2.protocol.ResponseType;
import org.jboss.security.xacml.core.model.context.DecisionType;
import org.jboss.security.xacml.core.model.context.ResultType;

/**
 * Unit Test the SOAP SAML XACML Servlet
 * @author Anil.Saldhana@redhat.com
 * @since Jan 28, 2009
 */
public class SOAPSAMLXACMLServletUnitTestCase extends TestCase
{ 
   public void testPermit() throws Exception
   { 
      validate("xacml/requests/XacmlRequest-01-01.xml", DecisionType.PERMIT.value()); 

      validate("xacml/requests/XacmlRequest-format2-01-01.xml", DecisionType.PERMIT.value()); 
   }
   
   public void testDeny() throws Exception
   {  
      validate("xacml/requests/XacmlRequest-01-02.xml", DecisionType.DENY.value());
   }
   
   @SuppressWarnings("unchecked")
   public void testIncorrectInput() throws Exception
   {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      
      String garbage = "fdfdsfdfk";
      ByteArrayInputStream bis = new ByteArrayInputStream(garbage.getBytes());
      
      SOAPSAMLXACMLServlet servlet = new SOAPSAMLXACMLServlet();
      servlet.init(new TestServletConfig(getServletContext()));
      ServletRequest sreq = new TestServletRequest(bis);
      ServletResponse sresp = new TestServletResponse(baos);
      servlet.service(sreq, sresp); 
       
      sresp.flushBuffer(); //Flush the servlet response ServletOutputStream to our baos
      
      bis = new ByteArrayInputStream(baos.toByteArray());
      Unmarshaller un = JAXBUtil.getUnmarshaller(SOAPSAMLXACMLUtil.getPackage());
      JAXBElement<Envelope> jax = (JAXBElement<Envelope>) un.unmarshal(bis);
      Envelope envelope = jax.getValue();
      assertNotNull("Envelope is not null", envelope); 
      JAXBElement<?> fault = (JAXBElement<?>) envelope.getBody().getAny().get(0);
      assertTrue(fault.getValue() instanceof Fault); 
   }
   
   public void testInteropSOAPRequest() throws Exception
   {
      validate("xacml/requests/interop-request.xml", DecisionType.PERMIT.value()); 
   }
   
   @SuppressWarnings("unchecked")
   private void validate(String requestFile, String value) throws Exception
   {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      
      SOAPSAMLXACMLServlet servlet = new SOAPSAMLXACMLServlet();
      servlet.init(new TestServletConfig(getServletContext()));
      InputStream is = getInputStream(requestFile);
      if(is == null)
         throw new IllegalArgumentException("Input Stream to request file is null");
      ServletRequest sreq = new TestServletRequest(is);
      ServletResponse sresp = new TestServletResponse(baos);
      servlet.service(sreq, sresp); 
       
      sresp.flushBuffer(); //Flush the servlet response ServletOutputStream to our baos
      
      ByteArrayInputStream bis = new ByteArrayInputStream(baos.toByteArray());
      Unmarshaller un = JAXBUtil.getUnmarshaller(SOAPSAMLXACMLUtil.getPackage());
      JAXBElement<Envelope> jax = (JAXBElement<Envelope>) un.unmarshal(bis);
      Envelope envelope = jax.getValue();
      assertNotNull("Envelope is not null", envelope);
      
      JAXBElement<ResponseType> jaxbResponseType = (JAXBElement<ResponseType>) envelope.getBody().getAny().get(0);
      ResponseType responseType = jaxbResponseType.getValue();
      
      assertNotNull("ResponseType is not null", responseType); 
      AssertionType assertion = (AssertionType) responseType.getAssertionOrEncryptedAssertion().get(0);
      XACMLAuthzDecisionStatementType xacmlStatement = (XACMLAuthzDecisionStatementType) assertion.getStatementOrAuthnStatementOrAuthzDecisionStatement().get(0);
      assertNotNull("XACML Authorization Statement is not null", xacmlStatement);
      org.jboss.security.xacml.core.model.context.ResponseType xacmlResponse = xacmlStatement.getResponse();
      ResultType resultType = xacmlResponse.getResult().get(0);
      DecisionType decision = resultType.getDecision();
      assertNotNull("Decision is not null", decision);
      assertEquals(value, decision.value()); 
   }
   
   private ServletContext getServletContext()
   {
      HashMap<String,String> map = new HashMap<String, String>();
      map.put("policyConfigFileName", "xacml/policies/config/rsaConfPolicyConfig.xml");
      return new TestServletContext(map); 
   }
   
   private InputStream getInputStream(String requestFileLoc)
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      return tcl.getResourceAsStream(requestFileLoc); 
   } 
}