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
package org.picketlink.identity.federation.web.servlets.saml;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivilegedActionException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.helpers.DefaultValidationEventHandler;

import org.apache.log4j.Logger;
import org.picketlink.identity.federation.api.saml.v2.response.SAML2Response;
import org.picketlink.identity.federation.core.factories.SOAPFactory;
import org.picketlink.identity.federation.core.factories.XACMLContextFactory;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.factories.SAMLAssertionFactory;
import org.picketlink.identity.federation.core.saml.v2.holders.IssuerInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.saml.v2.util.JAXBElementMappingUtil;
import org.picketlink.identity.federation.core.saml.v2.util.SOAPSAMLXACMLUtil;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.core.util.JAXBUtil;
import org.picketlink.identity.federation.org.xmlsoap.schemas.soap.envelope.Body;
import org.picketlink.identity.federation.org.xmlsoap.schemas.soap.envelope.Envelope;
import org.picketlink.identity.federation.org.xmlsoap.schemas.soap.envelope.Fault;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.saml.v2.profiles.xacml.assertion.XACMLAuthzDecisionStatementType;
import org.picketlink.identity.federation.saml.v2.profiles.xacml.protocol.XACMLAuthzDecisionQueryType;
import org.picketlink.identity.federation.saml.v2.protocol.RequestAbstractType;
import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.core.JBossRequestContext;
import org.jboss.security.xacml.core.model.context.RequestType;
import org.jboss.security.xacml.core.model.context.ResponseType;
import org.jboss.security.xacml.core.model.context.ResultType;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Servlet that can read SOAP 1.1 messages that contain
 * an XACML query in saml payload
 * @author Anil.Saldhana@redhat.com
 * @since Jan 27, 2009
 */
public class SOAPSAMLXACMLServlet extends HttpServlet
{   
   private static Logger log = Logger.getLogger(SOAPSAMLXACMLServlet.class);
   private boolean trace = log.isTraceEnabled();
   
   private static final long serialVersionUID = 1L;
   
   private String policyConfigFileName = null;
   
   private String issuerId = null;
   private String issuer = null;
   
   boolean debug = false;
   
   private transient PolicyDecisionPoint pdp = null;

   public void init(ServletConfig config) throws ServletException
   {  
      issuerId = config.getInitParameter("issuerID");
      if(issuerId == null)
         issuerId = "issue-id:1";
      
      issuer = config.getInitParameter("issuer"); 
      if(issuer == null)
         issuer = "urn:jboss-identity";
      
      policyConfigFileName = config.getInitParameter("policyConfigFileName");
      if(policyConfigFileName == null)
         policyConfigFileName = "policyConfig.xml"; 
      
      String debugStr = config.getInitParameter("debug");
      try
      {
         debug = Boolean.parseBoolean(debugStr);
      }
      catch(Exception ignore)
      {
         debug = false;
      }
      
      if(trace)
      {
         log.trace("Issuer=" + issuer + " :: issuerID=" + issuerId);
         log.trace("PolicyConfig File:" + policyConfigFileName);
         log.trace("Debug="+debug); 
      }
      
      if(debug)
      {
         SecurityActions.setSystemProperty("jaxb.debug", "true");
      }
      
      try
      {
         pdp = this.getPDP();
      }
      catch (PrivilegedActionException e)
      {
         log("Exception loading PDP::",e);
         throw new ServletException("Unable to load PDP");
      }
      super.init(config);     
   }

   
   @SuppressWarnings("unchecked")
   @Override
   protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
   {
      JAXBElement<RequestAbstractType> jaxbRequestType = null;
      
      Envelope envelope = null;
      XACMLAuthzDecisionQueryType xacmlRequest = null;
      
      try
      {
         Document inputDoc = DocumentUtil.getDocument(req.getInputStream());
         if(debug && trace)
            log.trace("Received SOAP:"+DocumentUtil.asString(inputDoc));
         
         Unmarshaller un = JAXBUtil.getUnmarshaller(SOAPSAMLXACMLUtil.getPackage());
         if(debug)
           un.setEventHandler(new DefaultValidationEventHandler());

         Object unmarshalledObject = un.unmarshal(DocumentUtil.getNodeAsStream(inputDoc));
         
         if(unmarshalledObject instanceof JAXBElement)
         {
            JAXBElement<?> jaxbElement = (JAXBElement<?>) unmarshalledObject;
            Object element = jaxbElement.getValue();
            if(element instanceof Envelope)
            {
               envelope = (Envelope)element; 
               Body soapBody = envelope.getBody(); 
               Object samlRequest = soapBody.getAny().get(0);
               if(samlRequest instanceof JAXBElement)
               {
                  jaxbRequestType = (JAXBElement<RequestAbstractType>)samlRequest; 
                  jaxbRequestType = (JAXBElement<RequestAbstractType>)samlRequest;
                  xacmlRequest = (XACMLAuthzDecisionQueryType) jaxbRequestType.getValue();
               }
               else
                  if(samlRequest instanceof Element)
                  { 
                     Element elem = (Element) samlRequest; 
                     xacmlRequest = SOAPSAMLXACMLUtil.getXACMLQueryType(elem);
                  } 
            }
            else if(element instanceof XACMLAuthzDecisionQueryType)
            {
               xacmlRequest = (XACMLAuthzDecisionQueryType) element;
            }
         }
         if(xacmlRequest == null)
            throw new IOException("XACML Request not parsed"); 

         RequestType requestType = xacmlRequest.getRequest();
         
         RequestContext requestContext = new JBossRequestContext();
         requestContext.setRequest(requestType);
         
         //pdp evaluation is thread safe
         ResponseContext responseContext = pdp.evaluate(requestContext);  
         
         ResponseType responseType = new ResponseType();
         ResultType resultType = responseContext.getResult();
         responseType.getResult().add(resultType);

         XACMLAuthzDecisionStatementType xacmlStatement = 
            XACMLContextFactory.createXACMLAuthzDecisionStatementType(requestType, responseType); 
         
         //Place the xacml statement in an assertion
         //Then the assertion goes inside a SAML Response
         
         String ID = IDGenerator.create("ID_");
         SAML2Response saml2Response = new SAML2Response();
         IssuerInfoHolder issuerInfo = new IssuerInfoHolder(this.issuer);
         
         List<StatementAbstractType> statements = new ArrayList<StatementAbstractType>();
         statements.add(xacmlStatement);
         
         AssertionType assertion = SAMLAssertionFactory.createAssertion(ID, 
               issuerInfo.getIssuer(), 
               XMLTimeUtil.getIssueInstant(), 
               null, 
               null, 
               statements);
    
         JAXBElement<?> jaxbResponse = JAXBElementMappingUtil.get(saml2Response.createResponseType(ID, issuerInfo, assertion));
         
         //Create a SOAP Envelope to hold the SAML response
         envelope = this.createEnvelope(jaxbResponse); 
      }
      catch (JAXBException e)
      {
         String id = IDGenerator.create();
         log.error(id + "::Exception parsing SOAP:", e);  
         envelope = this.createEnvelope(this.createFault("Parsing Error. Reference::" + id));
      } 
      catch (Exception e)
      { 
         String id = IDGenerator.create();
         log.error(id + "::Exception:", e); 
         envelope = this.createEnvelope(this.createFault("Server Error. Reference::" + id));
      } 
      finally
      {
         resp.setContentType("text/xml;charset=utf-8");;
         OutputStream os = resp.getOutputStream(); 
         try
         {
            if(envelope == null)
               throw new IllegalStateException("SOAPEnvelope is null");
            JAXBElement<?> jaxbEnvelope = JAXBElementMappingUtil.get(envelope);
            Marshaller marshaller = JAXBUtil.getMarshaller(SOAPSAMLXACMLUtil.getPackage());
            marshaller.marshal(jaxbEnvelope, os);  
         }
         catch (JAXBException e)
         {
            log("marshalling exception",e);
         }  
      } 
   } 
   
   private PolicyDecisionPoint getPDP() throws PrivilegedActionException
   {
      ClassLoader tcl = SecurityActions.getContextClassLoader();
      InputStream is = tcl.getResourceAsStream(this.policyConfigFileName);
      if(is == null)
         throw new IllegalStateException(policyConfigFileName  + " could not be located");
      return new JBossPDP(is); 
   } 
   
   private Envelope createEnvelope(Object obj)
   {
      Envelope envelope = SOAPFactory.getObjectFactory().createEnvelope();
      Body body = SOAPFactory.getObjectFactory().createBody();
      body.getAny().add(obj); 
      envelope.setBody(body);
      return envelope;
   }
   
   private JAXBElement<Fault> createFault(String msg)
   {
      Fault fault = SOAPFactory.getObjectFactory().createFault();
      fault.setFaultstring(msg);
      return SOAPFactory.getObjectFactory().createFault(fault); 
   }
}