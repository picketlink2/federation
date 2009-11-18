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
package org.jboss.identity.federation.api.soap;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.jboss.identity.federation.core.exceptions.ConfigurationException;
import org.jboss.identity.federation.core.exceptions.ProcessingException;
import org.jboss.identity.federation.core.factories.SOAPFactory;
import org.jboss.identity.federation.core.saml.v2.factories.SAMLAssertionFactory;
import org.jboss.identity.federation.core.saml.v2.util.SOAPSAMLXACMLUtil;
import org.jboss.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.jboss.identity.federation.org.xmlsoap.schemas.soap.envelope.Body;
import org.jboss.identity.federation.org.xmlsoap.schemas.soap.envelope.Envelope;
import org.jboss.identity.federation.org.xmlsoap.schemas.soap.envelope.Fault;
import org.jboss.identity.federation.saml.v2.assertion.AssertionType;
import org.jboss.identity.federation.saml.v2.assertion.NameIDType;
import org.jboss.identity.federation.saml.v2.profiles.xacml.assertion.XACMLAuthzDecisionStatementType;
import org.jboss.identity.federation.saml.v2.profiles.xacml.protocol.XACMLAuthzDecisionQueryType;
import org.jboss.identity.federation.saml.v2.protocol.ResponseType;
import org.jboss.security.xacml.core.model.context.DecisionType;
import org.jboss.security.xacml.core.model.context.RequestType;
import org.jboss.security.xacml.core.model.context.ResultType;

/**
 * Class that deals with sending XACML
 * Request Response bundled in SAML pay load
 * as SOAP Requests
 * @author Anil.Saldhana@redhat.com
 * @since Jul 30, 2009
 */
public class SOAPSAMLXACML
{ 
   /**
    * Given an xacml request
    * @param endpoint
    * @param issuer
    * @param xacmlRequest
    * @return
    * @throws ProcessingException
    */
   public Result send(String endpoint, String issuer, RequestType xacmlRequest) throws ProcessingException
   {
      try
      {
         XACMLAuthzDecisionQueryType queryType = SOAPSAMLXACMLUtil.createXACMLAuthzDecisionQueryType();
         queryType.setRequest(xacmlRequest);
         
         //Create Issue Instant
         queryType.setIssueInstant(XMLTimeUtil.getIssueInstant());
         
         //Create Issuer
         NameIDType nameIDType = SAMLAssertionFactory.getObjectFactory().createNameIDType();
         nameIDType.setValue(issuer);
         queryType.setIssuer(nameIDType);
         
         JAXBElement<?> jaxbQueryType = SOAPSAMLXACMLUtil.getJAXB(queryType);
         
         Envelope envelope = createEnvelope(jaxbQueryType);
         
         JAXBElement<?> soapRequest = SOAPFactory.getObjectFactory().createEnvelope(envelope);
         
         Marshaller marshaller = SOAPSAMLXACMLUtil.getMarshaller();
         Unmarshaller unmarshaller = SOAPSAMLXACMLUtil.getUnmarshaller();
         
         //Send it across the wire
         URL url = new URL(endpoint);
         URLConnection conn = url.openConnection();
         conn.setDoOutput(true); 
         marshaller.marshal(soapRequest, conn.getOutputStream());
         
         JAXBElement<?> result = (JAXBElement<?>) unmarshaller.unmarshal(conn.getInputStream()); 
         Envelope resultEnvelope = (Envelope) result.getValue();
         
         JAXBElement<?> samlResponse = (JAXBElement<?>) resultEnvelope.getBody().getAny().get(0);
         Object response = samlResponse.getValue();
         if(response instanceof Fault)
         {
            Fault fault = (Fault) response;
            return new Result(null,fault); 
         }
         
         ResponseType responseType = (ResponseType) response;
         AssertionType at = (AssertionType) responseType.getAssertionOrEncryptedAssertion().get(0);
         XACMLAuthzDecisionStatementType xst = (XACMLAuthzDecisionStatementType) at.getStatementOrAuthnStatementOrAuthzDecisionStatement().get(0);
         ResultType rt = xst.getResponse().getResult().get(0);
         DecisionType dt = rt.getDecision(); 
         
         return new Result(dt,null);
      }
      catch (JAXBException e)
      {
         throw new ProcessingException(e); 
      }
      catch (IOException e)
      {
         throw new ProcessingException(e);
      }
      catch (ConfigurationException e)
      {
         throw new ProcessingException(e);
      } 
   }
   
   private Envelope createEnvelope(JAXBElement<?> jaxbElement)
   {
      Envelope envelope = SOAPFactory.getObjectFactory().createEnvelope();
      Body body = SOAPFactory.getObjectFactory().createBody();
      body.getAny().add(jaxbElement); 
      envelope.setBody(body);
      return envelope;
   } 
   
   public static class Result
   {
      private Fault fault = null; 
      private DecisionType decisionType;
      
      Result(DecisionType decision, Fault fault)
      {
         this.decisionType = decision;
         this.fault = fault;
      }
      
      public boolean isResponseAvailable()
      {
         return decisionType != null;
      }
      
      public boolean isFault()
      {
         return fault != null;
      }
      
      public DecisionType getDecision()
      {
         return decisionType;
      }
      
      public Fault getFault()
      {
         return fault;
      }
      
      public boolean isPermit()
      {
         return decisionType == DecisionType.PERMIT;
      }
      
      public boolean isDeny()
      {
         return decisionType == DecisionType.DENY;
      }
   }
}