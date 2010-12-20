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

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Set;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPMessage;
import javax.xml.stream.XMLEventReader;

import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.parsers.saml.xacml.SAMLXACMLRequestParser;
import org.picketlink.identity.federation.core.parsers.util.StaxParserUtil;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.newmodel.saml.v2.profiles.xacml.assertion.XACMLAuthzDecisionStatementType;
import org.picketlink.identity.federation.newmodel.saml.v2.profiles.xacml.protocol.XACMLAuthzDecisionQueryType;
import org.picketlink.identity.federation.newmodel.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.newmodel.saml.v2.protocol.ResponseType.RTChoiceType;
import org.w3c.dom.Node;

/**
 * Utility associated with SOAP 1.1 Envelope,
 * SAML2 and XACML2
 * @author Anil.Saldhana@redhat.com
 * @since Jan 28, 2009
 */
public class SOAPSAMLXACMLUtil
{     
   /**
    * Parse the XACML Authorization Decision Query from the Dom Element
    * @param samlRequest
    * @return 
    * @throws ProcessingException 
    * @throws ConfigurationException  
    * @throws ParsingException
    */
   public static XACMLAuthzDecisionQueryType getXACMLQueryType( Node samlRequest ) 
   throws ParsingException, ConfigurationException, ProcessingException 
   {
      //We reparse it because the document may have issues with namespaces
      //String elementString = DocumentUtil.getDOMElementAsString(samlRequest);
      
      XMLEventReader xmlEventReader = StaxParserUtil.getXMLEventReader( DocumentUtil.getNodeAsStream( samlRequest ));
      SAMLXACMLRequestParser samlXACMLRequestParser = new SAMLXACMLRequestParser();
      return (XACMLAuthzDecisionQueryType) samlXACMLRequestParser.parse(xmlEventReader);
      
      /*Unmarshaller um = JAXBUtil.getUnmarshaller(collectivePackage);
      um.setEventHandler(new javax.xml.bind.helpers.DefaultValidationEventHandler());

      JAXBElement<?> obj = (JAXBElement<?>) um.unmarshal(new StringReader(elementString));
      Object xacmlObject = obj.getValue();
      if(xacmlObject instanceof XACMLAuthzDecisionQueryType == false)
         throw new RuntimeException("Unsupported type:" + xacmlObject);
      return (XACMLAuthzDecisionQueryType)xacmlObject;  */
   }
   
   public static XACMLAuthzDecisionStatementType getDecisionStatement( Node samlResponse ) throws ConfigurationException, ProcessingException, ParsingException
   {
      XMLEventReader xmlEventReader = StaxParserUtil.getXMLEventReader( DocumentUtil.getNodeAsStream( samlResponse ));
      SAMLParser samlParser = new SAMLParser();
      ResponseType response = (ResponseType) samlParser.parse( xmlEventReader );
      List<RTChoiceType> choices = response.getAssertions();
      for( RTChoiceType rst: choices )
      {
         AssertionType assertion = rst.getAssertion();
         if( assertion == null )
            continue;
         Set<StatementAbstractType> stats = assertion.getStatements();
         for( StatementAbstractType stat: stats )
         {
            if( stat instanceof XACMLAuthzDecisionStatementType )
            {
               return (XACMLAuthzDecisionStatementType) stat;
            }
         }
      }
      
      throw new RuntimeException( "Not found XACMLAuthzDecisionStatementType" ); 
   }
   
   public static SOAPMessage getSOAPMessage( InputStream is ) throws IOException, SOAPException
   {
      MessageFactory messageFactory = MessageFactory.newInstance();
      return messageFactory.createMessage(null, is ); 
   }
   
   public static SOAPMessage createFault( String message ) throws SOAPException 
   {
      MessageFactory messageFactory = MessageFactory.newInstance();
      SOAPMessage msg =  messageFactory.createMessage() ;
      SOAPEnvelope envelope = msg.getSOAPPart().getEnvelope();
      SOAPBody body = envelope.getBody();
      SOAPFault fault = body.addFault();
      fault.setFaultCode("Server");
      fault.setFaultActor( "urn:picketlink" );
      fault.setFaultString( message );
      return msg; 
   }
}