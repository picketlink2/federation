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
package org.picketlink.identity.federation.core.parsers.saml;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.parsers.ParserNamespaceSupport;
import org.picketlink.identity.federation.core.parsers.util.StaxParserUtil;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusCodeType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusType;

/**
 * Parse the SAML Response
 * @author Anil.Saldhana@redhat.com
 * @since Nov 2, 2010
 */
public class SAMLResponseParser implements ParserNamespaceSupport
{ 
   private String RESPONSE = JBossSAMLConstants.RESPONSE.get();
   /**
    * @see {@link ParserNamespaceSupport#parse(XMLEventReader)}
    */
   public Object parse(XMLEventReader xmlEventReader) throws ParsingException
   { 
      //Get the startelement
      StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
      StaxParserUtil.validate(startElement, RESPONSE );
      
      ResponseType response = parseBaseAttributes(startElement); 
      
      while( xmlEventReader.hasNext() )
      {
         //Let us peek at the next start element
         startElement = StaxParserUtil.peekNextStartElement( xmlEventReader );
         if( startElement == null )
            break;
         String elementName = StaxParserUtil.getStartElementName( startElement );
         
         if( JBossSAMLConstants.ISSUER.get().equals( elementName ))
         {
            startElement = StaxParserUtil.getNextStartElement( xmlEventReader );
            NameIDType issuer = new NameIDType();
            issuer.setValue( StaxParserUtil.getElementText( xmlEventReader ));
            response.setIssuer( issuer );
         }
         else if( JBossSAMLConstants.SIGNATURE.get().equals( elementName ))
         {
            startElement = StaxParserUtil.getNextStartElement( xmlEventReader );
            StaxParserUtil.bypassElementBlock(xmlEventReader, JBossSAMLConstants.SIGNATURE.get() );
         }
         else if( JBossSAMLConstants.ASSERTION.get().equals( elementName ))
         {
            SAMLAssertionParser assertionParser = new SAMLAssertionParser(); 
            response.getAssertionOrEncryptedAssertion().add( assertionParser.parse(xmlEventReader));
         }
         else if( JBossSAMLConstants.STATUS.get().equals( elementName ))
         {
            response.setStatus( parseStatus(xmlEventReader) ); 
         }
      }
      
      return response;
   }

   /**
    * @see {@link ParserNamespaceSupport#supports(QName)}
    */ 
   public boolean supports(QName qname)
   {
      return JBossSAMLURIConstants.PROTOCOL_NSURI.get().equals( qname.getNamespaceURI() )
             && RESPONSE.equals( qname.getLocalPart() );
   }
   
   /**
    * Parse the attributes at the response element
    * @param startElement
    * @return
    * @throws ConfigurationException
    */
   private ResponseType parseBaseAttributes( StartElement startElement ) throws ParsingException
   { 
      ResponseType response = new ResponseType();
      //Let us get the attributes
      Attribute idAttr = startElement.getAttributeByName( new QName( "ID" ));
      if( idAttr == null )
         throw new RuntimeException( "ID attribute is missing" );
      response.setID( StaxParserUtil.getAttributeValue( idAttr ));
      
      Attribute inResponseTo = startElement.getAttributeByName( new QName( "InResponseTo" ));
      if( inResponseTo != null )
         response.setInResponseTo( StaxParserUtil.getAttributeValue( inResponseTo ));
      
      Attribute destination = startElement.getAttributeByName( new QName( "Destination" ));
      if( destination != null )
         response.setDestination( StaxParserUtil.getAttributeValue( destination ));
      
      Attribute issueInstant = startElement.getAttributeByName( new QName( "IssueInstant" ));
      if( issueInstant != null )
      {
         response.setIssueInstant( XMLTimeUtil.parse( StaxParserUtil.getAttributeValue( issueInstant ))); 
      }
      
      Attribute version = startElement.getAttributeByName( new QName( "Version" ));
      if( version != null )
         response.setVersion( StaxParserUtil.getAttributeValue( version ));
      return response; 
   } 
   
   /**
    * Parse the status element
    * @param xmlEventReader
    * @return
    * @throws ParsingException
    */
   private StatusType parseStatus( XMLEventReader xmlEventReader ) throws ParsingException
   {
      //Get the Start Element
      StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
      String STATUS = JBossSAMLConstants.STATUS.get();
      StaxParserUtil.validate(startElement, STATUS );
      
      StatusType status = new StatusType();
      
      while( xmlEventReader.hasNext() )
      {
         startElement = StaxParserUtil.peekNextStartElement(xmlEventReader);
         QName startElementName = startElement.getName(); 
         String elementTag = startElementName.getLocalPart();

         StatusCodeType statusCode = new StatusCodeType();
         
         if( JBossSAMLConstants.STATUS_CODE.get().equals( elementTag ))
         {
            startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
            Attribute valueAttr = startElement.getAttributeByName( new QName( "Value" ));
            if( valueAttr != null )
            {
               statusCode.setValue( StaxParserUtil.getAttributeValue( valueAttr )); 
            } 
            //Get the next end element
            StaxParserUtil.getNextEndElement(xmlEventReader);
         }

         status.setStatusCode( statusCode );
         
         //Get the next end element
         XMLEvent xmlEvent = StaxParserUtil.peek(xmlEventReader);
         if( xmlEvent instanceof EndElement )
         {
            EndElement endElement = StaxParserUtil.getNextEndElement(xmlEventReader);
            if( StaxParserUtil.matches(endElement, STATUS ))
               break;
         }
      } 
      return status;
   } 
}