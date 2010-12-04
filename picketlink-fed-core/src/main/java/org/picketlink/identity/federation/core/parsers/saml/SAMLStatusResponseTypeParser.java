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

import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.parsers.util.StaxParserUtil;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.core.util.NetworkUtil;
import org.picketlink.identity.federation.newmodel.saml.v2.protocol.StatusCodeType;
import org.picketlink.identity.federation.newmodel.saml.v2.protocol.StatusResponseType;
import org.picketlink.identity.federation.newmodel.saml.v2.protocol.StatusType;

/**
 * Base Class for all Response Type parsing for SAML2
 * @author Anil.Saldhana@redhat.com
 * @since Nov 2, 2010
 */
public abstract class SAMLStatusResponseTypeParser
{
   /**
    * Parse the attributes that are common to all SAML Response Types
    * @param startElement
    * @param response
    * @throws ParsingException
    */
   protected void parseBaseAttributes(  StartElement startElement , StatusResponseType response ) throws ParsingException
   {
      Attribute idAttr = startElement.getAttributeByName( new QName( "ID" ));
      if( idAttr == null )
         throw new RuntimeException( "ID attribute is missing" );
      response.setID( StaxParserUtil.getAttributeValue( idAttr )); 
      
      Attribute version = startElement.getAttributeByName( new QName( "Version" ));
      if( version == null )
         throw new RuntimeException( "Version attribute required in Response" );
      response.setVersion( StaxParserUtil.getAttributeValue( version ));
      
      Attribute issueInstant = startElement.getAttributeByName( new QName( "IssueInstant" ));
      if( issueInstant == null )
         throw new RuntimeException( "IssueInstant attribute required in Response" ); 
      response.setIssueInstant( XMLTimeUtil.parse( StaxParserUtil.getAttributeValue( issueInstant ))); 
      
      Attribute destination = startElement.getAttributeByName( new QName( "Destination" ));
      if( destination != null )
         response.setDestination( StaxParserUtil.getAttributeValue( destination ));
      
      Attribute consent = startElement.getAttributeByName( new QName( "Consent" ));
      if( consent != null )
         response.setConsent( StaxParserUtil.getAttributeValue( consent ));  
      
      Attribute inResponseTo = startElement.getAttributeByName( new QName( "InResponseTo" ));
      if( inResponseTo != null )
         response.setInResponseTo( StaxParserUtil.getAttributeValue( inResponseTo ));
   }
   
    /**
    * Parse the status element
    * @param xmlEventReader
    * @return
    * @throws ParsingException
    */
   protected StatusType parseStatus( XMLEventReader xmlEventReader ) throws ParsingException
   {
      //Get the Start Element
      StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
      String STATUS = JBossSAMLConstants.STATUS.get();
      StaxParserUtil.validate(startElement, STATUS );
      
      StatusType status = new StatusType();
      
      while( xmlEventReader.hasNext() )
      {
         startElement = StaxParserUtil.peekNextStartElement(xmlEventReader);

         if( startElement == null )
            break;
         
         QName startElementName = startElement.getName(); 
         String elementTag = startElementName.getLocalPart();

         StatusCodeType statusCode = new StatusCodeType();
         
         if( JBossSAMLConstants.STATUS_CODE.get().equals( elementTag ))
         {
            startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
            if( startElement == null )
               break;
            Attribute valueAttr = startElement.getAttributeByName( new QName( "Value" ));
            if( valueAttr != null )
            {
               statusCode.setValue( NetworkUtil.createURI( StaxParserUtil.getAttributeValue( valueAttr ) )); 
            }
            status.setStatusCode( statusCode );
            
            //Peek at the next start element to see if it is status code
            startElement = StaxParserUtil.peekNextStartElement( xmlEventReader );
            if( JBossSAMLConstants.STATUS_CODE.get().equals( startElement.getName().getLocalPart() ))
            {
               StatusCodeType subStatusCodeType = new StatusCodeType();
               startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
               Attribute subValueAttr = startElement.getAttributeByName( new QName( "Value" ));
               if( subValueAttr != null )
               {
                  subStatusCodeType.setValue( NetworkUtil.createURI( StaxParserUtil.getAttributeValue( subValueAttr ))); 
               } 
               statusCode.setStatusCode( subStatusCodeType );
               
               // Go to Status code end element.
               EndElement endElement = StaxParserUtil.getNextEndElement(xmlEventReader);
               StaxParserUtil.validate(endElement, JBossSAMLConstants.STATUS_CODE.get());
               continue;
            }
            else
               break;
         } 
         
         //Get the next end element
         XMLEvent xmlEvent = StaxParserUtil.peek(xmlEventReader);
         if( xmlEvent instanceof EndElement )
         {
            EndElement endElement = StaxParserUtil.getNextEndElement(xmlEventReader);
            if( StaxParserUtil.matches(endElement, STATUS ))
               break;
            else
               throw new RuntimeException( "unknown end element:" + StaxParserUtil.getEndElementName( endElement ));
         }
      } 
      return status;
   }  
}