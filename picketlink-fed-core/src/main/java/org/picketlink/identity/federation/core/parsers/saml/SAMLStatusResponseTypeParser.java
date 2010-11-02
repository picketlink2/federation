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
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;

import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.parsers.util.StaxParserUtil;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.saml.v2.protocol.StatusResponseType;

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

}