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

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;

import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.parsers.ParserNamespaceSupport;
import org.picketlink.identity.federation.core.parsers.util.StaxParserUtil;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionsType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;

/**
 * Parse the saml assertion
 * @author Anil.Saldhana@redhat.com
 * @since Oct 12, 2010
 */
public class SAMLAssertionParser implements ParserNamespaceSupport
{
   public static final String LOCALPART = "Assertion"; 

   public Object parse(XMLEventReader xmlEventReader) throws ParsingException
   {
      try
      {
         xmlEventReader.nextEvent();
      }
      catch (XMLStreamException e)
      {
         throw new ParsingException( e );
      }
      
      AssertionType assertion = new AssertionType(); 
      
      //Peek at the next event
      while( xmlEventReader.hasNext() )
      { 
         StartElement peekedElement = StaxParserUtil.peekNextStartElement( xmlEventReader  );
            if( peekedElement == null )
               break; 
            
         String tag = StaxParserUtil.getStartElementName( peekedElement );
         
         if( JBossSAMLConstants.ISSUER.get().equalsIgnoreCase( tag ) )
         {
            try
            {
               StaxParserUtil.getNextStartElement( xmlEventReader );
               String issuerValue = xmlEventReader.getElementText();
               
               NameIDType issuer = new NameIDType();
               issuer.setValue( issuerValue );
               
               assertion.setIssuer( issuer );
            }
            catch (XMLStreamException e)
            {
              throw new ParsingException( e );
            } 
         }  
         else if( JBossSAMLConstants.SUBJECT.get().equalsIgnoreCase( tag ) )
         {
             SAMLSubjectParser subjectParser = new SAMLSubjectParser();
             assertion.setSubject( (SubjectType) subjectParser.parse(xmlEventReader));  
         }
         else if( JBossSAMLConstants.CONDITIONS.get().equalsIgnoreCase( tag ) )
         {
            try
            {
               QName notBeforeQName = new QName( "", JBossSAMLConstants.NOT_BEFORE.get() );
               QName notBeforeQNameWithNS = new QName( JBossSAMLURIConstants.ASSERTION_NSURI.get(), JBossSAMLConstants.NOT_BEFORE.get() );
               
               QName notAfterQName = new QName( "", JBossSAMLConstants.NOT_ON_OR_AFTER.get() );
               QName notAfterQNameWithNS = new QName( JBossSAMLURIConstants.ASSERTION_NSURI.get(), JBossSAMLConstants.NOT_ON_OR_AFTER.get() );
               
               StartElement conditionsElement = StaxParserUtil.getNextStartElement( xmlEventReader );
               
               Attribute notBeforeAttribute = conditionsElement.getAttributeByName( notBeforeQName );
               if( notBeforeAttribute == null )
                  notBeforeAttribute = conditionsElement.getAttributeByName( notBeforeQNameWithNS );
               
               Attribute notAfterAttribute = conditionsElement.getAttributeByName( notAfterQName );
               if( notAfterAttribute == null )
                  notAfterAttribute = conditionsElement.getAttributeByName( notAfterQNameWithNS );
               
               
               ConditionsType conditions = new ConditionsType();
               
               if( notBeforeAttribute != null )
               {
                  String notBeforeValue = StaxParserUtil.getAttributeValue( notBeforeAttribute );
                  
                  DatatypeFactory dtf = DatatypeFactory.newInstance();
                  XMLGregorianCalendar xmlcal = dtf.newXMLGregorianCalendar( notBeforeValue );
                  conditions.setNotBefore( xmlcal );
               }
               
               if( notAfterAttribute != null )
               {
                  String notAfterValue = StaxParserUtil.getAttributeValue( notAfterAttribute );
                  
                  DatatypeFactory dtf = DatatypeFactory.newInstance();
                  XMLGregorianCalendar xmlcal = dtf.newXMLGregorianCalendar( notAfterValue );
                  conditions.setNotOnOrAfter( xmlcal );
               }
               
               assertion.setConditions( conditions );
            } 
            catch (DatatypeConfigurationException e)
            {
               throw new ParsingException( e );
            }   
         }
         else
         {
            try
            {
               xmlEventReader.nextEvent();
            }
            catch (XMLStreamException e)
            {
               throw new ParsingException( e );
            }
         } 
      }
      return assertion;
   }

   public boolean supports(QName qname)
   { 
      return false;
   } 
}