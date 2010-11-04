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
package org.picketlink.identity.federation.core.parsers.util;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;

import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.saml.v2.factories.SAMLAssertionFactory;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnContextType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;

/**
 * Utility methods for SAML Parser
 * @author Anil.Saldhana@redhat.com
 * @since Nov 4, 2010
 */
public class SAMLParserUtil
{
   /**
    * Parse an {@code AttributeStatementType}
    * @param xmlEventReader
    * @return
    * @throws ParsingException
    */
   public static AttributeStatementType parseAttributeStatement( XMLEventReader xmlEventReader ) throws ParsingException
   {
      AttributeStatementType attributeStatementType = new AttributeStatementType();
      
      StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
      String AUTHNSTATEMENT = JBossSAMLConstants.ATTRIBUTE_STATEMENT.get();
      StaxParserUtil.validate( startElement, AUTHNSTATEMENT );
      
      while( xmlEventReader.hasNext() )
      {
         //Get the next start element
         startElement = StaxParserUtil.peekNextStartElement( xmlEventReader );
         String tag = startElement.getName().getLocalPart();
         if( JBossSAMLConstants.ATTRIBUTE.get().equals( tag ) )
         {
            AttributeType attribute = parseAttribute(xmlEventReader);
            attributeStatementType.getAttributeOrEncryptedAttribute().add( attribute );
         }
         else throw new RuntimeException( "Unknown tag:" + tag );
      } 
      return attributeStatementType;
   }
   
   /**
    * Parse an {@code AttributeType}
    * @param xmlEventReader
    * @return
    * @throws ParsingException
    */
   public static AttributeType parseAttribute( XMLEventReader xmlEventReader ) throws ParsingException
   {
      AttributeType attributeType = new AttributeType();

      StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader); 
      StaxParserUtil.validate( startElement, JBossSAMLConstants.ATTRIBUTE.get() );
      
      Attribute name = startElement.getAttributeByName( new QName( JBossSAMLConstants.NAME.get() ));
      if( name == null )
         throw new RuntimeException( "Required attribute Name in Attribute" );
      attributeType.setName( StaxParserUtil.getAttributeValue( name ));

      Attribute friendlyName = startElement.getAttributeByName( new QName( JBossSAMLConstants.FRIENDLY_NAME.get() ));
      if( friendlyName != null ) 
         attributeType.setFriendlyName( StaxParserUtil.getAttributeValue( friendlyName ));
      
      Attribute nameFormat = startElement.getAttributeByName( new QName( JBossSAMLConstants.NAME_FORMAT.get() ));
      if( nameFormat != null ) 
         attributeType.setNameFormat( StaxParserUtil.getAttributeValue( nameFormat ));
      
      while( xmlEventReader.hasNext() )
      {
         startElement = StaxParserUtil.peekNextStartElement(xmlEventReader);
         if( startElement == null )
            break;
         String tag = StaxParserUtil.getStartElementName(startElement);
         
         if( JBossSAMLConstants.ATTRIBUTE.get().equals( tag ))
            break;
         
         if( JBossSAMLConstants.ATTRIBUTE_VALUE.get().equals( tag ) )
         {
            Object attributeValue = parseAttributeValue(xmlEventReader);
            attributeType.getAttributeValue().add( attributeValue ); 
         }
         else throw new RuntimeException( "Unknown tag:" + tag );
      }
      
      return attributeType; 
   }
   
   /**
    * Parse Attribute value
    * @param xmlEventReader
    * @return
    * @throws ParsingException
    */
   public static Object parseAttributeValue( XMLEventReader xmlEventReader ) throws ParsingException
   {
      StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
      StaxParserUtil.validate( startElement, JBossSAMLConstants.ATTRIBUTE_VALUE.get() );
      
      Attribute type = startElement.getAttributeByName( new QName( JBossSAMLURIConstants.XSI_NSURI.get(),
            "type", "xsi"));
      if( type == null )
         throw new RuntimeException( "attribute value has no xsi type" );
      
      String typeValue  = StaxParserUtil.getAttributeValue(type);
      if( typeValue.contains( ":string" ))
      {
         return StaxParserUtil.getElementText(xmlEventReader);
      }
      
      throw new RuntimeException( "Unsupported xsi:type=" + typeValue );
   }
   
   /**
    * Parse the AuthnStatement inside the assertion
    * @param xmlEventReader
    * @return
    * @throws ParsingException
    */
   public static AuthnStatementType parseAuthnStatement( XMLEventReader xmlEventReader ) throws ParsingException
   {
      AuthnStatementType authnStatementType = new AuthnStatementType();
      
      StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
      String AUTHNSTATEMENT = JBossSAMLConstants.AUTHN_STATEMENT.get();
      StaxParserUtil.validate( startElement, AUTHNSTATEMENT );
      
      Attribute authnInstant = startElement.getAttributeByName( new QName( "AuthnInstant" ));
      if( authnInstant == null )
         throw new RuntimeException( "Required attribute AuthnInstant in " + AUTHNSTATEMENT );
      authnStatementType.setAuthnInstant( XMLTimeUtil.parse( StaxParserUtil.getAttributeValue( authnInstant )));
      
      Attribute sessionIndex = startElement.getAttributeByName( new QName( "SessionIndex" ));
      if( sessionIndex != null )
         authnStatementType.setSessionIndex( StaxParserUtil.getAttributeValue( sessionIndex ));
      
      //Get the next start element
      startElement = StaxParserUtil.peekNextStartElement( xmlEventReader );
      String tag = startElement.getName().getLocalPart();
      if( JBossSAMLConstants.AUTHN_CONTEXT.get().equals( tag ) )
      {
         authnStatementType.setAuthnContext( parseAuthnContextType( xmlEventReader ) );
      }
      else throw new RuntimeException( "Unknown tag:" + tag );
      
      EndElement endElement = StaxParserUtil.getNextEndElement(xmlEventReader);
      StaxParserUtil.validate(endElement, AUTHNSTATEMENT );
      
      return authnStatementType;
   }
   
   /**
    * Parse the AuthnContext Type inside the AuthnStatement
    * @param xmlEventReader
    * @return
    * @throws ParsingException 
    */
   public static AuthnContextType parseAuthnContextType( XMLEventReader xmlEventReader ) throws ParsingException 
   {
      AuthnContextType authnContextType = new AuthnContextType();
      
      StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
      StaxParserUtil.validate( startElement, JBossSAMLConstants.AUTHN_CONTEXT.get() );
      
      //Get the next start element
      startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
      String tag = startElement.getName().getLocalPart();
      
      if( JBossSAMLConstants.AUTHN_CONTEXT_DECLARATION_REF.get().equals( tag ))
      {
         String text = StaxParserUtil.getElementText( xmlEventReader );
         
         JAXBElement<?> acDeclRef = SAMLAssertionFactory.getObjectFactory().createAuthnContextDeclRef( text );
         authnContextType.getContent().add(acDeclRef);
         EndElement endElement = StaxParserUtil.getNextEndElement(xmlEventReader);
         StaxParserUtil.validate(endElement, JBossSAMLConstants.AUTHN_CONTEXT.get() );
      }
      else
         throw new RuntimeException( "Unknown Tag:" + tag );
      
      return authnContextType;
   } 
   
   /**
    * Parse a {@code NameIDType}
    * @param xmlEventReader
    * @return
    * @throws ParsingException
    */
   public static NameIDType parseNameIDType( XMLEventReader xmlEventReader ) throws ParsingException
   {
      StartElement nameIDElement = StaxParserUtil.getNextStartElement( xmlEventReader ); 
      NameIDType nameID = new NameIDType();
      
      Attribute nameQualifier = nameIDElement.getAttributeByName( new QName( JBossSAMLConstants.NAME_QUALIFIER.get() ));       
      if( nameQualifier != null )
      {
         nameID.setNameQualifier( StaxParserUtil.getAttributeValue(nameQualifier) ); 
      }  
      
      Attribute format = nameIDElement.getAttributeByName( new QName( JBossSAMLConstants.FORMAT.get() ));
      if( format != null )
      {
         nameID.setFormat( StaxParserUtil.getAttributeValue( format ));
      }
      
      Attribute spProvidedID = nameIDElement.getAttributeByName( new QName( JBossSAMLConstants.SP_PROVIDED_ID.get() ));
      if( spProvidedID != null )
      {
         nameID.setSPProvidedID( StaxParserUtil.getAttributeValue( spProvidedID ));
      }
      
      Attribute spNameQualifier = nameIDElement.getAttributeByName( new QName( JBossSAMLConstants.SP_NAME_QUALIFIER.get() ));
      if( spNameQualifier != null )
      {
         nameID.setSPNameQualifier( StaxParserUtil.getAttributeValue( spNameQualifier ));
      }

      String nameIDValue = StaxParserUtil.getElementText( xmlEventReader );
      nameID.setValue( nameIDValue ); 
      
      return nameID;
   }
}