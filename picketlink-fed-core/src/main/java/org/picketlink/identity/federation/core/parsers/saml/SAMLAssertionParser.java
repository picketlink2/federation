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

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.parsers.ParserNamespaceSupport;
import org.picketlink.identity.federation.core.parsers.util.StaxParserUtil;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.saml.v2.factories.SAMLAssertionFactory;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnContextType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnStatementType;
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
   private String ASSERTION = JBossSAMLConstants.ASSERTION.get();
   
   /**
    * @see {@link ParserNamespaceSupport#parse(XMLEventReader)}
    */
   public Object parse(XMLEventReader xmlEventReader) throws ParsingException
   {  
      StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
      StaxParserUtil.matches(startElement, ASSERTION );
      AssertionType assertion = parseBaseAttributes( startElement ); 

      //Peek at the next event
      while( xmlEventReader.hasNext() )
      {   
         XMLEvent xmlEvent = StaxParserUtil.peek( xmlEventReader );
         if( xmlEvent == null )
            break;
         
         if( xmlEvent instanceof EndElement )
         {
            xmlEvent = StaxParserUtil.getNextEvent( xmlEventReader );
            EndElement endElement = (EndElement) xmlEvent;
            String endElementTag = StaxParserUtil.getEndElementName( endElement );
            if( endElementTag.equals( JBossSAMLConstants.ASSERTION.get() ) )
               break;
         }
         
         StartElement peekedElement = null;

         if( xmlEvent instanceof StartElement )
         {
            peekedElement = (StartElement) xmlEvent;
         }
         else
         {
            peekedElement = StaxParserUtil.peekNextStartElement( xmlEventReader  ); 
         }
         if( peekedElement == null )
            break; 

         String tag = StaxParserUtil.getStartElementName( peekedElement );

         /*if( tag.equals( JBossSAMLConstants.ASSERTION.get() ))
         {
            StartElement nextElement = StaxParserUtil.getNextStartElement(xmlEventReader);
            Attribute idAttribute = nextElement.getAttributeByName( new QName( JBossSAMLConstants.ID.get() ) );
            assertion.setID( StaxParserUtil.getAttributeValue( idAttribute ));

            Attribute versionAttribute = nextElement.getAttributeByName( new QName( JBossSAMLConstants.VERSION.get() ));
            assertion.setVersion( StaxParserUtil.getAttributeValue(versionAttribute) );

            Attribute issueInstantAttribute = nextElement.getAttributeByName( new QName( JBossSAMLConstants.ISSUE_INSTANT.get() ));
            if( issueInstantAttribute != null )
            {
               assertion.setIssueInstant( XMLTimeUtil.parse( StaxParserUtil.getAttributeValue(issueInstantAttribute )));
            } 
            continue;
         }*/

         if( tag.equals( JBossSAMLConstants.SIGNATURE.get() ) )
         {
            StaxParserUtil.bypassElementBlock(xmlEventReader, JBossSAMLConstants.SIGNATURE.get() );
            continue; 
         }

         if( JBossSAMLConstants.ISSUER.get().equalsIgnoreCase( tag ) )
         {
            startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
            String issuerValue = StaxParserUtil.getElementText(xmlEventReader);
            NameIDType issuer = new NameIDType();
            issuer.setValue( issuerValue );

            assertion.setIssuer( issuer ); 
         }  
         else if( JBossSAMLConstants.SUBJECT.get().equalsIgnoreCase( tag ) )
         {
            SAMLSubjectParser subjectParser = new SAMLSubjectParser();
            assertion.setSubject( (SubjectType) subjectParser.parse(xmlEventReader));  
         }
         else if( JBossSAMLConstants.CONDITIONS.get().equalsIgnoreCase( tag ) )
         {
            SAMLConditionsParser conditionsParser = new SAMLConditionsParser();
            ConditionsType conditions = (ConditionsType) conditionsParser.parse(xmlEventReader); 

            assertion.setConditions( conditions ); 
         } 
         else if( JBossSAMLConstants.AUTHN_STATEMENT.get().equalsIgnoreCase( tag ) )
         {
            AuthnStatementType authnStatementType = parseAuthnStatement( xmlEventReader );
            assertion.getStatementOrAuthnStatementOrAuthzDecisionStatement().add( authnStatementType ); 
         }
      }
      return assertion;
   }
   
   /**
    * @see {@link ParserNamespaceSupport#supports(QName)}
    */
   public boolean supports(QName qname)
   { 
      String nsURI = qname.getNamespaceURI();
      String localPart = qname.getLocalPart();
      
      return nsURI.equals( JBossSAMLURIConstants.ASSERTION_NSURI.get() ) 
           && localPart.equals( JBossSAMLConstants.ASSERTION.get() );
   }  
   
   private AssertionType parseBaseAttributes( StartElement nextElement ) throws ParsingException
   { 
      AssertionType assertion = new AssertionType(); 
      Attribute idAttribute = nextElement.getAttributeByName( new QName( JBossSAMLConstants.ID.get() ) );
      assertion.setID( StaxParserUtil.getAttributeValue( idAttribute ));

      Attribute versionAttribute = nextElement.getAttributeByName( new QName( JBossSAMLConstants.VERSION.get() ));
      assertion.setVersion( StaxParserUtil.getAttributeValue(versionAttribute) );

      Attribute issueInstantAttribute = nextElement.getAttributeByName( new QName( JBossSAMLConstants.ISSUE_INSTANT.get() ));
      if( issueInstantAttribute != null )
      {
         assertion.setIssueInstant( XMLTimeUtil.parse( StaxParserUtil.getAttributeValue(issueInstantAttribute )));
      } 
      
      return assertion;
   }
   
   /**
    * Parse the AuthnStatement inside the assertion
    * @param xmlEventReader
    * @return
    * @throws ParsingException
    */
   private AuthnStatementType parseAuthnStatement( XMLEventReader xmlEventReader ) throws ParsingException
   {
      AuthnStatementType authnStatementType = new AuthnStatementType();
      
      StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
      String AUTHNSTATEMENT = JBossSAMLConstants.AUTHN_STATEMENT.get();
      StaxParserUtil.matches( startElement, AUTHNSTATEMENT );
      
      Attribute authnInstant = startElement.getAttributeByName( new QName( "AuthnInstant" ));
      authnStatementType.setAuthnInstant( XMLTimeUtil.parse( StaxParserUtil.getAttributeValue( authnInstant )));
      
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
   private AuthnContextType parseAuthnContextType( XMLEventReader xmlEventReader ) throws ParsingException 
   {
      AuthnContextType authnContextType = new AuthnContextType();
      
      StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
      StaxParserUtil.matches( startElement, JBossSAMLConstants.AUTHN_CONTEXT.get() );
      
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
}