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
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.ObjectFactory;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;

/**
 * Parse the saml subject
 * @author Anil.Saldhana@redhat.com
 * @since Oct 12, 2010
 */
public class SAMLSubjectParser implements ParserNamespaceSupport
{
   private ObjectFactory objectFactory = new ObjectFactory();

   /**
    * @see {@link ParserNamespaceSupport#parse(XMLEventReader)}
    */
   public Object parse(XMLEventReader xmlEventReader) throws ParsingException
   { 
      StaxParserUtil.getNextEvent(xmlEventReader); 
      
      SubjectType subject = new SubjectType(); 
      
      //Peek at the next event
      while( xmlEventReader.hasNext() )
      { 
         XMLEvent xmlEvent = StaxParserUtil.peek(xmlEventReader);
         if( xmlEvent instanceof EndElement )
         {
            EndElement endElement = (EndElement) xmlEvent;
            String endElementValue = StaxParserUtil.getEndElementName(endElement);
            if( endElementValue.equalsIgnoreCase( JBossSAMLConstants.SUBJECT.get() )) 
               break;  
         }
         
         StartElement peekedElement  = StaxParserUtil.peekNextStartElement( xmlEventReader  );
         if( peekedElement == null )
            break; 

         String tag = StaxParserUtil.getStartElementName( peekedElement );
         
         if( JBossSAMLConstants.NAMEID.get().equalsIgnoreCase( tag ) )
         {
            try
            {
               StartElement nameIDElement = StaxParserUtil.getNextStartElement( xmlEventReader ); 
               Attribute nameQualifier = nameIDElement.getAttributeByName( new QName( "", JBossSAMLConstants.NAME_QUALIFIER.get() ));
               if( nameQualifier == null )
                  nameQualifier = nameIDElement.getAttributeByName( new QName( JBossSAMLURIConstants.ASSERTION_NSURI.get(),
                        JBossSAMLConstants.NAME_QUALIFIER.get() ));
               
               String nameIDValue = xmlEventReader.getElementText();
               
               NameIDType nameID = new NameIDType();
               nameID.setValue( nameIDValue );
               if( nameQualifier != null )
               {
                  nameID.setNameQualifier( StaxParserUtil.getAttributeValue(nameQualifier) ); 
               }  
               
               JAXBElement<NameIDType> jaxbNameID =  objectFactory.createNameID( nameID );
               subject.getContent().add( jaxbNameID );
               
               //There is no need to get the end tag as the "getElementText" call above puts us past that
            }
            catch (XMLStreamException e)
            {
              throw new ParsingException( e );
            } 
         }  
         else if( JBossSAMLConstants.SUBJECT_CONFIRMATION.get().equalsIgnoreCase( tag ) )
         {
             StartElement subjectConfirmationElement = StaxParserUtil.getNextStartElement( xmlEventReader ); 
               Attribute method = subjectConfirmationElement.getAttributeByName( new QName( "", JBossSAMLConstants.METHOD.get() ));
               if( method == null )
                  method = subjectConfirmationElement.getAttributeByName( new QName( JBossSAMLURIConstants.ASSERTION_NSURI.get(),
                        JBossSAMLConstants.METHOD.get() )); 
               
               SubjectConfirmationType subjectConfirmationType = new SubjectConfirmationType();   
               
               if( method != null )
               {
                  subjectConfirmationType.setMethod( StaxParserUtil.getAttributeValue( method ) ); 
               }  
               
               JAXBElement<SubjectConfirmationType> jaxbSubjectConf = objectFactory.createSubjectConfirmation( subjectConfirmationType );
               subject.getContent().add(jaxbSubjectConf);
               
               //Get the end tag
               StaxParserUtil.getNextEvent(xmlEventReader); 
         }   
         else throw new RuntimeException( "Unknown tag:" + tag );    
      }
      
      return subject;
   }

   /**
    * @see {@link ParserNamespaceSupport#supports(QName)}
    */
   public boolean supports(QName qname)
   { 
      return false;
   }
}