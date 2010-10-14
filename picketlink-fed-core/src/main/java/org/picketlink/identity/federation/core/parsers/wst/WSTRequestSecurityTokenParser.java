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
package org.picketlink.identity.federation.core.parsers.wst;

import java.net.URI;
import java.net.URISyntaxException;

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
import org.picketlink.identity.federation.core.wstrust.WSTrustConstants;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken;
import org.picketlink.identity.federation.ws.trust.ValidateTargetType;

/**
 * Parse the WS-Trust RequestSecurityToken
 * @author Anil.Saldhana@redhat.com
 * @since Oct 11, 2010
 */
public class WSTRequestSecurityTokenParser implements ParserNamespaceSupport
{  
   /**
    * @see {@link ParserNamespaceSupport#parse(XMLEventReader)}
    */
   public Object parse(XMLEventReader xmlEventReader) throws ParsingException
   {
      StartElement startElement =  StaxParserUtil.getNextStartElement( xmlEventReader ); 
      
      RequestSecurityToken requestToken = new RequestSecurityToken();
      
      QName contextQName = new QName( "", "Context" );
      Attribute contextAttribute = startElement.getAttributeByName( contextQName );
      String contextValue = StaxParserUtil.getAttributeValue( contextAttribute );
      requestToken.setContext( contextValue ); 
      
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
            if( endElementTag.equals( WSTrustConstants.RST ) )
               break;
         }
         
         try
         {
            StartElement subEvent = StaxParserUtil.getNextStartElement( xmlEventReader );
            if( subEvent == null )
               break;
            
            String tag = StaxParserUtil.getStartElementName( subEvent );
            if( tag.equals( WSTrustConstants.REQUEST_TYPE ))
            { 
               String value = xmlEventReader.getElementText();
               requestToken.setRequestType( new URI( value ));
            }
            else if( tag.equals( WSTrustConstants.TOKEN_TYPE  ))
            {
               String value = xmlEventReader.getElementText();
               requestToken.setTokenType( new URI( value ));
            }
            else if( tag.equals( WSTrustConstants.VALIDATE_TARGET  ))
            {
               WSTValidateTargetParser wstValidateTargetParser = new WSTValidateTargetParser();
               ValidateTargetType validateTarget = (ValidateTargetType) wstValidateTargetParser.parse( xmlEventReader );
               requestToken.setValidateTarget( validateTarget ); 
               EndElement validateTargetEndElement = StaxParserUtil.getNextEndElement(xmlEventReader);
               if( !StaxParserUtil.getEndElementName( validateTargetEndElement ).equals( WSTrustConstants.VALIDATE_TARGET ) )
                  throw new RuntimeException( "</" + WSTrustConstants.VALIDATE_TARGET + "> expected" );
            }  
         }
         catch( XMLStreamException e )
         {
            throw new ParsingException( e );
         }
         catch (URISyntaxException e)
         {
            throw new ParsingException( e );
         }   
      }
      
      return requestToken;
   }
 
   /**
    * @see {@link ParserNamespaceSupport#supports(QName)}
    */
   public boolean supports(QName qname)
   { 
      return false;
   } 
}