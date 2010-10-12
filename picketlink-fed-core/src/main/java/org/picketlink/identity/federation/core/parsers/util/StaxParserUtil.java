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

import java.io.InputStream;

import javax.xml.stream.Location;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
 

/**
 * Utility for the stax based parser
 * @author Anil.Saldhana@redhat.com
 * @since Feb 8, 2010
 */
public class StaxParserUtil
{  
   /**
    * Given an {@code Attribute}, get its trimmed value
    * @param attribute
    * @return
    */
   public static String getAttributeValue(Attribute attribute)
   {
      return trim(attribute.getValue());
   }
   
   /**
    * Get the XML event reader
    * @param is
    * @return
    */
   public static XMLEventReader getXMLEventReader( InputStream is ) 
   {
      XMLInputFactory xmlInputFactory = null;
      XMLEventReader xmlEventReader = null;
      try 
      {
        xmlInputFactory = XMLInputFactory.newInstance();
        xmlInputFactory.setProperty( XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, Boolean.TRUE );
        xmlInputFactory.setProperty( XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE );
        xmlInputFactory.setProperty( XMLInputFactory.IS_NAMESPACE_AWARE, Boolean.TRUE );
        xmlInputFactory.setProperty( XMLInputFactory.IS_COALESCING, Boolean.TRUE );
 
        xmlEventReader = xmlInputFactory.createXMLEventReader(is);
      } 
      catch (Exception ex) 
      {
        throw new RuntimeException(ex);
      }
      return xmlEventReader;
    }  
   
   /**
    * Given a {@code Location}, return a formatted string
    * [lineNum,colNum]
    * @param location
    * @return
    */
   public static String getLineColumnNumber(Location location)
   {
     StringBuilder builder = new StringBuilder("[");
     builder.append(location.getLineNumber()).append(",").append(location.getColumnNumber()).append("]");
     return builder.toString();
   }
   
   /**
    * Get the next {@code StartElement }
    * @param xmlEventReader
    * @return
    * @throws XMLStreamException
    */
   public static StartElement getNextStartElement( XMLEventReader xmlEventReader ) throws XMLStreamException
   {
      while( true )
      {
         XMLEvent xmlEvent = xmlEventReader.nextEvent(); 
         
         if( xmlEvent == null || xmlEvent.isStartElement() )
            return ( StartElement ) xmlEvent; 
         else 
            xmlEvent = xmlEventReader.nextEvent();
      }
   }
   
   /**
    * Get the next {@code EndElement}
    * @param xmlEventReader
    * @return
    * @throws XMLStreamException
    */
   public static EndElement getNextEndElement( XMLEventReader xmlEventReader ) throws XMLStreamException
   {
      while( true )
      {
         XMLEvent xmlEvent = xmlEventReader.nextEvent(); 
         
         if( xmlEvent == null || xmlEvent.isEndElement() )
            return ( EndElement ) xmlEvent;  
         else 
            xmlEvent = xmlEventReader.nextEvent();
      }
   }
   
   /**
    * Return the name of the start element
    * @param startElement
    * @return
    */
   public static String getStartElementName(StartElement startElement)
   {
      return trim(startElement.getName().getLocalPart());
   }
   
   /**
    * Peek the next {@code StartElement }
    * @param xmlEventReader
    * @return
    * @throws XMLStreamException
    */
   public static StartElement peekNextStartElement( XMLEventReader xmlEventReader ) throws XMLStreamException
   {
      while( true )
      {
         XMLEvent xmlEvent = xmlEventReader.peek(); 
         
         if( xmlEvent == null || xmlEvent.isStartElement() )
            return ( StartElement ) xmlEvent; 
         else 
            xmlEvent = xmlEventReader.nextEvent();
      }
   }
   
   /**
    * Peek the next {@code EndElement}
    * @param xmlEventReader
    * @return
    * @throws XMLStreamException
    */
   public static EndElement peekNextEndElement( XMLEventReader xmlEventReader ) throws XMLStreamException
   {
      while( true )
      {
         XMLEvent xmlEvent = xmlEventReader.peek(); 
         
         if( xmlEvent == null || xmlEvent.isEndElement() )
            return ( EndElement ) xmlEvent; 
         else 
            xmlEvent = xmlEventReader.nextEvent();
      }
   }
   
   /**
    * Given a string, trim it
    * @param str
    * @return
    * @throws {@code IllegalArgumentException} if the passed str is null
    */
   public static final String trim(String str)
   {
      if(str == null || str.length() == 0)
         throw new IllegalArgumentException("Input str is null");
      return str.trim();
   }
}