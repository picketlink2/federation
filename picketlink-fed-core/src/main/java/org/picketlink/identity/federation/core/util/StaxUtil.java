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
package org.picketlink.identity.federation.core.util;

import java.io.OutputStream;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.picketlink.identity.federation.core.exceptions.ProcessingException;

/**
 * Utility class that deals with StAX
 * @author Anil.Saldhana@redhat.com
 * @since Oct 19, 2010
 */
public class StaxUtil
{ 
   /**
    * Flush the stream writer
    * @param writer
    * @throws ProcessingException
    */
   public static void flush( XMLStreamWriter writer ) throws ProcessingException 
   {
      try
      {
         writer.flush();
      }
      catch (XMLStreamException e)
      {
         throw new ProcessingException( e );
      }
   }

   /**
    * Get an {@code XMLEventWriter}
    * @param outStream
    * @return
    * @throws ProcessingException
    */
   public static XMLEventWriter getXMLEventWriter( final OutputStream outStream ) throws ProcessingException
   {
      XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newInstance();
      try
      {
         return xmlOutputFactory.createXMLEventWriter( outStream, "UTF-8" );
      }
      catch (XMLStreamException e)
      {
         throw new ProcessingException( e );
      }
   }

   /**
    * Get an {@code XMLStreamWriter}
    * @param outStream
    * @return
    * @throws ProcessingException
    */
   public static XMLStreamWriter getXMLStreamWriter( final OutputStream outStream ) throws ProcessingException
   {
      XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newInstance();
      try
      {
         return xmlOutputFactory.createXMLStreamWriter( outStream, "UTF-8" );
      }
      catch (XMLStreamException e)
      {
         throw new ProcessingException( e );
      }
   }
   
   /**
    * Set a prefix
    * @param writer
    * @param prefix
    * @param nsURI
    * @throws ProcessingException
    */
   public static void setPrefix( XMLStreamWriter writer, String prefix, String nsURI ) throws ProcessingException
   {
      try
      {
         writer.setPrefix(prefix, nsURI );
      }
      catch (XMLStreamException e)
      {
         throw new ProcessingException( e );
      }
   }
   
   /**
    * Write an attribute
    * @param writer
    * @param attributeName QName of the attribute
    * @param attributeValue
    * @throws ProcessingException
    */
   public static void writeAttribute( XMLStreamWriter writer, QName attributeName, String attributeValue ) throws ProcessingException
   {
      try
      {
         writer.writeAttribute( attributeName.getNamespaceURI() , attributeName.getLocalPart(), attributeValue );
      }
      catch (XMLStreamException e)
      {
         throw new ProcessingException( e );
      }
   }

   /**
    * Write an xml attribute
    * @param writer
    * @param localName localpart
    * @param value value of the attribute
    * @throws ProcessingException
    */
   public static void writeAttribute( XMLStreamWriter writer, String localName, String value )  throws ProcessingException
   {
      try
      { 
         writer.writeAttribute(localName, value);
      }
      catch (XMLStreamException e)
      {
         throw new ProcessingException( e );
      }
   }
   
   /**
    * Write an xml attribute
    * @param writer
    * @param localName localpart
    * @param type typically xsi:type
    * @param value value of the attribute
    * @throws ProcessingException
    */
   public static void writeAttribute( XMLStreamWriter writer, String localName, String type,  String value )  throws ProcessingException
   {
      try
      { 
         writer.writeAttribute( localName, type, value );
      }
      catch (XMLStreamException e)
      {
         throw new ProcessingException( e );
      }
   }
   
   /**
    * Write a string as text node
    * @param writer
    * @param value
    * @throws ProcessingException
    */
   public static void writeCharacters( XMLStreamWriter writer, String value )  throws ProcessingException
   {
      try
      { 
         writer.writeCharacters( value);
      }
      catch (XMLStreamException e)
      {
         throw new ProcessingException( e );
      }
   }
   
   /**
    * Write the default namespace
    * @param writer
    * @param ns
    * @throws ProcessingException
    */
   public static void WriteDefaultNameSpace( XMLStreamWriter writer, String ns ) throws ProcessingException
   {
      try
      {
         writer.writeDefaultNamespace( ns );
      }
      catch (XMLStreamException e)
      {
         throw new ProcessingException( e );
      }
   }
   
   /**
    * Write a namespace
    * @param writer
    * @param prefix prefix
    * @param ns Namespace URI
    * @throws ProcessingException
    */
   public static void writeNameSpace( XMLStreamWriter writer, String prefix, String ns )  throws ProcessingException
   {
      try
      { 
         writer.writeNamespace(prefix, ns);
      }
      catch (XMLStreamException e)
      {
         throw new ProcessingException( e );
      }
   }

   /**
    * Write a start element
    * @param writer
    * @param prefix
    * @param localPart
    * @param ns
    * @throws ProcessingException
    */
   public static void writeStartElement( XMLStreamWriter writer, String prefix, String localPart, String ns ) throws ProcessingException
   {
      try
      {
         writer.writeStartElement( prefix, localPart, ns);
      }
      catch (XMLStreamException e)
      {
         throw new ProcessingException( e );
      }
   }

   /**
    * <p>
    * Write an end element. The stream writer keeps track of which start element
    * needs to be closed with an end tag.
    * </p>
    * 
    * @param writer
    * @throws ProcessingException
    */
   public static void writeEndElement( XMLStreamWriter writer ) throws ProcessingException
   {
      try
      {
         writer.writeEndElement();
      }
      catch (XMLStreamException e)
      {
         throw new ProcessingException( e );
      }
   }
}