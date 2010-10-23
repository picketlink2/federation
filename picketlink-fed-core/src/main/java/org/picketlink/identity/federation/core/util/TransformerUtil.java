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

import java.util.Iterator;
import java.util.Properties;
import java.util.Stack;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import javax.xml.transform.ErrorListener;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.URIResolver;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.stax.StAXSource;

import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.parsers.util.StaxParserUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Utility to deal with JAXP Transformer
 * @author Anil.Saldhana@redhat.com
 * @since Oct 22, 2010
 */
public class TransformerUtil
{
   public static Transformer getTransformer() throws ConfigurationException
   {
      Transformer transformer;
      try
      {
         transformer = TransformerFactory.newInstance().newTransformer();
      }
      catch (TransformerConfigurationException e)
      {
         throw new ConfigurationException(e);
      }
      catch (TransformerFactoryConfigurationError e)
      {
         throw new ConfigurationException(e);
      }
      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
      transformer.setOutputProperty(OutputKeys.INDENT, "no");
      return transformer;
   }

   public static Transformer getStaxSourceToDomResultTransformer() throws ConfigurationException 
   {
      return new PicketLinkStaxToDOMTransformer();  
   }

   /**
    * Custom Project {@code Transformer} that can take in a {@link StAXSource}
    * and transform into {@link DOMResult}
    * @author anil 
    */
   private static class PicketLinkStaxToDOMTransformer extends Transformer
   { 
      @Override
      public void transform(Source xmlSource, Result outputTarget) throws TransformerException
      {
         if( !( xmlSource instanceof StAXSource ))
            throw new IllegalArgumentException( "xmlSource should be a stax source" ); 
         if( outputTarget instanceof DOMResult == false )
            throw new IllegalArgumentException( "outputTarget should be a dom result" );

         String rootTag = null;

         StAXSource staxSource = (StAXSource) xmlSource;
         XMLEventReader xmlEventReader = staxSource.getXMLEventReader();
         if( xmlEventReader == null )
            throw new TransformerException( "The StaxSource is expected to be created using XMLEventReader" );

         DOMResult domResult = (DOMResult) outputTarget;
         Document doc = (Document) domResult.getNode();

         Stack<Node> stack = new Stack<Node>();

         try
         {
            XMLEvent xmlEvent = StaxParserUtil.getNextEvent(xmlEventReader);
            if( xmlEvent instanceof StartElement == false )
               throw new TransformerException( "Expected StartElement " );

            StartElement rootElement = (StartElement) xmlEvent;
            rootTag = StaxParserUtil.getStartElementName( rootElement ); 
            Element docRoot = handleStartElement(xmlEventReader, rootElement, new CustomHolder(doc, false) );
            Node parent = (Element) doc.importNode(docRoot, true);
            doc.appendChild( parent );

            stack.push(parent); 

            while( xmlEventReader.hasNext() )
            {
               xmlEvent = StaxParserUtil.getNextEvent(xmlEventReader);
               int type = xmlEvent.getEventType();
               switch( type )
               {
                  case XMLEvent.START_ELEMENT:
                     StartElement startElement = (StartElement) xmlEvent;
                     CustomHolder holder = new CustomHolder(doc, false);
                     Element docStartElement = handleStartElement(xmlEventReader, startElement, holder  );
                     Node el = doc.importNode(docStartElement, true);

                     Node top = stack.peek();
                     
                     if( !holder.encounteredTextNode )
                     {
                        stack.push(el);  
                     }

                     if( top == null )
                        doc.appendChild(el);
                     else
                        top.appendChild( el );  
                     break;
                  case XMLEvent.END_ELEMENT:
                     EndElement endElement = (EndElement) xmlEvent;
                     String endTag = StaxParserUtil.getEndElementName( endElement );
                     if( rootTag.equals( endTag ))
                        return; //We are done with the dom parsing
                        else
                           stack.pop(); 
                     break;
               }
            }
         }
         catch (ParsingException e)
         {
            throw new TransformerException( e );
         }
      }

      @Override
      public void setParameter(String name, Object value)
      { 
      }

      @Override
      public Object getParameter(String name)
      {
         return null;
      }

      @Override
      public void clearParameters()
      { 
      }

      @Override
      public void setURIResolver(URIResolver resolver)
      { 
      }

      @Override
      public URIResolver getURIResolver()
      { 
         return null;
      }

      @Override
      public void setOutputProperties(Properties oformat)
      { 
      }

      @Override
      public Properties getOutputProperties()
      {
         // TODO Auto-generated method stub
         return null;
      }

      @Override
      public void setOutputProperty(String name, String value) throws IllegalArgumentException
      { 
      }

      @Override
      public String getOutputProperty(String name) throws IllegalArgumentException
      { 
         return null;
      }

      @Override
      public void setErrorListener(ErrorListener listener) throws IllegalArgumentException
      { 
      }

      @Override
      public ErrorListener getErrorListener()
      { 
         return null;
      } 

      private Element handleStartElement( XMLEventReader xmlEventReader, StartElement startElement,CustomHolder holder) throws ParsingException
      { 
         Document doc = holder.doc; 
         
         QName elementName = startElement.getName();
         String ns = elementName.getNamespaceURI();
         String prefix = elementName.getPrefix();
         String localPart = elementName.getLocalPart();

         String qual = prefix != null && prefix != "" ? prefix + ":" + localPart : localPart ;
         Element el = doc.createElementNS( ns, qual ); 

         //Look for attributes
         @SuppressWarnings("unchecked")
         Iterator<Attribute> attrs = startElement.getAttributes();
         while( attrs != null && attrs.hasNext() )
         {
            Attribute attr = attrs.next();
            QName attrName = attr.getName();
            ns = attrName.getNamespaceURI();
            qual = attrName.getPrefix() + ":" + attrName.getLocalPart();

            doc.createAttributeNS( ns, qual );
            el.setAttributeNS( ns, qual , attr.getValue() );
         } 
         
         XMLEvent nextEvent = StaxParserUtil.peek(xmlEventReader);
         if( nextEvent.getEventType() == XMLEvent.CHARACTERS )
         { 
            holder.encounteredTextNode = true;
            String text = StaxParserUtil.getElementText(xmlEventReader);
            Node textNode = doc.createTextNode( text );
            textNode = doc.importNode(textNode, true);
            el.appendChild( textNode ); 
         }   
         return el;
      }
      
      private class CustomHolder
      {
         public Document doc; 
         public boolean encounteredTextNode = false;
         
         public CustomHolder( Document document,  boolean bool )
         {
            this.doc = document; 
            this.encounteredTextNode = bool;
         }
      }
   }
}