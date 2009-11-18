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
package org.jboss.identity.federation.core.saml.v2.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory; 
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer; 
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory; 
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathException;

import org.apache.log4j.Logger;
import org.jboss.identity.federation.core.exceptions.ConfigurationException;
import org.jboss.identity.federation.core.exceptions.ParsingException;
import org.jboss.identity.federation.core.exceptions.ProcessingException;
import org.w3c.dom.DOMConfiguration;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Utility dealing with DOM
 * @author Anil.Saldhana@redhat.com
 * @since Jan 14, 2009
 */
public class DocumentUtil
{ 
   private static Logger log = Logger.getLogger(DocumentUtil.class);
   private static boolean trace = log.isTraceEnabled();
   
   
   /**
    * Check whether a node belongs to a document
    * @param doc
    * @param node
    * @return 
    */
   public static boolean containsNode(Document doc, Node node)  
   {  
     if(node.getNodeType() == Node.ELEMENT_NODE)
     {
        Element elem = (Element) node;
        NodeList nl = doc.getElementsByTagNameNS(elem.getNamespaceURI(), elem.getLocalName());
        if(nl != null && nl.getLength() > 0)
           return true;
        else
           return false;
     }
     throw new UnsupportedOperationException();
   }
   
   /**
    * Create a new document
    * @return
    * @throws ParserConfigurationException  
    */
   public static Document createDocument() throws ConfigurationException 
   {
      DocumentBuilderFactory factory = getDocumentBuilderFactory();
      DocumentBuilder builder;
      try
      {
         builder = factory.newDocumentBuilder();
      }
      catch (ParserConfigurationException e)
      {
         throw new ConfigurationException(e);
      }
      return builder.newDocument(); 
   }

   /**
    * Parse a document from the string
    * @param docString
    * @return 
    * @throws IOException 
    * @throws SAXException 
    * @throws ParserConfigurationException 
    */
   public static Document getDocument(String docString) 
   throws ConfigurationException,ParsingException, ProcessingException
   {
      return getDocument(new StringReader(docString));
   }
   
   /**
    * Parse a document from a reader
    * @param reader
    * @return
    * @throws ParsingException 
    * @throws ParserConfigurationException  
    * @throws IOException 
    * @throws SAXException 
    */
   public static Document getDocument(Reader reader) 
   throws ConfigurationException, ProcessingException, ParsingException 
   {
      try
      {
         DocumentBuilderFactory factory = getDocumentBuilderFactory();
         DocumentBuilder builder = factory.newDocumentBuilder();
         return builder.parse(new InputSource(reader));
      }
      catch (ParserConfigurationException e)
      {
         throw new ConfigurationException(e);
      }
      catch (SAXException e)
      {
         throw new ParsingException(e);
      }
      catch (IOException e)
      {
         throw new ProcessingException(e);
      }
   }
   
   /**
    * Get Document from a file
    * @param file
    * @return 
    * @throws ParserConfigurationException 
    * @throws IOException 
    * @throws SAXException 
    */
   public static Document getDocument(File file) 
   throws ConfigurationException, ProcessingException, ParsingException 
   {
      DocumentBuilderFactory factory = getDocumentBuilderFactory(); 
      try
      {
         DocumentBuilder builder = factory.newDocumentBuilder(); 
         return builder.parse(file);
      }
      catch (ParserConfigurationException e)
      {
         throw new ConfigurationException(e);
      }
      catch (SAXException e)
      {
         throw new ParsingException(e);
      }
      catch (IOException e)
      {
         throw new ProcessingException(e);
      }
   }
   
   /**
    * Get Document from an inputstream
    * @param is
    * @return
    * @throws ParserConfigurationException  
    * @throws IOException 
    * @throws SAXException 
    */
   public static Document getDocument(InputStream is) 
   throws ConfigurationException, ProcessingException, ParsingException 
   {
      DocumentBuilderFactory factory = getDocumentBuilderFactory(); 
      try
      {
         DocumentBuilder builder = factory.newDocumentBuilder(); 
         return builder.parse(is);
      }
      catch (ParserConfigurationException e)
      {
         throw new ConfigurationException(e);
      }
      catch (SAXException e)
      {
         throw new ParsingException(e);
      }
      catch (IOException e)
      {
         throw new ProcessingException(e);
      }
   }
   
   /**
    * Marshall a document into a String
    * @param signedDoc
    * @return
    * @throws TransformerFactoryConfigurationError 
    * @throws TransformerException  
    */
   public static String getDocumentAsString(Document signedDoc) 
   throws ProcessingException, ConfigurationException
   {
     Source source = new DOMSource(signedDoc);
     StringWriter sw = new StringWriter();
 
     Result streamResult = new StreamResult(sw);
     // Write the DOM document to the stream
     Transformer xformer = getTransformer();
     try
     {
        xformer.transform(source, streamResult);
     }
     catch (TransformerException e)
     {
        throw new ProcessingException(e);
     }
     
     return sw.toString();
   }
 
   /**
    * Marshall a DOM Element as string
    * @param element
    * @return
    * @throws TransformerFactoryConfigurationError 
    * @throws TransformerException  
    */
   public static String getDOMElementAsString(Element element) 
   throws ProcessingException, ConfigurationException
   {
     Source source = new DOMSource(element);
     StringWriter sw = new StringWriter();
 
     Result streamResult = new StreamResult(sw);
     // Write the DOM document to the file
     Transformer xformer = getTransformer();
     try
     {
        xformer.transform(source, streamResult);
     }
     catch (TransformerException e)
     {
        throw new ProcessingException(e);
     }
     
     return sw.toString();
   }
   
   /**
    * Stream a DOM Node as an input stream
    * @param node
    * @return
    * @throws TransformerFactoryConfigurationError 
    * @throws TransformerException  
    */
   public static InputStream getNodeAsStream(Node node) 
   throws ConfigurationException, ProcessingException 
   {
      Source source = new DOMSource(node);
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      
      Result streamResult = new StreamResult(baos);
      // Write the DOM document to the stream
      Transformer transformer = getTransformer();
      try
      {
         transformer.transform(source, streamResult);
      }
      catch (TransformerException e)
      {
         throw new ProcessingException(e);
      }
      
      ByteArrayInputStream bis = new ByteArrayInputStream(baos.toByteArray());
      
      return bis;
   }
   
   /**
    * Stream a DOM Node as a String
    * @param node
    * @return
    * @throws ProcessingException 
    * @throws TransformerFactoryConfigurationError 
    * @throws TransformerException  
    */
   public static String getNodeAsString(Node node) 
   throws ConfigurationException, ProcessingException 
   {
      Source source = new DOMSource(node);
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      
      Result streamResult = new StreamResult(baos);
      // Write the DOM document to the stream
      Transformer transformer = getTransformer();
      try
      {
         transformer.transform(source, streamResult);
      }
      catch (TransformerException e)
      {
         throw new ProcessingException(e);
      }
      
      return new String(baos.toByteArray()); 
   }
   
   /**
    * Given a document, return a Node with the given node name
    * and an attribute with a particular attribute value
    * @param document
    * @param nsURI
    * @param nodeName
    * @param attributeName
    * @param attributeValue
    * @return
    * @throws XPathException
    * @throws TransformerFactoryConfigurationError
    * @throws TransformerException
    */ 
   public static Node getNodeWithAttribute(Document document, final String nsURI,
         String nodeName,
         String attributeName, String attributeValue) throws XPathException,
         TransformerFactoryConfigurationError, TransformerException
   {
      NodeList nl = document.getElementsByTagNameNS(nsURI, nodeName);
      int len = nl != null ? nl.getLength() : 0;
      
      for (int i = 0; i < len; i++)
      {
         Node n = nl.item(i);
         if(n.getNodeType() != Node.ELEMENT_NODE)
            continue; 
         Element el = (Element) n;
         String attrValue = el.getAttributeNS(nsURI, attributeName);
         if(attributeValue.equals(attrValue))
            return el;
         //Take care of attributes with null NS
         attrValue = el.getAttribute(attributeName);
         if(attributeValue.equals(attrValue))
            return el;
      }
      return null;
   }
   
   /**
    * DOM3 method: Normalize the document with namespaces
    * @param doc
    * @return
    */
   public static Document normalizeNamespaces(Document doc)
   {
      DOMConfiguration docConfig = doc.getDomConfig(); 
      docConfig.setParameter("namespaces", Boolean.TRUE);  
      doc.normalizeDocument();
      return doc;
   }
   
   /**
    * Get a {@link Source} given a {@link Document}
    * @param doc
    * @return
    */
   public static Source getXMLSource(Document doc)
   {
      return new DOMSource(doc);
   }
   
   /**
    * Log the nodes in the document
    * @param doc
    */
   public static void logNodes(Document doc)
   {
     visit(doc, 0); 
   } 
    
   private static void visit(Node node, int level) 
   { 
      // Visit each child
      NodeList list = node.getChildNodes();
      for (int i=0; i<list.getLength(); i++) 
      {
         // Get child node
         Node childNode = list.item(i);
         if(trace) 
            log.trace("Node="+ childNode.getNamespaceURI()+ "::"+childNode.getLocalName());
         // Visit child node
         visit(childNode, level+1);
      }
   }
   
   /**
    * Create a namespace aware Document builder factory
    * @return
    */
   private static DocumentBuilderFactory getDocumentBuilderFactory()
   {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance(); 
      factory.setNamespaceAware(true);
      factory.setXIncludeAware(true);
      return factory;
   }
   
   private static Transformer getTransformer() 
   throws ProcessingException, ConfigurationException
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
}