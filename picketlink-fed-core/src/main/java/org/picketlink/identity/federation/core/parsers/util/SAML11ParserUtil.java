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

import java.net.URI;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.parsers.saml.SAML11SubjectParser;
import org.picketlink.identity.federation.core.saml.v1.SAML11Constants;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11AttributeStatementType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11AttributeType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11SubjectType;

/**
 * Utility for parsing SAML 1.1 payload
 * @author Anil.Saldhana@redhat.com
 * @since Jun 23, 2011
 */
public class SAML11ParserUtil
{
   /**
    * Parse an {@code SAML11AttributeStatementType}
    * @param xmlEventReader
    * @return
    * @throws ParsingException
    */
   public static SAML11AttributeStatementType parseSAML11AttributeStatement(XMLEventReader xmlEventReader)
         throws ParsingException
   {
      SAML11AttributeStatementType attributeStatementType = new SAML11AttributeStatementType();

      StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
      String ATTRIBSTATEMT = JBossSAMLConstants.ATTRIBUTE_STATEMENT.get();
      StaxParserUtil.validate(startElement, ATTRIBSTATEMT);

      while (xmlEventReader.hasNext())
      {
         XMLEvent xmlEvent = StaxParserUtil.peek(xmlEventReader);
         if (xmlEvent instanceof EndElement)
         {
            EndElement endElement = StaxParserUtil.getNextEndElement(xmlEventReader);
            StaxParserUtil.validate(endElement, JBossSAMLConstants.ATTRIBUTE_STATEMENT.get());
            break;
         }
         //Get the next start element
         startElement = StaxParserUtil.peekNextStartElement(xmlEventReader);
         String tag = startElement.getName().getLocalPart();
         if (JBossSAMLConstants.ATTRIBUTE.get().equals(tag))
         {
            SAML11AttributeType attribute = parseSAML11Attribute(xmlEventReader);
            attributeStatementType.add(attribute);
         }
         else if (JBossSAMLConstants.SUBJECT.get().equals(tag))
         {
            SAML11SubjectParser parser = new SAML11SubjectParser();
            SAML11SubjectType subject = (SAML11SubjectType) parser.parse(xmlEventReader);
            attributeStatementType.setSubject(subject);
         }
         else
            throw new RuntimeException("Unknown tag:" + tag + "::Location=" + startElement.getLocation());
      }
      return attributeStatementType;
   }

   /**
    * Parse a {@link SAML11AttributeType}
    * @param xmlEventReader
    * @return
    * @throws ParsingException
    */
   public static SAML11AttributeType parseSAML11Attribute(XMLEventReader xmlEventReader) throws ParsingException
   {
      StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
      StaxParserUtil.validate(startElement, JBossSAMLConstants.ATTRIBUTE.get());
      SAML11AttributeType attributeType = null;

      Attribute name = startElement.getAttributeByName(new QName(SAML11Constants.ATTRIBUTE_NAME));
      if (name == null)
         throw new RuntimeException("Required attribute Name in Attribute");
      String attribName = StaxParserUtil.getAttributeValue(name);

      Attribute namesp = startElement.getAttributeByName(new QName(SAML11Constants.ATTRIBUTE_NAMESPACE));
      if (namesp == null)
         throw new RuntimeException("Required attribute Namespace in Attribute");
      String attribNamespace = StaxParserUtil.getAttributeValue(namesp);

      attributeType = new SAML11AttributeType(attribName, URI.create(attribNamespace));

      attributeType.add(parseAttributeValue(xmlEventReader));

      parseAttributeType(xmlEventReader, startElement, JBossSAMLConstants.ATTRIBUTE.get(), attributeType);
      return attributeType;
   }

   /**
    * Parse an {@code SAML11AttributeType}
    * @param xmlEventReader 
    * @throws ParsingException
    */
   public static void parseAttributeType(XMLEventReader xmlEventReader, StartElement startElement, String rootTag,
         SAML11AttributeType attributeType) throws ParsingException
   {
      while (xmlEventReader.hasNext())
      {
         XMLEvent xmlEvent = StaxParserUtil.peek(xmlEventReader);
         if (xmlEvent instanceof EndElement)
         {
            EndElement end = StaxParserUtil.getNextEndElement(xmlEventReader);
            if (StaxParserUtil.matches(end, rootTag))
               break;
         }
         startElement = StaxParserUtil.peekNextStartElement(xmlEventReader);
         if (startElement == null)
            break;
         String tag = StaxParserUtil.getStartElementName(startElement);

         if (JBossSAMLConstants.ATTRIBUTE.get().equals(tag))
            break;

         if (JBossSAMLConstants.ATTRIBUTE_VALUE.get().equals(tag))
         {
            Object attributeValue = parseAttributeValue(xmlEventReader);
            attributeType.add(attributeValue);
         }
         else
            throw new RuntimeException("Unknown tag:" + tag + "::Location=" + startElement.getLocation());
      }
   }

   /**
    * Parse Attribute value
    * @param xmlEventReader
    * @return
    * @throws ParsingException
    */
   public static Object parseAttributeValue(XMLEventReader xmlEventReader) throws ParsingException
   {
      StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
      StaxParserUtil.validate(startElement, JBossSAMLConstants.ATTRIBUTE_VALUE.get());

      Attribute type = startElement.getAttributeByName(new QName(JBossSAMLURIConstants.XSI_NSURI.get(), "type", "xsi"));
      if (type == null)
      {
         return StaxParserUtil.getElementText(xmlEventReader);
      }

      String typeValue = StaxParserUtil.getAttributeValue(type);
      if (typeValue.contains(":string"))
      {
         return StaxParserUtil.getElementText(xmlEventReader);
      }

      throw new RuntimeException("Unsupported xsi:type=" + typeValue);
   }
}
