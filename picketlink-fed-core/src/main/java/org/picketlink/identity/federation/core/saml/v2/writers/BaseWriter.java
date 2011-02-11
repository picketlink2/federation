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
package org.picketlink.identity.federation.core.saml.v2.writers;

import static org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants.ASSERTION_NSURI;

import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;

import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.util.StaxUtil;
import org.picketlink.identity.federation.core.util.StringUtil; 
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.LocalizedNameType;

/**
 * Base Class for the Stax writers for SAML
 * @author Anil.Saldhana@redhat.com
 * @since Nov 2, 2010
 */
public class BaseWriter
{
   protected static String PROTOCOL_PREFIX = "samlp";
   protected static String ASSERTION_PREFIX = "saml";
   protected static String XACML_SAML_PREFIX = "xacml-saml";
   protected static String XACML_SAML_PROTO_PREFIX = "xacml-samlp";
   protected static String XSI_PREFIX = "xsi";
   
   protected XMLStreamWriter writer = null;  
   
   public BaseWriter(XMLStreamWriter writer) throws ProcessingException
   {
      this.writer = writer;
   }
   
   /**
    * Write {@code NameIDType} to stream
    * @param nameIDType
    * @param tag
    * @param out
    * @throws ProcessingException
    */
   public void write( NameIDType nameIDType, QName tag ) throws ProcessingException
   {
      StaxUtil.writeStartElement( writer, tag.getPrefix(), tag.getLocalPart() , tag.getNamespaceURI() );
      
      URI format = nameIDType.getFormat();
      if( format != null )
      {
         StaxUtil.writeAttribute( writer, JBossSAMLConstants.FORMAT.get(), format.toASCIIString() );
      } 
      
      String spProvidedID = nameIDType.getSPProvidedID();
      if( StringUtil.isNotNull( spProvidedID ))
      {
         StaxUtil.writeAttribute( writer, JBossSAMLConstants.SP_PROVIDED_ID.get(), spProvidedID );
      }
      
      String spNameQualifier = nameIDType.getSPNameQualifier();
      if( StringUtil.isNotNull( spNameQualifier ))
      {
         StaxUtil.writeAttribute( writer, JBossSAMLConstants.SP_NAME_QUALIFIER.get(), spNameQualifier );
      }
      
      String nameQualifier = nameIDType.getNameQualifier();
      if( StringUtil.isNotNull( nameQualifier ))
      {
         StaxUtil.writeAttribute( writer, JBossSAMLConstants.NAME_QUALIFIER.get(), nameQualifier );
      } 
      
      String value = nameIDType.getValue();
      if( StringUtil.isNotNull( value ))
      {
         StaxUtil.writeCharacters( writer, value );
      }
      
      StaxUtil.writeEndElement( writer); 
      StaxUtil.flush( writer ); 
   }
   
   /**
    * Write an {@code AttributeType} to stream
    * 
    * @param attributeType
    * @param out
    * @throws ProcessingException
    */
   public void write(AttributeType attributeType) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE.get(), ASSERTION_NSURI.get());

      writeAttributeTypeWithoutRootTag(attributeType); 
      
      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);
   }
   
   public void writeAttributeTypeWithoutRootTag( AttributeType attributeType ) throws ProcessingException
   {
      String attributeName = attributeType.getName();
      if (attributeName != null)
      {
         StaxUtil.writeAttribute(writer, JBossSAMLConstants.NAME.get(), attributeName);
      }

      String friendlyName = attributeType.getFriendlyName();
      if (StringUtil.isNotNull(friendlyName))
      {
         StaxUtil.writeAttribute(writer, JBossSAMLConstants.FRIENDLY_NAME.get(), friendlyName);
      }

      String nameFormat = attributeType.getNameFormat();
      if (StringUtil.isNotNull(nameFormat))
      {
         StaxUtil.writeAttribute(writer, JBossSAMLConstants.NAME_FORMAT.get(), nameFormat);
      }

      // Take care of other attributes such as x500:encoding
      Map<QName, String> otherAttribs = attributeType.getOtherAttributes();
      if (otherAttribs != null)
      {
         List<String> nameSpacesDealt = new ArrayList<String>();

         Iterator<QName> keySet = otherAttribs.keySet().iterator();
         while (keySet != null && keySet.hasNext())
         {
            QName qname = keySet.next();
            String ns = qname.getNamespaceURI();
            if (!nameSpacesDealt.contains(ns))
            {
               StaxUtil.writeNameSpace(writer, qname.getPrefix(), ns);
               nameSpacesDealt.add(ns);
            }
            String attribValue = otherAttribs.get(qname);
            StaxUtil.writeAttribute(writer, qname, attribValue);
         }
      }

      List<Object> attributeValues = attributeType.getAttributeValue();
      if (attributeValues != null)
      {
         for (Object attributeValue : attributeValues)
         {
            if (attributeValue instanceof String)
            {
               writeStringAttributeValue( (String) attributeValue ); 
            }
            else
               throw new RuntimeException("Unsupported attribute value:" + attributeValue.getClass().getName());
         }
      }
   }
   
   public void writeStringAttributeValue( String attributeValue ) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE_VALUE.get(), ASSERTION_NSURI.get());

      StaxUtil.writeNameSpace(writer, JBossSAMLURIConstants.XSI_PREFIX.get(), JBossSAMLURIConstants.XSI_NSURI.get());
      StaxUtil.writeNameSpace(writer, "xs", JBossSAMLURIConstants.XMLSCHEMA_NSURI.get());
      StaxUtil.writeAttribute(writer, JBossSAMLURIConstants.XSI_NSURI.get(), "type", "xs:string");
      StaxUtil.writeCharacters(writer, attributeValue ); 
      StaxUtil.writeEndElement(writer);
   }
   

   
   public void writeLocalizedNameType( LocalizedNameType localizedNameType, QName startElement ) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, startElement.getPrefix(), startElement.getLocalPart(), startElement.getNamespaceURI() );
      StaxUtil.writeAttribute(writer,  new QName( JBossSAMLURIConstants.XML.get(), "lang", "xml" ),  localizedNameType.getLang() );
      StaxUtil.writeCharacters(writer, localizedNameType.getValue() );
      StaxUtil.writeEndElement(writer);
   }
}