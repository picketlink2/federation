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

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;

import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.util.StaxUtil;
import org.picketlink.identity.federation.core.util.StringUtil;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;

/**
 * Base Class for the Stax writers for SAML
 * @author Anil.Saldhana@redhat.com
 * @since Nov 2, 2010
 */
public class BaseWriter
{
   protected static String PROTOCOL_PREFIX = "samlp";
   protected static String ASSERTION_PREFIX = "saml";
   
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
      
      String format = nameIDType.getFormat();
      if( StringUtil.isNotNull( format ))
      {
         StaxUtil.writeAttribute( writer, JBossSAMLConstants.FORMAT.get(), format );
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
}