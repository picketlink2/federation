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
package org.picketlink.identity.federation.web.util;

import java.io.IOException;
import java.io.InputStream;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.picketlink.identity.federation.core.config.IDPType;
import org.picketlink.identity.federation.core.config.SPType;
import org.picketlink.identity.federation.core.constants.PicketLinkFederationConstants;
import org.picketlink.identity.federation.core.handler.config.Handlers;
import org.picketlink.identity.federation.core.util.JAXBUtil;
import org.xml.sax.SAXException;

/**
 * Deals with Configuration
 * @author Anil.Saldhana@redhat.com
 * @since Aug 21, 2009
 */
public class ConfigurationUtil
{
   /**
    * Get the IDP Configuration
    * from the passed configuration
    * @param is
    * @return
    * @throws JAXBException
    * @throws SAXException
    * @throws IOException
    */
   @SuppressWarnings("unchecked")
   public static IDPType getIDPConfiguration(InputStream is) throws JAXBException, SAXException, IOException  
   {
      if(is == null)
         throw new IllegalArgumentException("inputstream is null");
      String schema = PicketLinkFederationConstants.SCHEMA_IDFED;
      
      Unmarshaller un = getUnmarshaller(schema);
      
      JAXBElement<IDPType> jaxbSp =  (JAXBElement<IDPType>) un.unmarshal(is);
      return jaxbSp.getValue(); 
   }

   
   /**
    * Get the SP Configuration from the
    * passed inputstream
    * @param is
    * @return
    * @throws JAXBException
    * @throws SAXException
    * @throws IOException
    */
   @SuppressWarnings("unchecked")
   public static SPType getSPConfiguration(InputStream is) throws JAXBException, SAXException, IOException  
   {
      if(is == null)
         throw new IllegalArgumentException("inputstream is null");
      String schema = PicketLinkFederationConstants.SCHEMA_IDFED;
      
      Unmarshaller un = getUnmarshaller(schema);
      
      JAXBElement<SPType> jaxbSp =  (JAXBElement<SPType>) un.unmarshal(is);
      return jaxbSp.getValue(); 
   }
   
   /**
    * Get the Handlers from the configuration
    * @param is
    * @return
    * @throws JAXBException
    * @throws SAXException
    * @throws IOException
    */
   @SuppressWarnings("unchecked")
   public static Handlers getHandlers(InputStream is) throws JAXBException, SAXException, IOException
   {
      if(is == null)
         throw new IllegalArgumentException("inputstream is null");
      String[] schemas = new String[] { PicketLinkFederationConstants.SCHEMA_IDFED,
    		  PicketLinkFederationConstants.SCHEMA_IDFED_HANDLER};

      Unmarshaller un = getUnmarshaller(schemas);
      JAXBElement<Handlers> handlers = (JAXBElement<Handlers>) un.unmarshal(is);
      return handlers.getValue(); 
   }
   

   private static Unmarshaller getUnmarshaller(String... schema) throws JAXBException, SAXException, IOException
   {
      String key = PicketLinkFederationConstants.JAXB_SCHEMA_VALIDATION;
      boolean validate = Boolean.parseBoolean(SecurityActions.getSystemProperty(key, "false"));
      
      String[] pkgName =  new String[] { IDPType.class.getPackage().getName(),
            Handlers.class.getPackage().getName()    
      } ; 
      
      Unmarshaller un = null;
      if(validate)
         un = JAXBUtil.getValidatingUnmarshaller(pkgName, schema);
      else
         un = JAXBUtil.getUnmarshaller(pkgName);
      return un;
   }
}