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

import java.io.InputStream;
import java.io.Reader;
import java.util.HashMap;
import java.util.Map;

import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;

/**
 * An LSResource Resolver for schema validation
 * @author Anil.Saldhana@redhat.com
 * @since Jun 9, 2009
 */
public class IDFedLSInputResolver implements LSResourceResolver
{
   private static Map<String, LSInput> lsmap = new HashMap<String,LSInput>(); 
   
   private static Map<String, String> schemaLocationMap = new HashMap<String,String>();
   
   static
   {
      //SAML
      schemaLocationMap.put("saml-schema-assertion-2.0.xsd", "schema/saml/v2/saml-schema-assertion-2.0.xsd");
      
      //WS-T
      schemaLocationMap.put("http://docs.oasis-open.org/ws-sx/ws-trust/200512/", 
            "schema/wstrust/v1_3/ws-trust-1.3.xsd");
      schemaLocationMap.put("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", 
            "schema/wstrust/v1_3/oasis-200401-wss-wssecurity-secext-1.0.xsd");
      schemaLocationMap.put("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", 
            "schema/wstrust/v1_3/oasis-200401-wss-wssecurity-utility-1.0.xsd");
      schemaLocationMap.put("http://schemas.xmlsoap.org/ws/2004/09/policy", 
            "schema/wstrust/v1_3/ws-policy.xsd");
      schemaLocationMap.put("http://www.w3.org/2005/08/addressing", 
            "schema/wstrust/v1_3/ws-addr.xsd");
      
      //XML DSIG
      schemaLocationMap.put("http://www.w3.org/2000/09/xmldsig#", 
            "schema/w3c/xmldsig/xmldsig-core-schema.xsd");
      schemaLocationMap.put("http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd", 
             "schema/w3c/xmldsig/xmldsig-core-schema.xsd");
      
      //XML Enc
      schemaLocationMap.put("http://www.w3.org/2001/04/xmlenc#",
             "schema/w3c/xmlenc/xenc-schema.xsd");
      schemaLocationMap.put("http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd",
             "schema/w3c/xmlenc/xenc-schema.xsd"); 
      
      //XML Schema/DTD
      schemaLocationMap.put("datatypes.dtd",
             "schema/w3c/xmlschema/datatypes.dtd");
      schemaLocationMap.put("http://www.w3.org/2001/XMLSchema.dtd",
             "schema/w3c/xmlschema/XMLSchema.dtd");
   }
   
   public LSInput resolveResource(String type, 
         String namespaceURI, final String publicId, 
         final String systemId, final String baseURI)
   {   
      LSInput lsi = lsmap.get(systemId);
      if(lsi == null)
      {
         ClassLoader tcl = SecurityActions.getContextClassLoader(); 
         String loc = schemaLocationMap.get(systemId);
         if(loc == null)
            return null;
         
         final InputStream is = tcl.getResourceAsStream(loc); 
         if(is == null)
            System.out.println("inputstream is null for "+ loc);
         lsi = new LSInput()
         {
            public String getBaseURI()
            {
               return baseURI;
            }

            public InputStream getByteStream()
            {
               return is;
            }

            public boolean getCertifiedText()
            { 
               return false;
            }

            public Reader getCharacterStream()
            { 
               return null;
            }

            public String getEncoding()
            { 
               return null;
            }

            public String getPublicId()
            {
               return publicId;
            }

            public String getStringData()
            { 
               return null;
            }

            public String getSystemId()
            {
               return systemId;
            }

            public void setBaseURI(String baseURI)
            {
            }

            public void setByteStream(InputStream byteStream)
            {
            }

            public void setCertifiedText(boolean certifiedText)
            {
            }

            public void setCharacterStream(Reader characterStream)
            {
            }

            public void setEncoding(String encoding)
            {
            }

            public void setPublicId(String publicId)
            {
            }

            public void setStringData(String stringData)
            {
            }

            public void setSystemId(String systemId)
            {
            }
        };

        lsmap.put(systemId, lsi);
      }
      return lsi;
   }

}