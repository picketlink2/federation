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
package org.picketlink.identity.federation.api.util;

import java.io.StringReader;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.picketlink.identity.federation.core.util.Base64;
import org.picketlink.identity.federation.core.util.JAXBUtil;
import org.picketlink.identity.xmlsec.w3.xmldsig.KeyInfoType;
import org.picketlink.identity.xmlsec.w3.xmldsig.ObjectFactory;

/**
 * Utility dealing with PublicKey/Certificates and xml-dsig KeyInfoType
 * @author Anil.Saldhana@redhat.com
 * @since Apr 29, 2009
 */
public class KeyUtil
{ 
   private static String EOL = getSystemProperty("line.separator", "\n");
   
   private static ObjectFactory of = new ObjectFactory();
   
   /**
    * Base64 encode the certificate
    * @param certificate
    * @return
    * @throws CertificateEncodingException
    */
   public static String encodeAsString(Certificate certificate) throws CertificateEncodingException
   {
      return Base64.encodeBytes(certificate.getEncoded());
   }
   
   /**
    * Given a certificate, build a keyinfo type
    * @param certificate
    * @return   
    * @throws JAXBException 
    * @throws CertificateException 
    */
   public static KeyInfoType getKeyInfo(Certificate certificate) throws JAXBException, CertificateException 
   { 
      if(certificate == null)
         throw new IllegalArgumentException("certificate is null");
      
      StringBuilder builder = new StringBuilder(); 
      
      if(certificate instanceof X509Certificate)
      {
         X509Certificate x509 = (X509Certificate) certificate; 
         
         //Add the binary encoded x509 cert
         String certStr = Base64.encodeBytes(x509.getEncoded(), 76);
         
         builder.append("<KeyInfo xmlns=\'http://www.w3.org/2000/09/xmldsig#\'>").append(EOL)
         .append("<X509Data>").append(EOL)
         .append("<X509Certificate>").append(EOL)
         .append(certStr).append(EOL)
         .append("</X509Certificate>")
         .append("</X509Data>")
         .append("</KeyInfo>");
      }
      else
         throw new RuntimeException("NYI");
      
      JAXBElement<?> keyInfoJ = (JAXBElement<?>) getUnmarshaller().unmarshal(new StringReader(builder.toString()));
      return (KeyInfoType) keyInfoJ.getValue();
   }
   
   /**
    * Get the object factory for the w3 xml-dsig
    * @return
    */
   public static ObjectFactory getObjectFactory()
   {
      return of;
   }
   
   /**
    * Get the Unmarshaller for the W3 XMLDSIG
    * @return 
    * @throws JAXBException 
    */
   public static Unmarshaller getUnmarshaller() throws JAXBException  
   {
      return JAXBUtil.getUnmarshaller("org.picketlink.identity.xmlsec.w3.xmldsig");
   }
   
   /**
    * Get the marshaller for the W3 XMLDSig
    * @return 
    * @throws JAXBException 
    */
   public static Marshaller getMarshaller() throws JAXBException 
   {
      return JAXBUtil.getMarshaller("org.picketlink.identity.xmlsec.w3.xmldsig");
   }
   
   /**
    * Get the system property
    * @param key
    * @param defaultValue
    * @return
    */
   static String getSystemProperty(final String key, final String defaultValue)
   {
      return AccessController.doPrivileged(new PrivilegedAction<String>()
      {
         public String run()
         {
            return System.getProperty(key, defaultValue);
         }
      });
   }
}
