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
package org.jboss.identity.federation.api.saml.v2.metadata;

import java.math.BigInteger;

import org.jboss.identity.federation.saml.v2.metadata.KeyDescriptorType;
import org.jboss.identity.federation.saml.v2.metadata.KeyTypes;
import org.jboss.identity.federation.saml.v2.metadata.ObjectFactory;
import org.jboss.identity.xmlsec.w3.xmldsig.KeyInfoType;
import org.jboss.identity.xmlsec.w3.xmlenc.EncryptionMethodType;

import static org.jboss.identity.federation.core.util.StringUtil.isNotNull;

/**
 * MetaDataBuilder for the KeyDescriptor
 * @author Anil.Saldhana@redhat.com
 * @since Apr 20, 2009
 */
public class KeyDescriptorMetaDataBuilder
{  
   /**
    * Create a Key Descriptor Type
    * @return
    */
   public static KeyDescriptorType createKeyDescriptor(KeyInfoType keyInfo,
         String algorithm, int keySize,
         boolean isSigningKey, boolean isEncryptionKey)
   {
      if(keyInfo == null)
         throw new IllegalArgumentException("keyInfo is null");
      
      if(isSigningKey == isEncryptionKey)
         throw new IllegalArgumentException("Only one of isSigningKey " +
         		"and isEncryptionKey should be true");
      
      KeyDescriptorType keyDescriptor = getObjectFactory().createKeyDescriptorType();
      
      if(isNotNull(algorithm))
      {
         EncryptionMethodType encryptionMethod = new EncryptionMethodType();
         encryptionMethod.setAlgorithm(algorithm);
         
         encryptionMethod.getContent().add(BigInteger.valueOf(keySize));
         
         keyDescriptor.getEncryptionMethod().add(encryptionMethod);  
      } 
      
      if(isSigningKey)
         keyDescriptor.setUse(KeyTypes.SIGNING);
      if(isEncryptionKey)
         keyDescriptor.setUse(KeyTypes.ENCRYPTION); 
      
      keyDescriptor.setKeyInfo(keyInfo);
      
      return keyDescriptor;
   }

   /**
    * Return the metadata object factory
    * @return
    */
   public static ObjectFactory getObjectFactory()
   {
      return MetaDataBuilder.getObjectFactory();
   }
}