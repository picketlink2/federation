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
package org.picketlink.identity.federation.api.saml.v2.metadata;

import static org.picketlink.identity.federation.core.util.StringUtil.isNotNull;

import java.math.BigInteger;

import org.picketlink.identity.federation.newmodel.saml.v2.metadata.KeyDescriptorType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.KeyTypes;
import org.picketlink.identity.xmlsec.w3.xmlenc.EncryptionMethodType;
import org.w3c.dom.Element;

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
   public static KeyDescriptorType createKeyDescriptor( Element keyInfo,
         String algorithm, int keySize,
         boolean isSigningKey, boolean isEncryptionKey)
   {
      if(keyInfo == null)
         throw new IllegalArgumentException("keyInfo is null");
      
      if(isSigningKey == isEncryptionKey)
         throw new IllegalArgumentException("Only one of isSigningKey " +
         		"and isEncryptionKey should be true");
      
      KeyDescriptorType keyDescriptor = new KeyDescriptorType();
      
      if(isNotNull(algorithm))
      {
         EncryptionMethodType encryptionMethod = new EncryptionMethodType();
         encryptionMethod.setAlgorithm(algorithm);
         
         encryptionMethod.getContent().add(BigInteger.valueOf(keySize));
         
         keyDescriptor.addEncryptionMethod( encryptionMethod );  
      } 
      
      if(isSigningKey)
         keyDescriptor.setUse(KeyTypes.SIGNING);
      if(isEncryptionKey)
         keyDescriptor.setUse(KeyTypes.ENCRYPTION); 
      
      keyDescriptor.setKeyInfo( keyInfo );
       
      return keyDescriptor;
   }
}