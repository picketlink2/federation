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
package org.picketlink.identity.federation.core.saml.md.providers;

import java.io.InputStream;
import java.security.PublicKey;
import java.util.Map;

import javax.xml.bind.JAXBElement;
 
import org.picketlink.identity.federation.core.interfaces.IMetadataProvider;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType;

/**
 * A file based metadata provider that
 * just looks for the passed in file name
 * @author Anil.Saldhana@redhat.com
 * @since Apr 21, 2009
 */
public class FileBasedEntityMetadataProvider extends AbstractMetadataProvider
implements IMetadataProvider<EntityDescriptorType>
{

   private static final String FILENAME_KEY = "FileName";
   private String fileName;
   private InputStream metadataFileStream;
   @SuppressWarnings("unused")
   private PublicKey encryptionKey;
   @SuppressWarnings("unused")
   private PublicKey signingKey;
   
   @Override
   public void init(Map<String, String> options)
   {
      super.init(options);
      fileName = options.get(FILENAME_KEY);
      if(fileName == null)
         throw new IllegalStateException("FileName option not set"); 
   }   
   
   /**
    * @see IMetadataProvider#getMetaData()
    */
   @SuppressWarnings("unchecked")
   public EntityDescriptorType getMetaData()
   {
      EntityDescriptorType edt = null; 
      
      if(this.metadataFileStream == null)
         throw new RuntimeException("Metadata file is not injected");
      
      try
      { 
         JAXBElement<EntityDescriptorType> j =
            (JAXBElement<EntityDescriptorType>) MetaDataBuilderDelegate.getUnmarshaller().unmarshal(metadataFileStream); 
         edt = j.getValue();
         //TODO: use the signing and enc key data
      }
      catch(Exception e)
      {
         throw new RuntimeException(e);
      }
      return edt;
   }

   /**
    * @see IMetadataProvider#isMultiple()
    */
   public boolean isMultiple()
   {
      return false;
   }

   public void injectEncryptionKey(PublicKey publicKey)
   {
      this.encryptionKey = publicKey;
   }

   public void injectFileStream(InputStream fileStream)
   {
      this.metadataFileStream = fileStream;
   }

   public void injectSigningKey(PublicKey publicKey)
   {
      this.signingKey = publicKey;  
   }

   public String requireFileInjection()
   {
      return this.fileName;
   } 
}