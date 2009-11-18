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
package org.jboss.identity.federation.core.saml.v2.metadata.store;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Map;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.apache.log4j.Logger;
import org.jboss.identity.federation.core.util.JAXBUtil;
import org.jboss.identity.federation.saml.v2.metadata.EntityDescriptorType;
import org.jboss.identity.federation.saml.v2.metadata.ObjectFactory;

/**
 * File based metadata store that uses
 * the ${user.home}/jbid-store location to
 * persist the data
 * @author Anil.Saldhana@redhat.com
 * @since Apr 27, 2009
 */
public class FileBasedMetadataConfigurationStore implements IMetadataConfigurationStore
{
   private static Logger log = Logger.getLogger(FileBasedMetadataConfigurationStore.class);
   private boolean trace = log.isTraceEnabled();
   
   private static String EXTENSION = ".xml";
   
   private String userHome = null;
   
   private String pkgName = "org.jboss.identity.federation.saml.v2.metadata"; 
   
   public FileBasedMetadataConfigurationStore()
   {
      userHome = SecurityActions.getSystemProperty("user.home");
      if(userHome == null)
         throw new RuntimeException("user.home system property not set");
      
      File jbid = new File(userHome + "/jbid-store");
      if(jbid.exists() == false)
      {
         if(trace)
            log.trace(jbid.getPath() + " does not exist. Hence creating.");
         jbid.mkdir();
      }
   }
   
   /** 
    * @see IMetadataConfigurationStore#load(String)
    */
   @SuppressWarnings("unchecked")
   public EntityDescriptorType load(String id) throws IOException
   {
      File persistedFile = validateIdAndReturnMDFile(id);
      
      Unmarshaller un;
      try
      {
         un = JAXBUtil.getUnmarshaller(pkgName);
         JAXBElement<EntityDescriptorType> je = 
            (JAXBElement<EntityDescriptorType>) un.unmarshal(persistedFile);
        return je.getValue();
      }
      catch (JAXBException e)
      {
         IOException ioe =new IOException(e.getLocalizedMessage());
         ioe.initCause(e);
         throw ioe;
      }
      
   }

   /**  
    * @see IMetadataConfigurationStore#persist(EntityDescriptorType, String)
    */
   public void persist(EntityDescriptorType entity, String id) throws IOException
   {
      File persistedFile = validateIdAndReturnMDFile(id);
      
      ObjectFactory of = new ObjectFactory();
      
      JAXBElement<?> jentity = of.createEntityDescriptor(entity);
      
      Marshaller m;
      try
      {
         m = JAXBUtil.getMarshaller(pkgName);
         m.marshal(jentity, persistedFile);
      }
      catch (JAXBException e)
      {
         IOException ioe =new IOException(e.getLocalizedMessage());
         ioe.initCause(e);
         throw ioe;
      } 
      if(trace) log.trace("Persisted into " + persistedFile.getPath());
   }

   /**
    * @see IMetadataConfigurationStore#delete(String)
    */
   public void delete(String id) 
   {
      File persistedFile = validateIdAndReturnMDFile(id);
      
      if(persistedFile.exists())
         persistedFile.delete(); 
   }

   /**
    * @throws IOException  
    * @throws ClassNotFoundException 
    * @see IMetadataConfigurationStore#loadTrustedProviders(String)
    */
   @SuppressWarnings("unchecked")
   public Map<String, String> loadTrustedProviders(String id) throws IOException, ClassNotFoundException 
   {
      File trustedFile = validateIdAndReturnTrustedProvidersFile(id);
      ObjectInputStream ois = new ObjectInputStream(new FileInputStream(trustedFile));
      Map<String, String> trustedMap = (Map<String, String>) ois.readObject();
      return trustedMap;
   }

   /**
    * @throws IOException   
    * @see IMetadataConfigurationStore#persistTrustedProviders(Map)
    */
   public void persistTrustedProviders(String id, Map<String, String> trusted) 
   throws IOException 
   {  
      File trustedFile = validateIdAndReturnTrustedProvidersFile(id);
      ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(trustedFile));
      oos.writeObject(trusted);
      oos.close(); 
      if(trace) log.trace("Persisted trusted map into "+ trustedFile.getPath());
   }
   
   /**
    * @see IMetadataConfigurationStore#deleteTrustedProviders(String)
    */
   public void deleteTrustedProviders(String id) 
   {
      File persistedFile = validateIdAndReturnTrustedProvidersFile(id);
      
      if(persistedFile.exists())
         persistedFile.delete();  
   }
   
   private File validateIdAndReturnMDFile(String id)
   {
      if(id == null)
         throw new IllegalArgumentException("id is null");
      if(!id.endsWith(EXTENSION))
         id += EXTENSION;
      return new File(userHome + "/jbid-store/" + id); 
   }
   
   private File validateIdAndReturnTrustedProvidersFile(String id)
   {
      if(id == null)
         throw new IllegalArgumentException("id is null");
      
      id += "-trusted" + EXTENSION; 
      
      return new File(userHome + "/jbid-store/" + id); 
   }
}