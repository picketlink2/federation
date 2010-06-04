/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2010, Red Hat Middleware LLC, and individual contributors
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
package org.picketlink.identity.federation.core.wstrust.plugins;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;

/**
 * <p>
 * {@code FileBasedRevocationRegistry} is a revocation registry implementation that uses a file to store the ids of the
 * revoked (canceled) security tokens. By default all ids are stored in $HOME/picketlink-store/sts/revoked.ids but a
 * different location can be specified through the constructor that takes the file name as a parameter.
 * </p>
 * <p>
 * NOTE: this implementation use a local cache to avoid reading the file system every time a revocation check is made,
 * making this registry a bad choice for distributed scenarios. Even though the registry file is updated whenever a 
 * new id is revoked, each node in the cluster will have its own cached view and thus a token that has been canceled by
 * one node may be accepted by another live node as the caches are not refreshed or synchronized.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class FileBasedRevocationRegistry implements RevocationRegistry
{
   private static Logger logger = Logger.getLogger(FileBasedRevocationRegistry.class);

   // this set contains the ids of the revoked security tokens.
   private static Set<String> revokedIds = new HashSet<String>();

   // the file that stores the revoked ids.
   private File registryFile;

   /**
    * <p>
    * Creates an instance of {@code RevocationRegistryFile} that stores the canceled ids in the default
    * {@code $HOME/picketlink-store/sts/revoked.ids} file.
    * </p>
    */
   public FileBasedRevocationRegistry()
   {
      // use the default location registry file location.
      StringBuilder builder = new StringBuilder();
      builder.append(System.getProperty("user.home"));
      builder.append(System.getProperty("file.separator") + "picketlink-store");
      builder.append(System.getProperty("file.separator") + "sts");

      // check if the $HOME/picketlink-store/sts directory exists.
      File directory = new File(builder.toString());
      if (!directory.exists())
         directory.mkdirs();

      // check if the default registry file exists.
      this.registryFile = new File(directory, "revoked.ids");
      if (!this.registryFile.exists())
      {
         try
         {
            this.registryFile.createNewFile();
         }
         catch (IOException ioe)
         {
            if (logger.isDebugEnabled())
               logger.debug("Error creating default registry file: " + ioe.getMessage());
            ioe.printStackTrace();
         }
      }

      // load the revoked ids cache.
      this.loadRevokedIds();
   }

   /**
    * <p>
    * Creates an instance of {@code RevocationRegistryFile} that stores the canceled ids in specified file.
    * </p>
    * 
    * @param registryFile a {@code String} that indicates the file that must be used to store revoked ids.
    */
   public FileBasedRevocationRegistry(String registryFile)
   {
      if (registryFile == null)
         throw new IllegalArgumentException("The revoked ids file cannot be null");

      // check if the specified file exists. If not, create it.
      this.registryFile = new File(registryFile);
      if (!this.registryFile.exists())
      {
         try
         {
            this.registryFile.createNewFile();
         }
         catch (IOException ioe)
         {
            if (logger.isDebugEnabled())
               logger.debug("Error creating registry file: " + ioe.getMessage());
            ioe.printStackTrace();
         }
      }

      // load the revoked ids cache.
      this.loadRevokedIds();
   }

   /*
    * (non-Javadoc)
    * @see org.picketlink.identity.federation.core.wstrust.plugins.RevocationRegistry#isRevoked(java.lang.String, java.lang.String)
    */
   public boolean isRevoked(String tokenType, String id)
   {
      return revokedIds.contains(id);
   }

   /*
    * (non-Javadoc)
    * @see org.picketlink.identity.federation.core.wstrust.plugins.RevocationRegistry#revokeToken(java.lang.String, java.lang.String)
    */
   public synchronized void revokeToken(String tokenType, String id)
   {
      try
      {
         // write a new line with the revoked id at the end of the file. 
         BufferedWriter writer = new BufferedWriter(new FileWriter(this.registryFile, true));
         writer.write(id + "\n");
         writer.close();
      }
      catch (IOException ioe)
      {
         if (logger.isDebugEnabled())
            logger.debug("Error appending content to registry file: " + ioe.getMessage());
         ioe.printStackTrace();
      }
      // add the revoked id to the local cache.
      revokedIds.add(id);

   }

   /**
    * <p>
    * This method loads the ids of the revoked assertions from the registry file. All retrieved ids are set in the
    * local cache of revoked ids.
    * </p>
    */
   private void loadRevokedIds()
   {
      try
      {
         // read the file contents and populate the local cache.
         BufferedReader reader = new BufferedReader(new FileReader(this.registryFile));
         String id = reader.readLine();
         while (id != null)
         {
            revokedIds.add(id);
            id = reader.readLine();
         }
         reader.close();
      }
      catch (IOException ioe)
      {
         if (logger.isDebugEnabled())
            logger.debug("Error opening registry file: " + ioe.getMessage());
         ioe.printStackTrace();
      }
   }
}
