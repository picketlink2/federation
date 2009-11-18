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

import java.io.IOException;
import java.util.Map;

import org.jboss.identity.federation.saml.v2.metadata.EntityDescriptorType;

/**
 * Configuration Store for the metadata
 * @author Anil.Saldhana@redhat.com
 * @since Apr 27, 2009
 */
public interface IMetadataConfigurationStore
{
   /**
    * Get the Trusted Providers
    * @param id
    * @return a map of name of provider, metadata urls 
    * @throws {@link IOException}
    * @throws {@link ClassNotFoundException}
    */
   Map<String, String> loadTrustedProviders(String id) throws IOException, ClassNotFoundException ;
   
   /**
    * Persist the map of trusted providers
    * @param id
    * @param trusted
    * @throws {@link IOException}
    */
   void persistTrustedProviders(String id, Map<String,String> trusted) throws IOException;
   
   /**
    * Persist into an external sink (file system, ldap, db etc)
    * @param entity
    * @param id An unique identifier useful for retrieval
    * @throws {@link IOException}
    */
   void persist(EntityDescriptorType entity, String id) throws IOException;
   
   /**
    * Load the descriptor from the external data sink
    * @param id unique identifier used during persistence
    * @return
    * @throws {@link IOException}
    */
   EntityDescriptorType load(String id) throws IOException;
   
   /**
    * Delete the descriptor from the external data sink
    * @param id 
    */
   void delete(String id);
   
   /**
    * Delete the trusted providers from the external data sink
    * @param id 
    */
   void deleteTrustedProviders(String id);
}