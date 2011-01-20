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
package org.picketlink.identity.federation.core.openid.providers.helpers;

import java.io.IOException;

import org.openid4java.association.Association;
import org.openid4java.association.AssociationException;
import org.openid4java.server.InMemoryServerAssociationStore;
import org.openid4java.server.ServerAssociationStore;
import org.picketlink.identity.federation.core.sts.registry.DefaultTokenRegistry;
import org.picketlink.identity.federation.core.sts.registry.SecurityTokenRegistry;

/**
 * A {@code SecurityTokenRegistry} for OpenID that uses in memory registry
 * @author Anil.Saldhana@redhat.com
 * @since Jan 20, 2011
 */
public class OpenIDTokenRegistryStore extends DefaultTokenRegistry implements ServerAssociationStore, SecurityTokenRegistry
{
   protected InMemoryServerAssociationStore store = new InMemoryServerAssociationStore();
   
   /**
    * @see org.openid4java.server.ServerAssociationStore#generate(java.lang.String, int)
    */
   public Association generate(String type, int expiryIn) throws AssociationException
   { 
      Association association = store.generate(type, expiryIn);
      try
      {
         addToken( association.getHandle(), association );
      }
      catch (IOException e)
      {
         throw new AssociationException( e );
      }
      return association;
   }

   /**
    * @see org.openid4java.server.ServerAssociationStore#load(java.lang.String)
    */
   public Association load(String handle)
   { 
      return (Association) getToken( handle );
   }

   /**
    * @see org.openid4java.server.ServerAssociationStore#remove(java.lang.String)
    */
   public void remove(String handle)
   {  
      try
      {
         removeToken( handle );
      }
      catch (IOException e)
      { 
         throw new RuntimeException( e );
      }
   }
}