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
package org.picketlink.identity.federation.api.openid.provider;

import org.openid4java.message.AuthSuccess;
import org.openid4java.message.DirectError;
import org.openid4java.message.Message;
import org.openid4java.message.ParameterList;
import org.openid4java.server.InMemoryServerAssociationStore;
import org.openid4java.server.ServerManager;

/**
 * Manages a OpenID Provider
 * @author Anil.Saldhana@redhat.com
 * @since Jul 15, 2009
 */
public class OpenIDProviderManager
{
   private ServerManager serverManager = new ServerManager();
   
   /**
    * Initialize internal data structures
    */
   public void initialize()
   {
      serverManager.setSharedAssociations(new InMemoryServerAssociationStore());
      serverManager.setPrivateAssociations(new InMemoryServerAssociationStore());
   }
   
   /**
    * Get the end point where the provider is active
    * @return string an url
    */
   public String getEndPoint()
   {
      return serverManager.getOPEndpointUrl();
   }
   
   /**
    * Set the end point where the provider is active
    * @param url
    */
   public void setEndPoint(String url)
   {
      serverManager.setOPEndpointUrl(url);
   }
   
   /**
    * Process a request from the RP/Relying Party (or OpenID Consumer)
    * for authenticating an user
    * @param requestParams
    * @param userSelId
    * @param userSelClaimed
    * @param authenticatedAndApproved
    * @return
    */
   public OpenIDMessage processAuthenticationRequest(ParameterList requestParams,
         String userSelId,
         String userSelClaimed,
         boolean authenticatedAndApproved)
   {
      Message authMessage = serverManager.authResponse(requestParams, 
            userSelId, userSelClaimed, authenticatedAndApproved);
      
      return new OpenIDMessage(authMessage); 
   }
   
   /**
    * Process a request for association from the RP
    * @param requestParams
    * @return
    */
   public OpenIDMessage processAssociationRequest(ParameterList requestParams)
   {
      return new OpenIDMessage(serverManager.associationResponse(requestParams));
   }
   
   /**
    * Process a verification request from RP for an already
    * authenticated user
    * @param requestParams
    * @return
    */
   public OpenIDMessage verify(ParameterList requestParams)
   {
      return new OpenIDMessage(serverManager.verify(requestParams));
   }
   
   /**
    * Create an error message that needs to be passed to the RP
    * @param msg
    * @return
    */
   public OpenIDMessage getDirectError(String msg)
   {
     return new OpenIDMessage(DirectError.createDirectError(msg));  
   }
   
   public static class OpenIDMessage
   {
      private Message message;
      
      OpenIDMessage(Message message)
      {
         this.message = message;
      }
      
      public boolean isSuccessful()
      {
         return message instanceof AuthSuccess;
      }
      
      public String getDestinationURL(boolean httpget)
      {
         return ((AuthSuccess) message).getDestinationUrl(httpget);
      }
      
      public String getResponseText()
      {
         return message.keyValueFormEncoding();
      }
   }
}