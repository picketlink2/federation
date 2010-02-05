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
package org.picketlink.identity.seam.federation.configuration;

import java.util.LinkedList;
import java.util.List;

import org.picketlink.identity.federation.saml.v2.metadata.EndpointType;
import org.picketlink.identity.seam.federation.SamlProfile;

/**
* @author Marcel Kolsteren
* @since Jan 27, 2010
*/
public class SamlService
{
   private SamlProfile profile;

   private List<SamlEndpoint> serviceEndpoints = new LinkedList<SamlEndpoint>();

   public SamlService(SamlProfile profile, List<EndpointType> endpoints)
   {
      this.profile = profile;

      for (EndpointType endpoint : endpoints)
      {
         Binding binding = null;
         if (endpoint.getBinding().endsWith("HTTP-Redirect"))
         {
            binding = Binding.HTTP_Redirect;
         }
         else if (endpoint.getBinding().endsWith("HTTP-POST"))
         {
            binding = Binding.HTTP_Post;
         }
         else
         {
            // ignore other bindings
         }
         if (binding != null)
         {
            SamlEndpoint samlEndpoint = new SamlEndpoint(this, binding, endpoint.getLocation(), endpoint
                  .getResponseLocation());
            serviceEndpoints.add(samlEndpoint);
         }
      }
   }

   public SamlProfile getProfile()
   {
      return profile;
   }

   public List<SamlEndpoint> getServiceEndpoints()
   {
      return serviceEndpoints;
   }

   public SamlEndpoint getEndpointForBinding(Binding binding)
   {
      for (SamlEndpoint endpoint : serviceEndpoints)
      {
         if (endpoint.getBinding() == binding)
         {
            return endpoint;
         }
      }

      return null;
   }
}
