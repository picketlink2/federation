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
package org.picketlink.identity.seam.federation;

import java.security.Principal;
import java.util.LinkedList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.Import;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.security.Identity;
import org.picketlink.identity.seam.federation.configuration.ServiceProvider;

/**
* @author Marcel Kolsteren
* @since Jan 30, 2010
*/
@Name("org.picketlink.identity.seam.federation.internalAuthenticator")
@AutoCreate
@Import("org.picketlink.identity.seam.federation")
public class InternalAuthenticator
{
   @In
   private Identity identity;

   @In
   private ServiceProvider serviceProvider;

   public boolean authenticate(Principal principal, HttpServletRequest httpRequest)
   {
      List<String> roles = new LinkedList<String>();
      Boolean internallyAuthenticated = serviceProvider.getInternalAuthenticationMethod().invoke(principal, roles);

      if (internallyAuthenticated)
      {
         identity.acceptExternallyAuthenticatedPrincipal(principal);
         for (String role : roles)
         {
            identity.addRole(role);
         }
      }

      return internallyAuthenticated;
   }
}
