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
package org.jboss.identity.seam.federation;

import java.util.List;

import org.jboss.identity.seam.federation.SamlIdentity;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;

/**
* @author Marcel Kolsteren
*/
@Name("authenticator")
public class Authenticator
{

   @In
   SamlIdentity identity;

   public boolean authenticate()
   {
      /* User has already been authenticated. Only thing we need to do here is the translation of attribute values to roles. */

      List<String> roles = identity.getAttributeValues("role");
      if (roles != null)
      {
         for (String role : roles)
         {
            identity.addRole(role);
         }
      }

      return true;
   }
}
