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
import java.util.List;

import org.jboss.seam.annotations.Name;
import org.jboss.seam.security.Identity;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;

/**
* @author Marcel Kolsteren
*/
@Name("authenticator")
public class Authenticator
{
   public Boolean internalAuthenticate(Principal principal, List<String> roles)
   {
      if (principal instanceof SamlPrincipal)
      {
         SamlPrincipal samlPrincipal = (SamlPrincipal) principal;

         if (samlPrincipal.getName().equals("employee"))
         {
            return false;
         }
         else
         {
            for (AttributeType attribute : samlPrincipal.getAttributes())
            {
               if (attribute.getName().equals("role"))
               {
                  List<Object> value = attribute.getAttributeValue();
                  if (value != null && value.size() > 0)
                  {
                     roles.add((String) value.get(0));
                  }
               }
            }

            return true;
         }
      }
      else
      {
         return true;
      }
   }

   public String localLogout()
   {
      Identity.instance().logout();
      return "loggedOut";
   }
}
