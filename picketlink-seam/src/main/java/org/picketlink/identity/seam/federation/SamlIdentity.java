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

import static org.jboss.seam.ScopeType.SESSION;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Startup;
import org.jboss.seam.annotations.intercept.BypassInterceptors;
import org.jboss.seam.security.Identity;

/**
 * Identity that has been establised using SAMLv2 authentication.
 * 
 * @author Marcel Kolsteren
 */
@Name("org.jboss.seam.security.identity")
@Scope(SESSION)
@Install(precedence = Install.FRAMEWORK)
@BypassInterceptors
@Startup
public class SamlIdentity extends Identity
{
   private static final long serialVersionUID = 7042249176714812268L;

   private Map<String, List<String>> attributes = new HashMap<String, List<String>>();

   public Map<String, List<String>> getAttributes()
   {
      return attributes;
   }

   public void setAttributes(Map<String, List<String>> attributes)
   {
      this.attributes = attributes;
   }

   public String getAttributeValue(String attributeName)
   {
      return attributes.get(attributeName).get(0);
   }

   public List<String> getAttributeValues(String attributeName)
   {
      return attributes.get(attributeName);
   }
}
