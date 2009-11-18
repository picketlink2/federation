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
package org.jboss.identity.federation.web.roles;

import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;
 
import org.jboss.identity.federation.core.interfaces.RoleGenerator;

/**
 * Simple Role Generator that looks
 * inside a roles.properties on the classpath
 * with format:  principalName=role1,role2
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Aug 21, 2009
 */
public class DefaultRoleGenerator implements RoleGenerator
{
   private static Properties props = new Properties();
   
   static
   {
      try
      {
         ClassLoader tcl = SecurityActions.getContextClassLoader();
         InputStream is = tcl.getResourceAsStream("roles.properties");
         if(is == null)
            throw new RuntimeException("roles.properties not found");
         props.load(is);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   public List<String> generateRoles(Principal principal)
   {
      List<String> roles = new ArrayList<String>();
      
      String csv = (String) props.get(principal.getName()); 
      //lets break the roles string
      StringTokenizer st = new StringTokenizer(csv,",");
      while(st != null && st.hasMoreTokens())
      {
         roles.add(st.nextToken());
      }
      return roles;
   }

}