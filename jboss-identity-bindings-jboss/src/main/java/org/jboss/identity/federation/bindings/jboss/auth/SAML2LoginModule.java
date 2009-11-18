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
package org.jboss.identity.federation.bindings.jboss.auth;

import java.security.Principal;
import java.security.acl.Group;
import java.util.List;

import javax.security.auth.login.LoginException;

import org.jboss.identity.federation.bindings.tomcat.sp.holder.ServiceProviderSAMLContext;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;

/**
 * Login Module that is capable of dealing with SAML2 cases
 * <p>
 * The password sent to this module should be 
 * {@link ServiceProviderSAMLContext#EMPTY_PASSWORD}
 * </p>
 * <p>
 * The username is available from {@link ServiceProviderSAMLContext#getUserName()}
 * and roles is available from {@link ServiceProviderSAMLContext#getRoles()}.
 * If the roles is null, then plugged in login modules in the stack have to provide
 * the roles.
 * </p>
 * @author Anil.Saldhana@redhat.com
 * @since Feb 13, 2009
 */
public class SAML2LoginModule extends UsernamePasswordLoginModule
{   
   @Override
   protected Principal getIdentity()
   { 
      return new SimplePrincipal(ServiceProviderSAMLContext.getUserName());
   }

   @Override
   protected Group[] getRoleSets() throws LoginException
   {
      Group group = new SimpleGroup("Roles");
      
      List<String> roles = ServiceProviderSAMLContext.getRoles();
      if(roles != null)
      {
         for(String role: roles)
         {
            group.addMember(new SimplePrincipal(role));
         }
      }
      return new Group[] {group};
   }

   @Override
   protected String getUsersPassword() throws LoginException
   {
      return ServiceProviderSAMLContext.EMPTY_PASSWORD;
   }
}