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
package org.jboss.identity.federation.bindings.jboss.subject;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * A Principal Group used to register roles in JBoss
 * @author Anil.Saldhana@redhat.com
 * @since Jan 16, 2009
 */
public class JBossIdentityGroup extends JBossIdentityPrincipal implements Group
{ 
   private static final long serialVersionUID = 1L;

   private Set<Principal> roles = new HashSet<Principal>();
   
   public JBossIdentityGroup(String name)
   {
     super(name);   
   }
   
   public boolean addMember(Principal user)
   { 
      return roles.add(user);
   }

   public boolean isMember(Principal member)
   { 
      return roles.contains(member);
   }

   public Enumeration<? extends Principal> members()
   {
      Set<Principal> readOnly = Collections.unmodifiableSet(roles);
      return Collections.enumeration(readOnly);
   }

   public boolean removeMember(Principal user)
   {
      return roles.remove(user);
   }
}