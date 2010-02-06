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

import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.seam.federation.configuration.SamlIdentityProvider;

/**
* @author Marcel Kolsteren
* @since Jan 28, 2010
*/
public class SamlPrincipal implements Principal
{
   private NameIDType nameId;

   private SamlIdentityProvider identityProvider;

   private List<AttributeType> attributes = new LinkedList<AttributeType>();

   private String sessionIndex;

   private AssertionType assertion;

   public NameIDType getNameId()
   {
      return nameId;
   }

   public void setNameId(NameIDType nameId)
   {
      this.nameId = nameId;
   }

   public SamlIdentityProvider getIdentityProvider()
   {
      return identityProvider;
   }

   public void setIdentityProvider(SamlIdentityProvider identityProvider)
   {
      this.identityProvider = identityProvider;
   }

   public List<AttributeType> getAttributes()
   {
      return attributes;
   }

   public void setAttributes(List<AttributeType> attributes)
   {
      this.attributes = attributes;
   }

   public String getSessionIndex()
   {
      return sessionIndex;
   }

   public void setSessionIndex(String sessionIndex)
   {
      this.sessionIndex = sessionIndex;
   }

   public AssertionType getAssertion()
   {
      return assertion;
   }

   public void setAssertion(AssertionType assertion)
   {
      this.assertion = assertion;
   }

   public String getName()
   {
      return nameId.getValue();
   }
}
