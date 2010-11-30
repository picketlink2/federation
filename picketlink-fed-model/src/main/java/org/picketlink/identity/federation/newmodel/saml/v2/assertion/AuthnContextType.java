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
package org.picketlink.identity.federation.newmodel.saml.v2.assertion;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;



/**
 * <p>Java class for AuthnContextType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AuthnContextType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;choice>
 *           &lt;sequence>
 *             &lt;element ref="{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef"/>
 *             &lt;choice minOccurs="0">
 *               &lt;element ref="{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextDecl"/>
 *               &lt;element ref="{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextDeclRef"/>
 *             &lt;/choice>
 *           &lt;/sequence>
 *           &lt;choice>
 *             &lt;element ref="{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextDecl"/>
 *             &lt;element ref="{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextDeclRef"/>
 *           &lt;/choice>
 *         &lt;/choice>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:assertion}AuthenticatingAuthority" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */ 
public class AuthnContextType 
{  
   private Set<URI> authenticatingAuthority = new LinkedHashSet<URI>();

   private AuthnContextTypeSequence sequence;

   private Set<URIType> URITypes = new HashSet<URIType>();


   public void addAuthenticatingAuthority( URI aa )
   {
      authenticatingAuthority.add( aa );
   }

   public void addAuthenticatingAuthority( URI[] aas )
   {
      authenticatingAuthority.addAll( Arrays.asList( aas ) );
   }

   public Set<URI> getAuthenticatingAuthority()
   {
      return Collections.unmodifiableSet( authenticatingAuthority );
   }   

   public AuthnContextTypeSequence getSequence()
   {
      return sequence;
   }

   public void setSequence(AuthnContextTypeSequence sequence)
   {
      this.sequence = sequence;
   } 

   public void addURIType( URIType aa )
   {
      URITypes.add( aa );
   }

   public void addURIType( URIType[] aas )
   {
      URITypes.addAll( Arrays.asList( aas ) );
   }

   public Set<URIType> getURIType()
   {
      return Collections.unmodifiableSet( URITypes );
   } 

   /**
    <sequence>
       <element ref="saml:AuthnContextClassRef"/>
       <choice minOccurs="0">
          <element ref="saml:AuthnContextDecl"/>
          <element ref="saml:AuthnContextDeclRef"/>
       </choice>
    </sequence>
    */ 
   public class AuthnContextTypeSequence
   {
      private AuthnContextClassRefType classRef;
      private Set<URIType> URITypes;
      public AuthnContextClassRefType getClassRef()
      {
         return classRef;
      }
      public void setClassRef(AuthnContextClassRefType classRef)
      {
         this.classRef = classRef;
      }
      public void addURIType( URIType aa )
      {
         URITypes.add( aa );
      }

      public void addURIType( URIType[] aas )
      {
         URITypes.addAll( Arrays.asList( aas ) );
      }

      public Set<URIType> getURIType()
      {
         return Collections.unmodifiableSet( URITypes );
      } 
   }
}