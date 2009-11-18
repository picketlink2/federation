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
package org.picketlink.identity.federation.core.saml.v2.constants;

/**
 * @author Anil.Saldhana@redhat.com
 * @since Sep 11, 2009
 */
public enum X500SAMLProfileConstants 
{

   CN("commonName", "urn:oid:2.5.4.3"),
   GIVENNAME("givenName","urn:oid:2.5.4.42"),
   EMAIL_ADDRESS("mail", "urn:oid:0.9.2342.19200300.100.1.3"),
   EMPLOYEE_NUMBER("mail", "urn:oid:2.16.840.1.113730.3.1.3"),
   SN("surname", "urn:oid:2.5.4.4"),
   TELEPHONE("telephoneNumber", "urn:oid:2.5.4.20"); 
   
   private String friendlyName = null;
   private String uri = null;
   
   private X500SAMLProfileConstants(String friendlyName,
         String uristr)
   {
      this.uri = uristr;  
   }
   
   public String get()
   {
      return this.uri;
   }

   public String getFriendlyName()
   {
      return friendlyName;
   }  
}