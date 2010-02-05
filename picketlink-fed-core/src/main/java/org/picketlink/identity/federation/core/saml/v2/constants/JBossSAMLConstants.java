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
 * SAML Constants
 * @author Anil.Saldhana@redhat.com
 * @since Dec 10, 2008
 */
public enum JBossSAMLConstants 
{
   LANG_EN("en"),
   METADATA_MIME("application/samlmetadata+xml"),
   SIGNATURE_SHA1_WITH_DSA("http://www.w3.org/2000/09/xmldsig#dsa-sha1"),
   SIGNATURE_SHA1_WITH_RSA("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
   VERSION_2_0("2.0"),
   HTTP_POST_BINDING("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
   
   private String val;
   
   private JBossSAMLConstants(String val)
   {
      this.val = val;
   }
   
   public String get()
   {
      return this.val;
   }
}
