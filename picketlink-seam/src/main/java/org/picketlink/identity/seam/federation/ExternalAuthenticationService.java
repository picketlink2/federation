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

/**
* @author Marcel Kolsteren
* @since Jan 26, 2010
*/
public enum ExternalAuthenticationService {

   AUTHENTICATION_SERVICE("AuthenticationService"),

   LOGOUT_SERVICE("LogoutService"),

   SAML_ASSERTION_CONSUMER_SERVICE("AssertionConsumerService"),

   SAML_SINGLE_LOGOUT_SERVICE("SingleLogoutService"),

   SAML_META_DATA_SERVICE("MetaDataService"),

   OPEN_ID_SERVICE("OpenIdService"),

   OPEN_ID_XRDS_SERVICE("OpenIdXrdsService");

   private String name;

   private ExternalAuthenticationService(String name)
   {
      this.name = name;
   }

   public String getName()
   {
      return name;
   }
}
