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
package org.picketlink.identity.federation.web.constants;

/**
 * Constants
 * @author Anil.Saldhana@redhat.com
 * @since Oct 8, 2009
 */
public interface GeneralConstants
{
   String ASSERTIONS_VALIDITY = "ASSERTIONS_VALIDITY";
   
   String ATTRIBUTES = "ATTRIBUTES";
   String ATTRIBUTE_KEYS = "ATTRIBUTE_KEYS";
   String ATTIBUTE_MANAGER = "ATTRIBUTE_MANAGER"; 
   
   String CANONICALIZATION_METHOD = "CANONICALIZATION_METHOD";
   String CONFIGURATION = "CONFIGURATION";
   String CONFIG_FILE_LOCATION = "/WEB-INF/picketlink-idfed.xml";
   
   String GLOBAL_LOGOUT = "GLO";
   

   String HANDLER_CONFIG_FILE_LOCATION = "/WEB-INF/picketlink-handlers.xml";
   
   String IDENTITY_SERVER = "IDENTITY_SERVER";
   String IGNORE_SIGNATURES = "IGNORE_SIGNATURES";
   
   String KEYPAIR = "KEYPAIR";
   
   String LOGOUT_PAGE = "LOGOUT_PAGE";
   String LOGOUT_PAGE_NAME = "/logout.jsp";
   
   String PRINCIPAL_ID = "jboss_identity.principal";
   String RELAY_STATE = "RelayState";
   String ROLES = "ROLES";
   String ROLES_ID = "jboss_identity.roles";
   
   String ROLE_GENERATOR = "ROLE_GENERATOR";
   String ROLE_VALIDATOR = "ROLE_VALIDATOR";
   String ROLE_VALIDATOR_IGNORE = "ROLE_VALIDATOR_IGNORE";
   
   String SAML_REQUEST_KEY = "SAMLRequest";
   String SAML_RESPONSE_KEY = "SAMLResponse";
   
   String SENDER_PUBLIC_KEY = "SENDER_PUBLIC_KEY";
   String SIGN_OUTGOING_MESSAGES = "SIGN_OUTGOING_MESSAGES";
  
   String USERNAME_FIELD = "JBID_USERNAME";
   String PASS_FIELD = "JBID_PASSWORD";
}