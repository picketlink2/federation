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
package org.picketlink.identity.federation.core.saml.v1;

/**
 * Constants for the SAML v1.1 Specifications
 * @author Anil.Saldhana@redhat.com
 * @since Jun 22, 2011
 */
public interface SAML11Constants
{
   String ACTION = "Action";

   String ASSERTIONID = "AssertionID";

   String ASSERTION_11_NSURI = "urn:oasis:names:tc:SAML:1.0:assertion";

   String ATTRIBUTE_NAME = "AttributeName";

   String ATTRIBUTE_NAMESPACE = "AttributeNamespace";

   String ATTRIBUTE_STATEMENT = "AttributeStatement";

   String AUDIENCE_RESTRICTION_CONDITION = "AudienceRestrictionCondition";

   String AUTHENTICATION_INSTANT = "AuthenticationInstant";

   String AUTHENTICATION_METHOD = "AuthenticationMethod";

   String AUTHENTICATION_STATEMENT = "AuthenticationStatement";

   String AUTHORIZATION_DECISION_STATEMENT = "AuthorizationDecisionStatement";

   String CONFIRMATION_METHOD = "ConfirmationMethod";

   String DECISION = "Decision";

   String FORMAT = "Format";

   String ISSUER = "Issuer";

   String MAJOR_VERSION = "MajorVersion";

   String MINOR_VERSION = "MinorVersion";

   String NAME_IDENTIFIER = "NameIdentifier";

   String NAME_QUALIFIER = "NameQualifier";

   String NAMESPACE = "Namespace";

   String PROTOCOL_11_NSURI = "urn:oasis:names:tc:SAML:1.0:protocol";

   String RESOURCE = "Resource";
}