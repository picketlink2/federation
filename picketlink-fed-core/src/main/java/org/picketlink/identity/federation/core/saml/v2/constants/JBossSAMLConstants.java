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
   ADDRESS( "Address" ),
   ALLOW_CREATE( "AllowCreate" ),
   ASSERTION( "Assertion" ),
   ASSERTION_CONSUMER_SERVICE_URL( "AssertionConsumerServiceURL" ),
   ATTRIBUTE( "Attribute" ),
   ATTRIBUTE_STATEMENT( "AttributeStatement" ),
   ATTRIBUTE_VALUE( "AttributeValue" ),
   AUDIENCE( "Audience" ),
   AUDIENCE_RESTRICTION( "AudienceRestriction" ),
   AUTHN_CONTEXT( "AuthnContext" ),
   AUTHENTICATING_AUTHORITY( "AuthenticatingAuthority" ),
   AUTHN_CONTEXT_CLASS_REF( "AuthnContextClassRef" ),
   AUTHN_CONTEXT_DECLARATION( "AuthnContextDecl" ),
   AUTHN_CONTEXT_DECLARATION_REF( "AuthnContextDeclRef" ),
   AUTHN_INSTANT( "AuthnInstant" ),
   AUTHN_REQUEST( "AuthnRequest" ),
   AUTHN_STATEMENT( "AuthnStatement" ),
   CONDITIONS( "Conditions" ),
   CONSENT( "Consent" ),
   DESTINATION( "Destination" ),
   ENCODING( "Encoding" ),
   FORMAT( "Format" ),
   FRIENDLY_NAME( "FriendlyName" ),
   ID( "ID" ),
   IN_RESPONSE_TO( "InResponseTo" ),
   ISSUE_INSTANT( "IssueInstant" ),
   ISSUER( "Issuer" ),
   LANG_EN("en"),
   LOGOUT_REQUEST( "LogoutRequest" ),
   LOGOUT_RESPONSE( "LogoutResponse" ),
   METADATA_MIME("application/samlmetadata+xml"),
   METHOD( "Method" ),
   NAME( "Name" ),
   NAME_FORMAT( "NameFormat" ),
   NAMEID( "NameID" ),
   NAMEID_POLICY( "NameIDPolicy" ),
   NAME_QUALIFIER( "NameQualifier" ),
   NOT_BEFORE( "NotBefore" ),
   NOT_ON_OR_AFTER( "NotOnOrAfter" ),
   RECIPIENT( "Recipient" ),
   RESPONSE( "Response" ),
   SESSION_INDEX( "SessionIndex" ),
   SP_PROVIDED_ID( "SPProvidedID" ),
   SP_NAME_QUALIFIER( "SPNameQualifier" ),
   SIGNATURE( "Signature" ),
   SIGNATURE_SHA1_WITH_DSA("http://www.w3.org/2000/09/xmldsig#dsa-sha1"),
   SIGNATURE_SHA1_WITH_RSA("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
   STATUS( "Status" ),
   STATUS_CODE( "StatusCode" ),
   STATUS_DETAIL( "StatusDetail" ),
   STATUS_MESSAGE( "StatusMessage" ),
   STATUS_RESPONSE_TYPE( "StatusResponseType" ),
   SUBJECT( "Subject" ),
   SUBJECT_CONFIRMATION( "SubjectConfirmation" ),
   SUBJECT_CONFIRMATION_DATA( "SubjectConfirmationData" ),
   VALUE( "Value" ),
   VERSION( "Version" ),
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
