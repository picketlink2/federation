/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2009, Red Hat Middleware LLC, and individual contributors
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
package org.picketlink.identity.federation.core.wstrust;

import javax.xml.namespace.QName;

/**
 * <p>
 * This class defines the constants used throughout the WS-Trust implementation code.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @author <a href="mailto:asaldhan@redhat.com">Anil Saldhana</a>
 */
public class WSTrustConstants
{
   public static final String BASE_NAMESPACE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";

   // WS-Trust request types
   public static final String BATCH_ISSUE_REQUEST = BASE_NAMESPACE + "/BatchIssue";
   public static final String ISSUE_REQUEST = BASE_NAMESPACE + "/Issue";
   public static final String RENEW_REQUEST = BASE_NAMESPACE + "/Renew";
   public static final String CANCEL_REQUEST = BASE_NAMESPACE + "/Cancel";
   public static final String VALIDATE_REQUEST = BASE_NAMESPACE + "/Validate";
   public static final String BATCH_VALIDATE_REQUEST = BASE_NAMESPACE + "/BatchValidate";
   
   // WS-Trust validation constants.
   public static final String STATUS_TYPE = BASE_NAMESPACE + "/RSTR/Status";
   public static final String STATUS_CODE_VALID = BASE_NAMESPACE + "/status/valid";
   public static final String STATUS_CODE_INVALID = BASE_NAMESPACE + "/status/invalid";
   
   // WS-Trust key types.
   public static final String KEY_TYPE_BEARER = BASE_NAMESPACE + "/Bearer";
   public static final String KEY_TYPE_SYMMETRIC = BASE_NAMESPACE + "/SymmetricKey";
   public static final String KEY_TYPE_PUBLIC = BASE_NAMESPACE + "/PublicKey"; 
   
   // WS-Trust binary secret types.
   public static final String BS_TYPE_ASYMMETRIC = BASE_NAMESPACE + "/AsymmetricKey";
   public static final String BS_TYPE_SYMMETRIC = BASE_NAMESPACE + "/SymmetricKey";
   public static final String BS_TYPE_NONCE = BASE_NAMESPACE + "/Nonce";
   
   // WS-Trust computed key types.
   public static final String CK_PSHA1 = BASE_NAMESPACE + "/CK/PSHA1";
   
   // WSS namespaces values.
   public static final String WSA_NS = "http://www.w3.org/2005/08/addressing";
   public static final String WSP_NS = "http://schemas.xmlsoap.org/ws/2004/09/policy";
   public static final String WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
   public static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
   public static final String WSSE11_NS = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";
   public static final String XENC_NS = "http://www.w3.org/2001/04/xmlenc#";
   public static final String DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
   public static final String SAML2_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
   
   // WSS Fault codes
   public static final QName SECURITY_TOKEN_UNAVAILABLE = new QName(WSSE_NS, "SecurityTokenUnavailable");
   public static final QName INVALID_SECURITY_TOKEN = new QName(WSSE_NS, "InvalidSecurityToken");
   public static final QName INVALID_SECURITY = new QName(WSSE_NS, "InvalidSecurity");
   public static final QName FAILED_AUTHENTICATION = new QName(WSSE_NS, "FailedAuthentication");
   
   //Token Types
   public static final String SAML2_TOKEN_TYPE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
   public static final String RSTR_STATUS_TOKEN_TYPE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status";
   
   //Element Names
   public static final String RST = "RequestSecurityToken";
   public static final String RST_COLLECTION = "RequestSecurityTokenCollection";
   public static final String REQUEST_TYPE = "RequestType";
   public static final String TOKEN_TYPE = "TokenType";
   public static final String CANCEL_TARGET = "CancelTarget";
   public static final String VALIDATE_TARGET = "ValidateTarget";
   
   //Attribute Names
   public static final String RST_CONTEXT = "Context";
}